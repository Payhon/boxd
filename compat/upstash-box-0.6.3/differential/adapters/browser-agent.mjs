import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { z } from "zod";
import { boxConfig, consume, managedAgent, settleCleanup } from "./common.mjs";

const LOCAL_PAGE = "data:text/html,%3C!doctype%20html%3E%3Chtml%3E%3Cbody%3E%3Ch1%3Eboxd%20fixture%3C%2Fh1%3E%3Ca%20href%3D%22%23fixture%22%3Efixture%20link%3C%2Fa%3E%3C%2Fbody%3E%3C%2Fhtml%3E";

// This local wrapper intentionally keeps state visible to cleanup. The shared
// helper predates resource-bearing browser cases and only forwards `box`.
const managedBox = (operation, options = {}) => ({
  prepare: () => ({ box: null, deleted: false, resources: {} }),
  async execute(context) {
    const { sdk, target, config, state } = context;
    state.box = await sdk.Box.create(boxConfig(target, config, {
      name: options.name,
      browser: options.browser ?? false,
      extra: options.extra?.(context),
    }));
    return operation({ ...context, box: state.box });
  },
  async cleanup({ state }) {
    await settleCleanup([
      ...(options.cleanup ? [() => options.cleanup(state)] : []),
      ...(state.box && !state.deleted ? [async () => { await state.box.delete(); state.deleted = true; }] : []),
    ]);
  },
});

const agentBox = (operation) => managedBox(operation, {
  name: "boxd-phase4-agent-differential",
  extra: ({ config }) => ({ agent: managedAgent(config) }),
});
const browserBox = (operation, ai = false, cleanup) => managedBox(operation, {
  name: "boxd-phase4-browser-differential",
  browser: true,
  cleanup,
  extra: ai ? ({ config }) => ({ agent: managedAgent(config) }) : undefined,
});
const tabOperation = (operation, ai = false) => browserBox(async ({ box }) => {
  const tab = await box.browser.tab.create(LOCAL_PAGE);
  return operation({ box, tab });
}, ai);
const recordingResource = (operation) => browserBox(async ({ box }) => {
  const handle = await box.browser.recordings.start({ maxDurationSeconds: 1 });
  const recording = await handle.stop();
  return operation({ box, recording });
});

const agentAdapters = new Map([
  ["POST /v2/box/{box_id}/run", agentBox(async ({ box }) => box.agent.run({ prompt: "return the word ok", webhook: { url: "https://example.invalid/boxd-differential" } }))],
  ["POST /v2/box/{box_id}/run/stream", agentBox(async ({ box }) => consume(await box.agent.stream({ prompt: "return the word ok" })))],
  ["POST /v2/box/{box_id}/runs/{run_id}/cancel", agentBox(async ({ box }) => {
    const run = await box.agent.run({ prompt: "wait for cancellation", webhook: { url: "https://example.invalid/boxd-differential" } });
    return run.cancel();
  })],
  ["GET /v2/box/{box_id}/runs", agentBox(async ({ box }) => box.listRuns())],
  ["GET /v2/box/{box_id}/logs", agentBox(async ({ box }) => box.logs({ limit: 2 }))],
]);

const recordingDownload = recordingResource(async ({ box, recording }) => {
  const dir = await mkdtemp(join(tmpdir(), "boxd-recording-diff-"));
  try { return await box.browser.recordings.download(recording.id, { path: join(dir, "recording.mp4") }); }
  finally { await rm(dir, { recursive: true, force: true }); }
});
recordingDownload.binaryBodyKind = "media";

const browserAdapters = new Map([
  ["POST /v2/box/{box_id}/browser/tabs", browserBox(async ({ box }) => box.browser.tab.create(LOCAL_PAGE))],
  ["GET /v2/box/{box_id}/browser/tabs", browserBox(async ({ box }) => box.browser.listTabs())],
  ["POST /v2/box/{box_id}/browser/goto", tabOperation(({ tab }) => tab.goto(LOCAL_PAGE))],
  ["POST /v2/box/{box_id}/browser/extract", tabOperation(({ tab }) => tab.extract("extract the page title", z.object({ title: z.string().optional() })), true)],
  ["POST /v2/box/{box_id}/browser/observe", tabOperation(({ tab }) => tab.observe("find the main heading"), true)],
  ["POST /v2/box/{box_id}/browser/act", tabOperation(({ tab }) => tab.act("click the first link"), true)],
  ["POST /v2/box/{box_id}/browser/run", tabOperation(({ tab }) => tab.run("summarize this page"), true)],
  ["GET /v2/box/{box_id}/browser/content", tabOperation(({ tab }) => tab.content())],
  ["GET /v2/box/{box_id}/browser/screenshot", tabOperation(({ tab }) => tab.screenshot())],
  ["POST /v2/box/{box_id}/browser/screencast", tabOperation(({ tab }) => tab.liveViewUrl())],
  ["POST /v2/box/{box_id}/browser/connect", browserBox(async ({ box }) => box.browser.cdpUrl())],
  ["POST /v2/box/{box_id}/browser/recordings", browserBox(async ({ box, state }) => {
    state.resources.recording = await box.browser.recordings.start({ maxDurationSeconds: 1 });
    return state.resources.recording;
  }, false, async (state) => {
    if (state.resources.recording) await state.resources.recording.stop();
  })],
  ["POST /v2/box/{box_id}/browser/recordings/stop", browserBox(async ({ box }) => {
    const handle = await box.browser.recordings.start({ maxDurationSeconds: 1 });
    return handle.stop();
  })],
  ["GET /v2/box/{box_id}/browser/recordings", browserBox(async ({ box }) => box.browser.recordings.list())],
  ["GET /v2/box/{box_id}/browser/recordings/{id}", recordingResource(({ box, recording }) => box.browser.recordings.get(recording.id))],
  ["GET /v2/box/{box_id}/browser/recordings/{id}/download", recordingDownload],
  ["DELETE /v2/box/{box_id}/browser/tabs/{tab_id}", tabOperation(({ tab }) => tab.close())],
]);

export const browserAgentAdapters = new Map([...agentAdapters, ...browserAdapters]);
export const browserAgentAdapterCaseIds = [...browserAgentAdapters.keys()];
