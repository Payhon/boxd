import assert from "node:assert/strict";
import test from "node:test";
import { browserAgentAdapters } from "../differential/adapters/browser-agent.mjs";

const expected = [
  "POST /v2/box/{box_id}/run", "POST /v2/box/{box_id}/run/stream", "POST /v2/box/{box_id}/runs/{run_id}/cancel",
  "GET /v2/box/{box_id}/runs", "GET /v2/box/{box_id}/logs",
  "POST /v2/box/{box_id}/browser/tabs", "GET /v2/box/{box_id}/browser/tabs",
  "POST /v2/box/{box_id}/browser/goto", "POST /v2/box/{box_id}/browser/extract",
  "POST /v2/box/{box_id}/browser/observe", "POST /v2/box/{box_id}/browser/act",
  "POST /v2/box/{box_id}/browser/run", "GET /v2/box/{box_id}/browser/content",
  "GET /v2/box/{box_id}/browser/screenshot", "POST /v2/box/{box_id}/browser/screencast",
  "POST /v2/box/{box_id}/browser/connect", "POST /v2/box/{box_id}/browser/recordings",
  "POST /v2/box/{box_id}/browser/recordings/stop", "GET /v2/box/{box_id}/browser/recordings",
  "GET /v2/box/{box_id}/browser/recordings/{id}", "GET /v2/box/{box_id}/browser/recordings/{id}/download",
  "DELETE /v2/box/{box_id}/browser/tabs/{tab_id}",
];

test("Browser/Agent adapters register every pinned public case", () => {
  assert.deepEqual([...browserAgentAdapters.keys()], expected);
});

test("Browser/Agent adapters use real resource sequencing and cleanup", async () => {
  const events = [];
  const tab = {
    id: "real-tab-id",
    goto: async (url) => { events.push(["tab.goto", url]); return { url }; },
    extract: async (instruction, schema) => { events.push(["tab.extract", instruction, Boolean(schema?.parse)]); return {}; },
    observe: async (instruction) => { events.push(["tab.observe", instruction]); return { elements: [] }; },
    act: async (instruction) => { events.push(["tab.act", instruction]); return { success: true }; },
    run: async (prompt) => { events.push(["tab.run", prompt]); return { completed: true }; },
    content: async () => { events.push(["tab.content"]); return {}; },
    screenshot: async () => { events.push(["tab.screenshot"]); return new Uint8Array(); },
    liveViewUrl: async () => { events.push(["tab.liveViewUrl"]); return "https://example.invalid/live"; },
    close: async () => { events.push(["tab.close"]); },
  };
  const recording = { id: "real-recording-id", status: "completed" };
  const box = {
    id: "real-box-id",
    agent: {
      run: async (options) => { events.push(["agent.run", options]); return { cancel: async () => events.push(["run.cancel"]) }; },
      stream: async () => { events.push(["agent.stream"]); return { async *[Symbol.asyncIterator]() { yield { type: "text-delta", text: "ok" }; } }; },
    },
    listRuns: async () => { events.push(["listRuns"]); return []; },
    logs: async (options) => { events.push(["logs", options]); return []; },
    browser: {
      tab: { create: async (url) => { events.push(["tab.create", url]); return tab; } },
      listTabs: async () => { events.push(["listTabs"]); return [tab]; },
      cdpUrl: async () => { events.push(["cdpUrl"]); return "ws://example.invalid"; },
      recordings: {
        start: async (options) => { events.push(["recordings.start", options]); return { id: recording.id, stop: async () => { events.push(["recordings.handle.stop"]); return recording; } }; },
        stop: async () => { events.push(["recordings.stop"]); return recording; },
        list: async () => { events.push(["recordings.list"]); return [recording]; },
        get: async (id) => { events.push(["recordings.get", id]); return recording; },
        download: async (id, options) => { events.push(["recordings.download", id, options]); return options.path; },
      },
    },
    delete: async () => { events.push(["box.delete"]); },
  };
  const sdk = { Box: { create: async (options) => { events.push(["box.create", options]); return box; } } };
  const context = { sdk, target: { apiKey: "key", baseUrl: "http://local", prefix: "LOCAL" }, config: { providerApiKey: "provider" } };

  for (const [caseId, adapter] of browserAgentAdapters) {
    const state = await adapter.prepare(context);
    await adapter.execute({ ...context, state });
    await adapter.cleanup({ ...context, state });
  }

  assert.equal(events.filter(([name]) => name === "box.create").length, expected.length);
  assert.equal(events.filter(([name]) => name === "box.delete").length, expected.length);
  assert.ok(events.some(([name, id]) => name === "recordings.get" && id === "real-recording-id"));
  assert.ok(events.some(([name, id]) => name === "recordings.download" && id === "real-recording-id"));
  assert.ok(events.some(([name, options]) => name === "box.create" && options.browser === true));
  assert.ok(events.some(([name, options]) => name === "box.create" && options.agent?.apiKey === "provider"));
  const browserCreates = events.filter(([name, options]) => name === "box.create" && options.browser === true).map(([, options]) => options);
  assert.ok(browserCreates.some((options) => !options.agent), "plain browser cases must not inject an agent");
  assert.ok(browserCreates.some((options) => options.agent?.apiKey === "provider"), "AI browser cases must inject the provider agent");
  assert.ok(events.filter(([name]) => name === "recordings.handle.stop").length >= 3, "recording start cleanup must stop the active handle");
});
