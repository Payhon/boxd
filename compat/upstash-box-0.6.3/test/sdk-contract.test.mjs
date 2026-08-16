import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Box, BoxError, runCustomHarness } from "@upstash/box";
import { z } from "zod";

const dto = JSON.parse(await readFile(new URL("../fixtures/dto.json", import.meta.url), "utf8"));
const errors = JSON.parse(await readFile(new URL("../fixtures/errors.json", import.meta.url), "utf8"));
const agentFixture = await readFile(new URL("../fixtures/agent.sse", import.meta.url), "utf8");

const bytes = (text) => new TextEncoder().encode(text);
function stream(text) { return new ReadableStream({ start(c) { c.enqueue(bytes(text)); c.close(); } }); }

async function buildVendoredPinnedSdk() {
  const output = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL("../scripts/build-pinned-sdk.mjs", import.meta.url)), "--json"]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", chunk => (stdout += chunk));
    child.stderr.on("data", chunk => (stderr += chunk));
    child.on("close", code => code === 0 ? resolve(stdout) : reject(new Error(stderr || `build exited ${code}`)));
  });
  return JSON.parse(output);
}

test("public SDK calls retain header, prefix, snake_case, and stream bytes", async () => {
  const calls = [];
  const prior = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const u = String(url); const headers = new Headers(init.headers);
    calls.push({ url: u, method: init.method ?? "GET", headers, body: init.body });
    if (u.endsWith("/exec-stream")) return new Response(stream(await readFile(new URL("../fixtures/exec-stream.bytes", import.meta.url))), { status: 200 });
    if (u.endsWith("/code-stream")) return new Response(stream(await readFile(new URL("../fixtures/code-stream-error.bytes", import.meta.url))), { status: 200 });
    if (u.endsWith("/status")) return Response.json({ status: "running" });
    if (u.endsWith("/exec")) return Response.json({ output: "stdout", error: "stderr", exit_code: 0 });
    if (u.endsWith("/code")) return Response.json({ output: "ok", exit_code: 0 });
    if (u.endsWith("/run/stream")) return new Response(stream(agentFixture), { headers: { "content-type": "text/event-stream" } });
    return Response.json({ ...dto.response.box, id: "box_fixture", status: "running", labels: [], enabled_skills: [], files: [], runs: [], logs: [] });
  };
  try {
    const box = await Box.create({ name: "fixture", apiKey: "fixture-not-a-secret", baseUrl: "http://contract.invalid", keepAlive: true, agent: { harness: "codex", model: "openai/gpt-5", apiKey: "agent-key" } });
    await box.getStatus();
    await box.configureModel("openai/gpt-5");
    const run = await box.exec.command("echo hello");
    assert.equal(run.stdout, "stdout");
    const chunks = []; for await (const chunk of await box.exec.stream("echo hello")) chunks.push(chunk);
    assert.deepEqual(chunks, [{ type: "output", data: "stdout: raw\nstderr: raw\n" }, { type: "exit", exitCode: 7, cpuNs: 42 }]);
    await assert.rejects(async () => { for await (const _ of await box.exec.streamCode({ code: "bad", lang: "python" })) {} }, BoxError);
    assert.deepEqual([...agentFixture.matchAll(/^event: (.+)$/gm)].map(event => event[1]), ["run_start", "text", "thinking", "tool", "tool_result", "stats", "done"]);
    const agentEvents = []; for await (const event of await box.agent.stream({ prompt: "hello" })) agentEvents.push(event);
    assert.deepEqual(agentEvents.map(event => event.type), ["start", "text-delta", "reasoning", "tool-call", "tool-result", "stats", "finish"]);
    assert.equal(agentEvents.at(-1).sessionId, "session_fixture");
    await box.skills.add("owner/repo/skill");
    assert.deepEqual(await box.skills.list(), []);
    await box.skills.remove("owner/repo/skill");
    assert.ok(calls.every((c) => new URL(c.url).pathname.startsWith("/v2/box")));
    assert.ok(calls.every((c) => c.headers.get("X-Box-Api-Key") === "fixture-not-a-secret"));
    const create = calls[0]; assert.match(String(create.body), /keep_alive/); assert.doesNotMatch(String(create.body), /keepAlive/);
    const skillAdd = calls.find(c => new URL(c.url).pathname.endsWith("/config/skills") && c.method === "POST");
    assert.deepEqual(JSON.parse(String(skillAdd.body)), { skill_id: "owner/repo/skill" });
    assert.ok(calls.some(c => c.method === "DELETE" && new URL(c.url).pathname.endsWith("/config/skills/owner/repo/skill")));
  } finally { globalThis.fetch = prior; }
});

test("custom harness emits box-sse-v1 snake_case bytes", async () => {
  let output = "";
  await runCustomHarness(({ prompt }, emit) => { emit.text(prompt); return { output: prompt, inputTokens: 1, outputTokens: 1, sessionId: "s" }; }, { argv: ["-p", "hello", "--model", "custom", "--stream"], write: (x) => { output += x; } });
  assert.equal(output, await readFile(new URL("../fixtures/custom-harness.sse", import.meta.url), "utf8").then((x) => x.replaceAll("session_fixture", "s")));
});

test("SDK errors preserve all required status and server error shapes", async () => {
  const prior = globalThis.fetch;
  try {
    for (const status of [401, 404, 409, 413, 422, 429, 501]) {
      globalThis.fetch = async () => Response.json(errors[String(status)], { status });
      await assert.rejects(() => Box.get("box_fixture", { apiKey: "fixture", baseUrl: "http://contract.invalid" }), (e) => e instanceof BoxError && e.statusCode === status && e.message === errors[String(status)].error);
    }
  }
  finally { globalThis.fetch = prior; }
});

test("vendored pinned SDK webhook run sends exact wire shape and accepts run identity", async () => {
  const built = await buildVendoredPinnedSdk();
  const prior = globalThis.fetch;
  const calls = [];
  try {
    const { Box: PinnedBox } = await import(`${built.entry}?webhook-contract`);
    globalThis.fetch = async (url, init = {}) => {
      calls.push({ path: new URL(String(url)).pathname, method: init.method ?? "GET", body: init.body });
      if (String(url).endsWith("/run")) {
        return Response.json({ status: "accepted", run_id: "01900000-0000-7000-8000-000000000001" });
      }
      return Response.json({ ...dto.response.box, id: "box_fixture", status: "idle", labels: [], agent: "codex", model: "openai/gpt-5" });
    };
    const box = await PinnedBox.create({
      apiKey: "fixture-api-key",
      baseUrl: "http://contract.invalid",
      agent: { harness: "codex", model: "openai/gpt-5", apiKey: "agent-fixture" },
    });
    const run = await box.agent.run({
      prompt: "deliver me",
      webhook: {
        url: "https://hooks.example.test/completed",
        headers: { Authorization: "Bearer fixture" },
      },
    });
    assert.equal(run.id, "01900000-0000-7000-8000-000000000001");
    const webhook = calls.find(call => call.path.endsWith("/run"));
    assert.equal(webhook.method, "POST");
    assert.deepEqual(JSON.parse(String(webhook.body)), {
      prompt: "deliver me",
      webhook: {
        url: "https://hooks.example.test/completed",
        headers: { Authorization: "Bearer fixture" },
      },
    });
  } finally {
    globalThis.fetch = prior;
    await rm(built.cleanup.dir, { recursive: true, force: true });
  }
});

test("vendored pinned SDK browser model actions preserve exact wire and response mapping", async () => {
  const built = await buildVendoredPinnedSdk();
  const prior = globalThis.fetch;
  const calls = [];
  try {
    const { Box: PinnedBox } = await import(`${built.entry}?browser-model-contract`);
    globalThis.fetch = async (url, init = {}) => {
      const path = new URL(String(url)).pathname;
      calls.push({ path, method: init.method ?? "GET", body: init.body });
      if (path.endsWith("/browser/extract")) return Response.json({ data: { title: "Contract" } });
      if (path.endsWith("/browser/observe")) return Response.json({ elements: [{ description: "Submit", selector: "#submit", url: "https://example.test/submit" }] });
      if (path.endsWith("/browser/act")) return Response.json({ success: true, message: "clicked", action_description: "Click submit", actions: [{ selector: "#submit", description: "Submit", method: "click", arguments: [] }], cache_status: "MISS", input_tokens: 11, output_tokens: 7 });
      if (path.endsWith("/browser/run")) return Response.json({ data: { ok: true }, result: "done", completed: true, steps: [{ step: 1, action: "click", reasoning: "submit", url: "https://example.test/done" }], step_count: 1, input_tokens: 19, output_tokens: 5 });
      return Response.json({ ...dto.response.box, id: "box_fixture", status: "idle", labels: [], browser: true });
    };
    const box = await PinnedBox.get("box_fixture", { apiKey: "fixture", baseUrl: "http://contract.invalid" });
    const tab = box.browser.getTab("tab_contract");
    assert.deepEqual(await tab.extract("read title", z.object({ title: z.string() }), { model: "openai/gpt-4o" }), { title: "Contract" });
    assert.deepEqual(await tab.observe("find submit"), { elements: [{ description: "Submit", selector: "#submit", url: "https://example.test/submit" }] });
    assert.deepEqual(await tab.act("click submit"), { success: true, message: "clicked", actionDescription: "Click submit", actions: [{ selector: "#submit", description: "Submit", method: "click", arguments: [] }], cacheStatus: "MISS", inputTokens: 11, outputTokens: 7 });
    assert.deepEqual(await tab.run("finish", { schema: z.object({ ok: z.boolean() }), maxSteps: 4, model: "openrouter/model" }), { data: { ok: true }, result: "done", completed: true, steps: [{ step: 1, action: "click", reasoning: "submit", url: "https://example.test/done" }], stepCount: 1, inputTokens: 19, outputTokens: 5 });
    assert.deepEqual(calls.filter(call => call.path.includes("/browser/")).map(call => ({ path: call.path, method: call.method, body: JSON.parse(String(call.body)) })), [
      { path: "/v2/box/box_fixture/browser/extract", method: "POST", body: { instruction: "read title", schema: { type: "object", properties: { title: { type: "string" } }, required: ["title"], additionalProperties: false }, tab: "tab_contract", model: "openai/gpt-4o" } },
      { path: "/v2/box/box_fixture/browser/observe", method: "POST", body: { instruction: "find submit", tab: "tab_contract" } },
      { path: "/v2/box/box_fixture/browser/act", method: "POST", body: { instruction: "click submit", tab: "tab_contract" } },
      { path: "/v2/box/box_fixture/browser/run", method: "POST", body: { prompt: "finish", tab: "tab_contract", schema: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"], additionalProperties: false }, max_steps: 4, model: "openrouter/model" } },
    ]);
  } finally {
    globalThis.fetch = prior;
    await rm(built.cleanup.dir, { recursive: true, force: true });
  }
});

test("vendored pinned SDK browser recordings preserve wire metadata and binary download", async () => {
  const built = await buildVendoredPinnedSdk();
  const work = await mkdtemp(join(tmpdir(), "boxd-sdk-recording-contract-"));
  const prior = globalThis.fetch;
  const calls = [];
  const recordingId = "01900000-0000-7000-8000-000000000055";
  const metadata = status => ({
    id: recordingId,
    box_id: "box_fixture",
    status,
    started_at: 1_700_000_000_000,
    expires_at: 1_701_209_600,
    ...(status === "recording" ? {} : {
      ended_at: 1_700_000_001_000,
      duration_ms: 1_000,
      size_bytes: 16,
      segment_count: 1,
      mp4_size_bytes: 11,
      stopped_reason: "requested",
    }),
    max_duration_seconds: 42,
    markers: [{ type: "tab_switch", at_ms: 0, label: "Fixture", tab_id: "tab_contract" }],
  });
  try {
    const { Box: PinnedBox } = await import(`${built.entry}?browser-recording-contract`);
    globalThis.fetch = async (url, init = {}) => {
      const parsed = new URL(String(url));
      const path = parsed.pathname;
      const method = init.method ?? "GET";
      calls.push({ path, search: parsed.search, method, body: init.body, headers: new Headers(init.headers) });
      if (path.endsWith(`/${recordingId}/download`)) {
        return new Response(bytes("mp4-contract"), { headers: { "content-type": "video/mp4" } });
      }
      if (path.endsWith("/browser/recordings") && method === "POST") return Response.json(metadata("recording"));
      if (path.endsWith("/browser/recordings/stop")) return Response.json(metadata("completed"));
      if (path.endsWith("/browser/recordings") && method === "GET") {
        return Response.json({ recordings: [metadata("completed")] });
      }
      if (path.endsWith(`/${recordingId}`)) return Response.json(metadata("recording"));
      return Response.json({ ...dto.response.box, id: "box_fixture", status: "idle", labels: [], browser: true });
    };
    const box = await PinnedBox.get("box_fixture", { apiKey: "fixture", baseUrl: "http://contract.invalid" });
    const handle = await box.browser.recordings.start({ maxDurationSeconds: 42 });
    assert.equal(handle.id, recordingId);
    const stopped = await handle.stop();
    assert.equal(stopped.status, "completed");
    assert.equal(stopped.expiresAt, 1_701_209_600_000);
    assert.deepEqual(stopped.markers, [{ type: "tab_switch", atMs: 0, endMs: undefined, label: "Fixture", tabId: "tab_contract" }]);
    assert.equal((await box.browser.recordings.list())[0].segmentCount, 1);
    assert.equal((await box.browser.recordings.get(recordingId)).id, recordingId);
    const destination = join(work, "recording.mp4");
    assert.equal(await box.browser.recordings.download(recordingId, { path: destination }), destination);
    assert.equal(await readFile(destination, "utf8"), "mp4-contract");

    const start = calls.find(call => call.path.endsWith("/browser/recordings") && call.method === "POST");
    assert.deepEqual(JSON.parse(String(start.body)), { max_duration_seconds: 42 });
    const list = calls.find(call => call.path.endsWith("/browser/recordings") && call.method === "GET");
    assert.equal(list.search, "?limit=100");
    assert.ok(calls.every(call => call.headers.get("X-Box-Api-Key") === "fixture"));
  } finally {
    globalThis.fetch = prior;
    await rm(work, { recursive: true, force: true });
    await rm(built.cleanup.dir, { recursive: true, force: true });
  }
});

test("vendored pinned SDK cannot materialize a recursive file name", async () => {
  const built = await buildVendoredPinnedSdk();
  const work = await mkdtemp(join(tmpdir(), "boxd-sdk-nested-download-"));
  const priorFetch = globalThis.fetch;
  const priorCwd = process.cwd();
  try {
    const { Box: PinnedBox } = await import(built.entry);
    globalThis.fetch = async url => {
      const pathname = new URL(String(url)).pathname;
      if (pathname.endsWith("/files/list")) {
        return Response.json({ files: [{ name: "left/same.txt", path: "/workspace/home/src/left/same.txt", size: 1, is_dir: false, mod_time: "2026-01-01T00:00:00Z" }] });
      }
      if (pathname.endsWith("/files/download")) return new Response(bytes("x"));
      return Response.json({ ...dto.response.box, id: "box_fixture", status: "idle", labels: [] });
    };
    const box = await PinnedBox.get("box_fixture", { apiKey: "fixture", baseUrl: "http://contract.invalid" });
    process.chdir(work);
    await assert.rejects(
      () => box.files.download({ folder: "src" }),
      error => error?.code === "ENOENT" && String(error.path).endsWith("src/left/same.txt"),
    );
  } finally {
    process.chdir(priorCwd);
    globalThis.fetch = priorFetch;
    await rm(work, { recursive: true, force: true });
    await rm(built.cleanup.dir, { recursive: true, force: true });
  }
});

test("vendored pinned SDK receives 501 for nested download while flat download succeeds", async () => {
  const built = await buildVendoredPinnedSdk();
  const work = await mkdtemp(join(tmpdir(), "boxd-sdk-download-contract-"));
  const priorCwd = process.cwd();
  const server = createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    response.setHeader("content-type", "application/json");
    if (url.pathname.endsWith("/files/list")) {
      const folder = url.searchParams.get("folder");
      if (folder?.endsWith("/nested")) {
        response.statusCode = 501;
        response.end(JSON.stringify({ error: "feature_not_supported", message: "nested directory download in @upstash/box@0.6.3", request_id: "fixture" }));
        return;
      }
      response.end(JSON.stringify({ files: [{ name: "same.txt", path: "/workspace/home/flat/same.txt", size: 4, is_dir: false, mod_time: "2026-01-01T00:00:00Z" }] }));
      return;
    }
    if (url.pathname.endsWith("/files/download")) {
      response.setHeader("content-type", "application/octet-stream");
      response.end("flat");
      return;
    }
    response.end(JSON.stringify({ ...dto.response.box, id: "box_fixture", status: "idle", labels: [] }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    assert.equal(typeof address, "object");
    const { Box: PinnedBox, BoxError: PinnedBoxError } = await import(`${built.entry}?http-contract`);
    const box = await PinnedBox.get("box_fixture", { apiKey: "fixture", baseUrl: `http://127.0.0.1:${address.port}` });
    process.chdir(work);
    await assert.rejects(
      () => box.files.download({ folder: "nested" }),
      error => error instanceof PinnedBoxError && error.statusCode === 501 && error.message === "feature_not_supported",
    );
    await box.files.download({ folder: "flat" });
    assert.equal(await readFile(join(work, "flat", "same.txt"), "utf8"), "flat");
  } finally {
    process.chdir(priorCwd);
    server.close();
    await once(server, "close");
    await rm(work, { recursive: true, force: true });
    await rm(built.cleanup.dir, { recursive: true, force: true });
  }
});
