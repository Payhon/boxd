import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, realpathSync, rmSync } from "node:fs";
import { readFile, rm, stat, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { publicCases } from "../public-case-registry.mjs";

const root = new URL("../", import.meta.url);
const fixtureUrl = new URL("../fixtures/public-captures.json", import.meta.url);
const coverageUrl = new URL("../coverage-table.json", import.meta.url);
const manifest = JSON.parse(await readFile(new URL("../route-manifest.json", import.meta.url), "utf8"));
const dto = JSON.parse(await readFile(new URL("../fixtures/dto.json", import.meta.url), "utf8"));
const types = JSON.parse(await readFile(new URL("../fixtures/types.json", import.meta.url), "utf8"));
const errors = JSON.parse(await readFile(new URL("../fixtures/errors.json", import.meta.url), "utf8"));
const agentSse = await readFile(new URL("../fixtures/agent.sse", import.meta.url), "utf8");
const execBytes = await readFile(new URL("../fixtures/exec-stream.bytes", import.meta.url));
const codeErrorBytes = await readFile(new URL("../fixtures/code-stream-error.bytes", import.meta.url));
const harnessSse = await readFile(new URL("../fixtures/custom-harness.sse", import.meta.url), "utf8");
const generating = process.argv.includes("--generate-fixtures");
const writingCoverage = process.argv.includes("--write-coverage");
const jsonOutput = process.argv.includes("--json");
const official = /(^|\.)upstash\.com$/i;
const serverUrl = process.env.BOXD_BASE_URL;
if (serverUrl && (process.env.BOXD_CONTRACT_SERVER_OPT_IN !== "1" || official.test(new URL(serverUrl).hostname))) throw new Error("server execution is disabled: set BOXD_CONTRACT_SERVER_OPT_IN=1 and a non-Upstash BOXD_BASE_URL");
if (serverUrl && process.env.BOXD_CONTRACT_DESTRUCTIVE_OPT_IN !== "1") throw new Error("server execution includes destructive public SDK cases; set BOXD_CONTRACT_DESTRUCTIVE_OPT_IN=1");

function template(path) {
  const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${path.split(/(\{[^}]+\})/).map(part => part.startsWith("{") ? part.endsWith("+}") ? ".+" : "[^/]+" : escape(part)).join("")}$`);
}
function routeFor(method, pathname) {
  // A generic /{box_id} route also matches nested paths under a permissive
  // template.  Select the longest matching manifest path, never a case id.
  return manifest.routes.filter(r => r.method === method && template(r.path).test(pathname)).sort((a, b) => b.path.length - a.path.length)[0];
}
const bytes = text => new TextEncoder().encode(text);
const stream = text => new ReadableStream({ start(c) { c.enqueue(typeof text === "string" ? bytes(text) : text); c.close(); } });
const canonical = value => JSON.stringify(value, Object.keys(value ?? {}).sort());
function jsonFor(path) {
  const base = dto.responses?.box ?? { id: "box_fixture", status: "running", size: "small", keep_alive: true, agent: "codex", labels: [], enabled_skills: [], expires_at: 99 };
  if (path.endsWith("/status")) return { status: "running" }; if (path.endsWith("/runs")) return []; if (path.endsWith("/logs")) return [];
  if (path.endsWith("/files/read")) return { content: "aGVsbG8=" }; if (path.endsWith("/files/list")) return { files: [{ name: "a.txt", path: "/workspace/home/src/a.txt", is_dir: false }] };
  if (path.endsWith("/snapshots")) return []; if (path.endsWith("/schedules")) return []; if (path.includes("/schedules/")) return { id: "schedule_fixture", cron: "* * * * *" };
  if (path.endsWith("/exec") || path.endsWith("/code")) return dto.responses?.exec ?? { output: "ok", error: "", exit_code: 0 }; if (path.endsWith("/git/diff")) return { diff: "" }; if (path.endsWith("/git/status")) return { status: "" };
  if (path.endsWith("/git/commit")) return { sha: "abc" }; if (path.endsWith("/git-config")) return { user_name: "n" }; if (path.endsWith("/git/create-pr")) return { url: "https://example.invalid/pr" }; if (path.endsWith("/git/exec")) return { output: "", exit_code: 0 };
  if (path.endsWith("/browser/tabs")) return { id: "tab_fixture", tabs: [] }; if (path.endsWith("/browser/connect")) return { cdp_url: "ws://example.invalid/cdp" }; if (path.endsWith("/browser/screencast")) return { screencast_url: "https://example.invalid/live" };
  if (path.endsWith("/browser/content")) return { content: "<html/>" }; if (path.endsWith("/browser/screenshot")) return { data: "aGVsbG8=" }; if (path.includes("/browser/recordings")) return { id: "recording_fixture", status: "stopped", recordings: [], next_cursor: "", playlist_url: "https://example.invalid/v2/box/box_fixture/browser/recordings/recording_fixture/playlist" };
  if (path.endsWith("/browser/extract")) return { data: {} }; if (path.endsWith("/browser/observe")) return { elements: [] }; if (path.endsWith("/browser/act")) return { success: true }; if (path.endsWith("/browser/run")) return { result: "", completed: true, steps: [], step_count: 0 };
  if (path.endsWith("/preview")) return { url: "https://example.invalid/p", previews: [] }; return base;
}
function responseFor(path) {
  if (path.endsWith("/exec-stream")) return new Response(stream(execBytes), { headers: { "content-type": "text/event-stream" } });
  if (path.endsWith("/code-stream")) return new Response(stream(codeErrorBytes), { headers: { "content-type": "text/event-stream" } });
  if (path.endsWith("/run/stream")) return new Response(stream(agentSse), { headers: { "content-type": "text/event-stream" } });
  if (path.endsWith("/files/download")) return new Response(bytes("archive"));
  if (path.endsWith("/recordings/recording_fixture/download")) return new Response(bytes("mp4"), { headers: { "content-type": "video/mp4" } });
  return Response.json(jsonFor(path));
}
async function snapshotRequest(input, init = {}) {
  const request = new Request(String(input), { method: init.method ?? "GET", headers: init.headers, body: init.body });
  const url = new URL(request.url); const method = request.method;
  const headers = { api_key: request.headers.get("x-box-api-key"), content_type: request.headers.get("content-type") };
  let body = null; let body_kind = "none";
  if (init.body instanceof FormData) {
    body_kind = "multipart"; const form = await request.formData(); body = [];
    for (const [name, value] of form.entries()) body.push(typeof value === "string" ? { name, value } : { name, filename: value.name, type: value.type, sha256: createHash("sha256").update(Buffer.from(await value.arrayBuffer())).digest("hex") });
    body.sort((a, b) => canonical(a).localeCompare(canonical(b)));
  } else if (init.body != null) { body_kind = "json"; body = await request.json(); }
  return { method, pathname: url.pathname, query: [...url.searchParams.entries()].sort(), headers, body_kind, body };
}
function comparable(c) { return { method: c.method, path: c.route, query: c.query, headers: { api_key: c.headers.api_key, content_type: c.headers.content_type?.replace(/boundary=.*/, "boundary=<generated>") ?? null }, body_kind: c.body_kind, body: c.body }; }
async function loadPinned() { const output = await new Promise((resolve, reject) => { const p = spawn(process.execPath, [fileURLToPath(new URL("./build-pinned-sdk.mjs", import.meta.url)), "--json"], { cwd: fileURLToPath(root) }); let out="", err=""; p.stdout.on("data", d=>out+=d); p.stderr.on("data", d=>err+=d); p.on("close", c=>c ? reject(new Error(err || `build exited ${c}`)) : resolve(out)); }); const built = JSON.parse(output); return { sdk: await import(built.entry), dir: built.dir, cleanup: built.cleanup }; }
const built = await loadPinned(); const sdk = built.sdk; const cases = publicCases(sdk); const captured = []; const covered = new Set(); const caseEvidence = []; let expected = generating ? [] : JSON.parse(await readFile(fixtureUrl, "utf8")).captures; let position = 0;
function cleanupPinnedSync() {
  try {
    const { dir, token } = built.cleanup;
    if (createHash("sha256").update(dir).digest("hex") !== token) return;
    const metadata = lstatSync(dir);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) return;
    if (!basename(dir).startsWith("boxd-pinned-sdk-") || dirname(realpathSync(dir)) !== realpathSync(tmpdir())) return;
    rmSync(dir, { recursive: true, force: true });
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}
process.once("exit", cleanupPinnedSync);
const caseIds = cases.map((item) => item.id);
assert.equal(new Set(caseIds).size, caseIds.length, "public case ids must be unique");
if (process.argv.includes("--list-cases")) {
  console.log(JSON.stringify({ public_cases: caseIds.length, case_ids: caseIds }, null, 2));
  await rm(built.dir, { recursive: true, force: true });
  process.exit(0);
}
const prior = globalThis.fetch;
if (!serverUrl) globalThis.fetch = async (input, init = {}) => {
  const request = await snapshotRequest(input, init); const route = routeFor(request.method, request.pathname);
  if (!route) throw new Error(`unknown actual route: ${request.method} ${request.pathname}`);
  assert.equal(request.headers.api_key, "fixture-api-key", `${request.method} ${request.pathname} missing API key`);
  if (request.body_kind === "json") assert.match(request.headers.content_type ?? "", /^application\/json/i, `${request.method} ${request.pathname} JSON content-type`);
  if (request.body_kind === "multipart") assert.match(request.headers.content_type ?? "", /^multipart\/form-data; boundary=/i, `${request.method} ${request.pathname} multipart boundary`);
  const capture = { ...request, route: route.path };
  if (generating) expected.push(comparable(capture)); else assert.deepEqual(comparable(capture), expected[position], `capture ${position} differs from committed fixture`);
  position++; captured.push(capture); covered.add(`${request.method} ${route.path}`);
  if (request.method === "POST" && request.pathname === "/v2/box" && request.body_kind === "json") return Response.json({ ...jsonFor(request.pathname), keep_alive: Boolean(request.body.keep_alive), agent: request.body.agent, model: request.body.model });
  return responseFor(request.pathname);
};
try {
  // Each call is awaited through its documented public SDK method.  Several
  // mutators intentionally return void, so parsing is proven by the SDK's
  // request/response implementation rather than treating void as a failure.
  for (const item of cases) {
    const firstCapture = captured.length;
    await item.run();
    if (!serverUrl) {
      const declaredContract = item.id.replace(/#.*$/, "");
      const actualContracts = [...new Set(captured.slice(firstCapture).map((entry) => `${entry.method} ${entry.route}`))];
      assert.ok(
        actualContracts.includes(declaredContract),
        `${item.id} did not dispatch its declared contract; actual: ${actualContracts.join(", ")}`,
      );
      caseEvidence.push({ case_id: item.id, captured_contracts: actualContracts });
    }
  }
  const box = await sdk.Box.create({ apiKey: "fixture-api-key", baseUrl: serverUrl || "http://boxd.contract.invalid", keepAlive: true, browser: true, agent: { harness: "codex", model: "openai/gpt-5", apiKey: "agent-key" } });
  const recording = await box.browser.recordings.get("recording_fixture"); assert.match(recording.playlistUrl, /\/browser\/recordings\/recording_fixture\/playlist$/);
  assert.deepEqual([...agentSse.matchAll(/^event: (.+)$/gm)].map(x => x[1]), ["run_start", "text", "thinking", "tool", "tool_result", "stats", "done"]);
  const events = []; for await (const event of await box.agent.stream({ prompt: "hello" })) events.push(event);
  assert.deepEqual(events.map(x => x.type), ["start", "text-delta", "reasoning", "tool-call", "tool-result", "stats", "finish"]);
  assert.equal(events[0].runId, "run_fixture"); assert.equal(events[1].text, "hello"); assert.equal(events[3].toolName, "shell"); assert.equal(events[5].memoryPeakBytes, 1024); assert.equal(events.at(-1).sessionId, "session_fixture"); assert.ok(types.exports.includes("BoxData")); assert.match(harnessSse, /event: done/);
} finally { if (!serverUrl) globalThis.fetch = prior; await rm(".boxd-recording.mp4", { force: true }); await rm(built.dir, { recursive: true, force: true }); }
if (!generating) assert.equal(position, expected.length, "committed capture fixture contains stale dispatches");
const responseLinkedRoutes = manifest.routes.filter(r => r.dispatch_ids.length === 0 || r.relation === "response_linked_capability");
const directRoutes = manifest.routes.filter(r => !responseLinkedRoutes.includes(r)); for (const r of directRoutes) assert.ok(covered.has(`${r.method} ${r.path}`), `missing executable capture case: ${r.method} ${r.path}`);
for (const status of [401,404,409,413,422,429,501]) assert.ok(errors[String(status)]?.error, `missing error fixture ${status}`);
assert.equal(responseLinkedRoutes.length, 1, "frozen manifest must contain exactly one response-linked contract");
const table = { kind: "Phase 0 public SDK capture evidence", public_cases: cases.length, public_case_ids: caseIds, case_evidence: caseEvidence, captured_dispatches: captured.length, covered_direct_contracts: directRoutes.length, response_linked: responseLinkedRoutes.length, total: directRoutes.length + responseLinkedRoutes.length, entries: [...covered].sort().map(id => ({ id, runner: "public-sdk-capture" })) };
if (generating) await writeFile(fixtureUrl, `${JSON.stringify({ schema: 1, captures: expected }, null, 2)}\n`);
if (!generating && !writingCoverage && !serverUrl) assert.deepEqual(JSON.parse(await readFile(coverageUrl, "utf8")), table, "coverage-table.json is stale; run npm run generate:coverage");
if (jsonOutput) console.log(JSON.stringify(table)); else console.log(JSON.stringify({ mode: generating ? "generate-fixtures" : serverUrl ? "server" : "mock-fetch-capture", ...table }, null, 2));
