import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import test from "node:test";

const check = new URL("../scripts/check-manifest.mjs", import.meta.url).pathname;
const source = new URL("../upstream/client.ts", import.meta.url);
const override = new URL("../route-overrides.json", import.meta.url);
const manifest = new URL("../raw-dispatch-manifest.json", import.meta.url);
const provenance = new URL("../provenance.json", import.meta.url);
function rejectsGate() { assert.throws(() => execFileSync(process.execPath, [check], { stdio: "pipe" })); }

test("extractor gate rejects vendored source hash drift and restores it", async () => {
  const original = await readFile(source, "utf8");
  await writeFile(source, `${original}\n// mutation\n`);
  try { rejectsGate(); } finally { await writeFile(source, original); }
});

test("extractor gate rejects raw manifest method/path drift and restores it", async () => {
  const original = await readFile(manifest, "utf8");
  const mutated = original.replace('"method": "POST"', '"method": "TRACE"');
  assert.notEqual(mutated, original); await writeFile(manifest, mutated);
  try { rejectsGate(); } finally { await writeFile(manifest, original); }
});

test("extractor gate rejects stale or unknown overrides and restores them", async () => {
  const original = await readFile(override, "utf8");
  const value = JSON.parse(original);
  value.overrides = [{ source_line: 1, node_hash: "unknown", route: { method: "GET", path: "/v2/box" } }];
  await writeFile(override, `${JSON.stringify(value, null, 2)}\n`);
  try { rejectsGate(); } finally { await writeFile(override, original); }
});

test("extractor gate rejects an added business callsite even when its source hash is updated", async () => {
  const originalSource = await readFile(source, "utf8");
  const originalProof = await readFile(provenance, "utf8");
  const mutatedSource = `${originalSource}\nthis._request("GET", "/v2/box");\n`;
  const proof = JSON.parse(originalProof);
  proof.upstream.files["packages/sdk/src/client.ts"] = (await import("node:crypto")).createHash("sha256").update(mutatedSource).digest("hex");
  await writeFile(source, mutatedSource);
  await writeFile(provenance, `${JSON.stringify(proof, null, 2)}\n`);
  try { rejectsGate(); } finally { await writeFile(source, originalSource); await writeFile(provenance, originalProof); }
});

test("extractor gate rejects a removed normalization mapping and restores it", async () => {
  const original = await readFile(manifest, "utf8");
  const value = JSON.parse(original);
  value.normalization.pop();
  await writeFile(manifest, `${JSON.stringify(value, null, 2)}\n`);
  try { rejectsGate(); } finally { await writeFile(manifest, original); }
});

test("AST extraction preserves sensitive placeholders and structured query keys", async () => {
  const raw = JSON.parse(await readFile(manifest, "utf8")).dispatches;
  const byLine = (line) => raw.find((row) => row.source.line === line);
  assert.equal(byLine(314).canonical_path, "/v2/box/{box_id}/runs/{run_id}/cancel");
  assert.equal(byLine(2699).canonical_path, "/v2/box/{box_id}/schedules/{id}");
  assert.deepEqual(byLine(465).query.map((entry) => entry.name), ["encoding", "full_page", "tab"]);
  assert.deepEqual(byLine(2070).query.map((entry) => entry.name), ["encoding", "path"]);
  assert.deepEqual(byLine(2390).query.map((entry) => entry.name), ["limit", "offset"]);
  assert.deepEqual(byLine(2522).query.map((entry) => entry.name), ["cursor", "limit"]);
  assert.equal(byLine(972).role, "poll");
  assert.equal(byLine(1496).role, "retry");
  assert.equal(byLine(2359).role, "poll");
  for (const line of [972, 1496, 2023, 2359, 2842, 2866]) {
    assert.ok(byLine(line), `raw callsite ${line} is retained`);
    assert.ok(byLine(line).normalized_into, `raw callsite ${line} has a normalized contract`);
  }
  assert.equal(byLine(2023).role, "contract_reuse");
  assert.equal(byLine(2023).response_kind, "json", "cd reads ExecResult.exit_code despite returning Promise<void>");
  assert.equal(byLine(314).response_kind, "empty", "cancel discards the successful response after catch");
  assert.equal(byLine(2842).role, "contract_reuse");
  assert.equal(byLine(2866).role, "contract_reuse");
  assert.equal(byLine(1272).body_kind, "json|multipart");
  assert.equal(byLine(1337).body_kind, "json|multipart");
  assert.equal(byLine(1757).response_kind, "raw+sse");
  assert.equal(byLine(1821).response_kind, "raw+sse");
  assert.equal(byLine(2110).body_kind, "multipart");
  assert.equal(byLine(2110).response_kind, "empty");
  assert.equal(byLine(2139).response_kind, "binary");
  assert.equal(byLine(2549).response_kind, "binary");
  assert.ok(byLine(2070).query.every((entry) => entry.encoding === "url"));
  assert.ok(byLine(2139).query.every((entry) => entry.encoding === "url"));
  for (const line of [2676, 2691, 2723]) assert.equal(byLine(line).body_kind, "json", `line ${line} shorthand body`);
  assert.ok(raw.every((row) => !row.canonical_path.includes("{this_")));
  assert.equal(raw.length, 86);
  assert.equal(raw.filter((row) => row.transport === "_request").length, 64);
  assert.equal(raw.filter((row) => row.transport === "fetch").length, 22);
});
