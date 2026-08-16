import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const runner = new URL("../scripts/capture-runner.mjs", import.meta.url).pathname;
const registry = new URL("../public-case-registry.mjs", import.meta.url);
const captures = new URL("../fixtures/public-captures.json", import.meta.url);
function fails() { assert.throws(() => execFileSync(process.execPath, [runner], { cwd: new URL("../", import.meta.url).pathname, stdio: "pipe" })); }

test("public runner rejects a removed public case", async () => {
  const original = await readFile(registry, "utf8");
  await writeFile(registry, original.replace('staticCase("GET /v2/box", () => Box.list({ ...connection, label: "label fixture" })),', ""));
  try { fails(); } finally { await writeFile(registry, original); }
});

test("public runner rejects a public case id that disagrees with its actual dispatch", async () => {
  const original = await readFile(registry, "utf8");
  const mutated = original.replace(
    'suffix.endsWith("/download") ? "GET" : "POST"',
    'suffix.endsWith("/download") ? "POST" : "POST"',
  );
  assert.notEqual(mutated, original);
  await writeFile(registry, mutated);
  try { fails(); } finally { await writeFile(registry, original); }
});

test("public runner rejects committed query, JSON, content-type, multipart and route mutations", async () => {
  const original = await readFile(captures, "utf8");
  const mutate = (change) => { const fixture = JSON.parse(original); change(fixture); return `${JSON.stringify(fixture, null, 2)}\n`; };
  const mutations = [
    fixture => fixture.captures[0].query[0][1] = "wrong label",
    fixture => fixture.captures.find(c => c.path === "/v2/box/{box_id}/exec").body.command[0] = "wrong",
    fixture => fixture.captures.find(c => c.headers.content_type === "application/json").headers.content_type = "text/plain",
    fixture => fixture.captures.find(c => c.body_kind === "multipart").body.find(field => field.filename).filename = "wrong.txt",
    fixture => fixture.captures.find(c => c.path === "/v2/box/{box_id}/exec").path = "/v2/box/unknown/actual",
  ];
  try { for (const mutation of mutations) { await writeFile(captures, mutate(mutation)); fails(); } }
  finally { await writeFile(captures, original); }
});
