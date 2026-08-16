import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import test from "node:test";

const manifestUrl = new URL("../route-manifest.json", import.meta.url);
const check = new URL("../scripts/check-manifest.mjs", import.meta.url).pathname;
test("manifest gate rejects a route/method mutation", async () => {
  const original = await readFile(manifestUrl, "utf8");
  const mutated = original.replace('"method": "DELETE"', '"method": "TRACE"');
  assert.notEqual(mutated, original);
  await writeFile(manifestUrl, mutated);
  try { assert.throws(() => execFileSync(process.execPath, [check], { stdio: "pipe" })); }
  finally { await writeFile(manifestUrl, original); }
});
