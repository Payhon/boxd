import assert from "node:assert/strict";
import test from "node:test";
import { rm, stat } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

test("pinned build reports runner-owned cleanup and leaves no temp tree after cleanup", async () => {
  const output = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL("../scripts/build-pinned-sdk.mjs", import.meta.url)), "--json"]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("close", (code) => code === 0 ? resolve(stdout) : reject(new Error(stderr || `build exited ${code}`)));
  });
  const built = JSON.parse(output);
  assert.match(built.entry, /index\.js$/);
  assert.equal(built.cleanup.dir, built.dir);
  assert.match(built.cleanup.token, /^[a-f0-9]{64}$/);
  await stat(built.cleanup.dir);
  await rm(built.cleanup.dir, { recursive: true, force: true });
  await assert.rejects(stat(built.cleanup.dir));
});
