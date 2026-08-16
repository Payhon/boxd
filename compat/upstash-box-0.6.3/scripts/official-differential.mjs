import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const officialBaseUrl = "https://us-east-1.box.upstash.com";
const fixture = JSON.parse(
  await readFile(
    new URL("../fixtures/official/unauthenticated-list-401.json", import.meta.url),
    "utf8",
  ),
);

async function loadPinnedSdk() {
  const output = await new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [fileURLToPath(new URL("./build-pinned-sdk.mjs", import.meta.url)), "--json"],
      { cwd: fileURLToPath(new URL("../", import.meta.url)) },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("close", (code) =>
      code === 0 ? resolve(stdout) : reject(new Error(stderr || `SDK build exited ${code}`)),
    );
  });
  const built = JSON.parse(output);
  return { sdk: await import(built.entry), cleanup: built.cleanup };
}

const authenticated = process.env.BOXD_OFFICIAL_DIFFERENTIAL_API_KEY;
if (authenticated && process.env.BOXD_OFFICIAL_DIFFERENTIAL_OPT_IN !== "1") {
  throw new Error(
    "refusing authenticated official request without BOXD_OFFICIAL_DIFFERENTIAL_OPT_IN=1",
  );
}

const built = await loadPinnedSdk();
const sdk = built.sdk;
try {
if (authenticated) {
  const boxes = await sdk.Box.list({ apiKey: authenticated, baseUrl: officialBaseUrl });
  console.log(
    JSON.stringify({
      mode: "authenticated-read-only",
      operation: "Box.list",
      status: "success",
      result_count: boxes.length,
      note: "No identifiers, response bodies, or API key are printed.",
    }),
  );
} else {
  await assert.rejects(
    () =>
      sdk.Box.list({
        apiKey: "boxd_fixture_invalid_key",
        baseUrl: officialBaseUrl,
      }),
    (error) => {
      assert.ok(error instanceof sdk.BoxError);
      assert.equal(error.statusCode, fixture.response.status);
      assert.equal(error.message, fixture.response.body.error);
      return true;
    },
  );
  console.log(
    JSON.stringify({
      mode: "unauthenticated-read-only",
      operation: "Box.list",
      status: fixture.response.status,
      fixture: "fixtures/official/unauthenticated-list-401.json",
    }),
  );
}
} finally {
  await rm(built.cleanup.dir, { recursive: true, force: true });
}
