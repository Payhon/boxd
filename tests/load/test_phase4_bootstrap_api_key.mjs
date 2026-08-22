import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { baseUrl, bootstrapApiKey, LOAD_SCOPES, revokeApiKey, safeOutputPath } from "../../scripts/phase4-bootstrap-api-key.mjs";

test("bootstrap helper creates and revokes an admin-issued load key without printing it", async (t) => {
  const requests = [];
  let invalidCreation = false;
  const server = createServer(async (request, response) => {
    requests.push({ method: request.method, url: request.url, headers: request.headers });
    if (request.url === "/api/admin/v1/auth/login") {
      response.setHeader("set-cookie", "boxd_session=session-value; Path=/; HttpOnly; SameSite=Strict");
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ csrf_token: "boxd_csrf_1234567890123456" }));
      return;
    }
    if (request.url === "/api/admin/v1/api-keys" && request.method === "POST") {
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify({ id: "01900000-0000-7000-8000-000000000099", scopes: invalidCreation ? ["boxes_read"] : LOAD_SCOPES, api_key: "boxd_compat_test_secret" }));
      return;
    }
    if (request.url === "/api/admin/v1/api-keys/01900000-0000-7000-8000-000000000099" && request.method === "DELETE") {
      response.setHeader("content-type", "application/json");
      response.end("{}");
      return;
    }
    response.statusCode = 404;
    response.end("{}");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const address = server.address();
  const root = await mkdtemp(join(tmpdir(), "boxd-phase4-bootstrap-test-"));
  const previous = { RUNNER_TEMP: process.env.RUNNER_TEMP, BOXD_BASE_URL: process.env.BOXD_BASE_URL, BOXD_ADMIN_USER: process.env.BOXD_ADMIN_USER, BOXD_ADMIN_PASSWORD: process.env.BOXD_ADMIN_PASSWORD };
  process.env.RUNNER_TEMP = root;
  process.env.BOXD_BASE_URL = `http://127.0.0.1:${address.port}`;
  process.env.BOXD_ADMIN_USER = "admin";
  process.env.BOXD_ADMIN_PASSWORD = "test-password";
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });

  const output = join(root, "api-key.json");
  await bootstrapApiKey(output);
  const created = JSON.parse(await readFile(output, "utf8"));
  assert.equal(created.id, "01900000-0000-7000-8000-000000000099");
  assert.equal(created.api_key, "boxd_compat_test_secret");
  assert.equal((await stat(output)).mode & 0o777, 0o600);
  assert.equal(requests[1].headers.cookie, "boxd_session=session-value");
  assert.equal(requests[1].headers["x-csrf-token"], "boxd_csrf_1234567890123456");

  await revokeApiKey(output);
  await assert.rejects(() => stat(output));
  assert.equal(requests.at(-1).method, "DELETE");

  invalidCreation = true;
  await assert.rejects(() => bootstrapApiKey(join(root, "rollback.json")), /contract mismatch/);
  assert.equal(requests.at(-1).method, "DELETE");
});

test("bootstrap helper rejects escaped, symlinked, hardlinked, and pre-existing paths", async () => {
  const root = await mkdtemp(join(tmpdir(), "boxd-phase4-bootstrap-path-test-"));
  const previous = process.env.RUNNER_TEMP;
  process.env.RUNNER_TEMP = root;
  try {
    await assert.rejects(() => safeOutputPath(join(root, "..", "escape.json")), /below RUNNER_TEMP/);
    const realParent = join(root, "real");
    const { mkdir, symlink, writeFile, link } = await import("node:fs/promises");
    await mkdir(realParent);
    await symlink(realParent, join(root, "symlink-parent"));
    await assert.rejects(() => safeOutputPath(join(root, "symlink-parent", "key.json")), /real directory/);
    await symlink(join(root, "missing-target"), join(root, "symlink-file"));
    await assert.rejects(() => safeOutputPath(join(root, "symlink-file")), /must not already exist/);
    const existing = join(root, "existing.json");
    await writeFile(existing, "{}", { mode: 0o600 });
    await assert.rejects(() => safeOutputPath(existing), /must not already exist/);
    const alias = join(root, "alias.json");
    await link(existing, alias);
    await assert.rejects(() => safeOutputPath(alias, { mustExist: true }), /unique regular file/);
  } finally {
    if (previous === undefined) delete process.env.RUNNER_TEMP; else process.env.RUNNER_TEMP = previous;
  }
});

test("bootstrap helper requires an explicit clean loopback port", async () => {
  const previous = process.env.BOXD_BASE_URL;
  try {
    for (const value of ["http://127.0.0.1", "http://127.0.0.1:7331?x=1", "http://127.0.0.1:7331/#x"]) {
      process.env.BOXD_BASE_URL = value;
      assert.throws(() => baseUrl(), /explicit loopback port/);
    }
    process.env.BOXD_BASE_URL = "http://127.0.0.1:80";
    assert.equal(baseUrl().port, "");
  } finally {
    if (previous === undefined) delete process.env.BOXD_BASE_URL; else process.env.BOXD_BASE_URL = previous;
  }
});
