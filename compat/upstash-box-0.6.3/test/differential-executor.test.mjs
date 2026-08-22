import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runDifferential } from "../differential/executor.mjs";
import { differentialConfig } from "../differential/gates.mjs";

const matrix = JSON.parse(await readFile(new URL("../differential/case-matrix.json", import.meta.url), "utf8"));
const select = (...ids) => ids.map((id) => matrix.cases.find((item) => item.case_id === id));

async function fixtureServer({ key, boxes = [], cleanupStatus = 204, delayMs = 0 }) {
  const requests = [];
  const server = createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    requests.push({ method: request.method, url: request.url, apiKey: request.headers["x-box-api-key"], body: Buffer.concat(chunks).toString("utf8") });
    if (delayMs > 0 && request.method === "GET" && request.url === "/v2/box") await new Promise((resolve) => setTimeout(resolve, delayMs));
    if (request.headers["x-box-api-key"] !== key) {
      response.writeHead(401, { "content-type": "application/json" });
      response.end('{"error":"wrong credential"}');
    } else if (request.method === "GET" && request.url === "/v2/box") {
      response.writeHead(200, { "content-type": "application/json", "cache-control": "no-cache" });
      response.end(JSON.stringify(boxes));
    } else if (request.method === "GET" && request.url === "/v2/box/settings/env") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"env_vars":{}}');
    } else if (request.method === "PUT" && request.url.startsWith("/v2/box/settings/env/")) {
      response.writeHead(204);
      response.end();
    } else if (request.method === "DELETE" && request.url.startsWith("/v2/box/settings/env/")) {
      response.writeHead(cleanupStatus, cleanupStatus === 204 ? {} : { "content-type": "application/json" });
      response.end(cleanupStatus === 204 ? undefined : '{"error":"cleanup failed"}');
    } else {
      response.writeHead(404, { "content-type": "application/json" });
      response.end('{"error":"not found"}');
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return { url: `http://127.0.0.1:${address.port}`, requests, close: () => new Promise((resolve) => server.close(resolve)) };
}

function config(official, local, extra = {}) {
  return differentialConfig({
    BOXD_DIFF_OFFICIAL_BASE_URL: official.url,
    BOXD_DIFF_LOCAL_BASE_URL: local.url,
    BOXD_DIFF_OFFICIAL_API_KEY: "official-key-secret",
    BOXD_DIFF_LOCAL_API_KEY: "local-key-secret",
    BOXD_DIFF_OFFICIAL_PREFIX: "OFFICIAL_DIFF",
    BOXD_DIFF_LOCAL_PREFIX: "LOCAL_DIFF",
    BOXD_DIFF_EXTERNALLY_MUTATING_OPT_IN: "1",
    BOXD_DIFF_REQUEST_TIMEOUT_MS: "1000",
    BOXD_DIFF_GLOBAL_TIMEOUT_MS: "5000",
    BOXD_DIFF_CONCURRENCY: "2",
    ...extra,
  });
}

test("vendored SDK makes real isolated requests to both targets and cleans mutations", async () => {
  const official = await fixtureServer({ key: "official-key-secret" });
  const local = await fixtureServer({ key: "local-key-secret" });
  try {
    const evidence = await runDifferential({
      matrix,
      selectedCases: select("GET /v2/box", "PUT /v2/box/settings/env/{key}"),
      config: config(official, local),
    });
    assert.equal(evidence.status, "passed");
    assert.equal(evidence.results.executed_cases, 2);
    assert.equal(evidence.results.passed_cases, 2);
    assert.equal(evidence.results.cleanup_failed_cases, 0);
    assert.ok(official.requests.every((item) => item.apiKey === "official-key-secret"));
    assert.ok(local.requests.every((item) => item.apiKey === "local-key-secret"));
    assert.ok(official.requests.some((item) => item.method === "DELETE" && item.url.includes("OFFICIAL_DIFF")));
    assert.ok(local.requests.some((item) => item.method === "DELETE" && item.url.includes("LOCAL_DIFF")));
    assert.doesNotMatch(JSON.stringify(evidence), /official-key-secret|local-key-secret|boxd-differential-value/);
  } finally {
    await Promise.all([official.close(), local.close()]);
  }
});

test("a normalized response difference fails the case", async () => {
  const official = await fixtureServer({ key: "official-key-secret", boxes: [] });
  const local = await fixtureServer({ key: "local-key-secret", boxes: [{ id: "local-id", status: "idle" }] });
  try {
    const evidence = await runDifferential({ matrix, selectedCases: select("GET /v2/box"), config: config(official, local) });
    assert.equal(evidence.status, "failed");
    assert.equal(evidence.results.failed_cases, 1);
    assert.equal(evidence.results.cases[0].reason, "artifact_mismatch");
  } finally {
    await Promise.all([official.close(), local.close()]);
  }
});

test("cleanup failure fails an otherwise matching mutating case", async () => {
  const official = await fixtureServer({ key: "official-key-secret" });
  const local = await fixtureServer({ key: "local-key-secret", cleanupStatus: 500 });
  try {
    const evidence = await runDifferential({ matrix, selectedCases: select("PUT /v2/box/settings/env/{key}"), config: config(official, local) });
    assert.equal(evidence.status, "failed");
    assert.equal(evidence.results.cleanup_failed_cases, 1);
    assert.equal(evidence.results.cases[0].reason, "cleanup_failed");
  } finally {
    await Promise.all([official.close(), local.close()]);
  }
});

test("per-request timeout fails the case instead of hanging or passing", async () => {
  const official = await fixtureServer({ key: "official-key-secret", delayMs: 100 });
  const local = await fixtureServer({ key: "local-key-secret" });
  try {
    const evidence = await runDifferential({
      matrix,
      selectedCases: select("GET /v2/box"),
      config: config(official, local, { BOXD_DIFF_REQUEST_TIMEOUT_MS: "20", BOXD_DIFF_GLOBAL_TIMEOUT_MS: "200" }),
    });
    assert.equal(evidence.status, "failed");
    assert.equal(evidence.results.failed_cases, 1);
    assert.equal(evidence.results.cases[0].reason, "target_execution_failed");
  } finally {
    await Promise.all([official.close(), local.close()]);
  }
});

test("global timeout bounds the complete selected run", async () => {
  const official = await fixtureServer({ key: "official-key-secret", delayMs: 100 });
  const local = await fixtureServer({ key: "local-key-secret", delayMs: 100 });
  try {
    const evidence = await runDifferential({
      matrix,
      selectedCases: select("GET /v2/box"),
      config: config(official, local, { BOXD_DIFF_REQUEST_TIMEOUT_MS: "500", BOXD_DIFF_GLOBAL_TIMEOUT_MS: "20" }),
    });
    assert.equal(evidence.status, "failed");
    assert.equal(evidence.results.failed_cases, 1);
    assert.equal(evidence.results.cases[0].reason, "target_execution_failed");
  } finally {
    await Promise.all([official.close(), local.close()]);
  }
});
