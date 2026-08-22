import assert from "node:assert/strict";
import test from "node:test";
import { normalizeHeaders, normalizeJson, normalizeResponse, normalizeSse } from "../differential/normalizers.mjs";

test("JSON normalizer sorts objects and removes volatile and secret values", () => {
  assert.deepEqual(
    normalizeJson({ z: 1, id: "official-id", nested: { api_key: "secret", a: 2 }, labels: ["b", "a"] }),
    { id: "<id>", labels: ["b", "a"], nested: { a: 2, api_key: "<redacted>" }, z: 1 },
  );
});

test("header normalizer keeps comparable headers and canonicalizes multipart boundaries", () => {
  assert.deepEqual(
    normalizeHeaders({ Date: "tomorrow", "Content-Type": "multipart/form-data; boundary=random", "Cache-Control": " no-cache " }),
    { "cache-control": "no-cache", "content-type": "multipart/form-data; boundary=<generated>" },
  );
});

test("SSE normalizer handles CRLF, comments, multiline JSON and volatile ids", () => {
  const input = ": keepalive\r\nid: 42\r\nevent: done\r\ndata: {\"run_id\":\"official\",\r\ndata: \"output\":\"ok\"}\r\n\r\n";
  assert.deepEqual(normalizeSse(input), [
    { event: "done", id: "<event_id>", data: { output: "ok", run_id: "<run_id>" } },
  ]);
});

test("response normalizer compares status, selected headers and normalized JSON", () => {
  assert.deepEqual(
    normalizeResponse({ status: 200, headers: { "content-type": "application/json", date: "ignored" }, json: { request_id: "a", ok: true } }),
    { status: 200, headers: { "content-type": "application/json" }, body: { ok: true, request_id: "<request_id>" } },
  );
});
