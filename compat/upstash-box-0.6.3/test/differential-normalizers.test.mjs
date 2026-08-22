import assert from "node:assert/strict";
import test from "node:test";
import { normalizeBinary, normalizeHeaders, normalizeJson, normalizeResponse, normalizeSse } from "../differential/normalizers.mjs";

test("JSON normalizer sorts objects and removes volatile and secret values", () => {
  assert.deepEqual(
    normalizeJson({ z: 1, id: "official-id", nested: { api_key: "secret", a: 2 }, labels: ["b", "a"] }),
    { id: "<id>", labels: ["b", "a"], nested: { a: 2, api_key: "<redacted>" }, z: 1 },
  );
});

test("JSON normalizer canonicalizes response URLs and runtime accounting", () => {
  assert.deepEqual(normalizeJson({ screencast_url: "wss://one.invalid/live?t=secret", input_tokens: 12 }), {
    input_tokens: "<redacted>",
    screencast_url: "<url>",
  });
});

test("JSON normalizer removes target-specific PR and recording identities", () => {
  assert.deepEqual(normalizeJson({ number: 42, url: "https://github.com/a/b/pull/42", started_at: 1, size_bytes: 999, status: "completed" }), {
    number: "<number>", size_bytes: "<size_bytes>", started_at: "<started_at>", status: "completed", url: "<url>",
  });
});

test("binary normalizer compares media shape without unstable encoded bytes", () => {
  assert.deepEqual(normalizeBinary(Uint8Array.from([0, 0, 0, 24, 102, 116, 121, 112, 1]), "video/mp4"), {
    kind: "binary", format: "mp4", nonempty: true,
  });
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
