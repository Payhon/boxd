import assert from "node:assert/strict";
import test from "node:test";
import { differentialConfig, evaluateDifferentialGates, redactEvidence, redactUrl } from "../differential/gates.mjs";

const readOnly = [{ case_id: "GET /v2/box", setup: null, risk: { classification: "read_only" } }];
const baseEnv = {
  BOXD_DIFF_OFFICIAL_BASE_URL: "https://official.example.test",
  BOXD_DIFF_LOCAL_BASE_URL: "http://127.0.0.1:7331",
  BOXD_DIFF_OFFICIAL_API_KEY: "official-secret",
  BOXD_DIFF_LOCAL_API_KEY: "local-secret",
  BOXD_DIFF_OFFICIAL_PREFIX: "OFFICIAL_DIFF",
  BOXD_DIFF_LOCAL_PREFIX: "LOCAL_DIFF",
};

test("missing credentials and target configuration blocks all execution", () => {
  const result = evaluateDifferentialGates(readOnly, differentialConfig({}));
  assert.equal(result.allowed, false);
  assert.deepEqual(result.blockers.map((item) => item.gate), ["credential", "base_url", "resource_prefix"]);
});

test("read-only and sandbox-mutating cases need no extra opt-in", () => {
  const sandbox = [{ case_id: "DELETE /v2/box", setup: null, risk: { classification: "sandbox_mutating" } }];
  assert.deepEqual(evaluateDifferentialGates([...readOnly, ...sandbox], differentialConfig(baseEnv)), { allowed: true, blockers: [] });
});

test("external mutation, cost, budget, runtime and provider gates are independent", () => {
  const selected = [
    { case_id: "PUT /v2/box/settings/env/{key}", setup: null, risk: { classification: "externally_mutating" } },
    { case_id: "POST /v2/box/{box_id}/run", setup: "Box.create", risk: { classification: "cost_incurring" } },
  ];
  const result = evaluateDifferentialGates(selected, differentialConfig(baseEnv));
  assert.deepEqual(result.blockers.map((item) => item.gate), ["runtime", "provider", "externally_mutating_opt_in", "cost_opt_in", "budget"]);
});

test("evidence redaction removes nested credential-like values", () => {
  const evidence = redactEvidence({ apiKey: "alpha", nested: { authorization: "Bearer beta" }, safe: "ok" });
  assert.deepEqual(evidence, { apiKey: "<redacted>", nested: { authorization: "<redacted>" }, safe: "ok" });
  assert.doesNotMatch(JSON.stringify(evidence), /alpha|beta/);
});

test("evidence URLs drop userinfo, query credentials and fragments", () => {
  assert.equal(redactUrl("https://user:password@example.test/v2?token=secret#fragment"), "https://example.test/v2");
});
