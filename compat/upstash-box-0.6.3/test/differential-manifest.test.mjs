import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runDifferential } from "../differential/executor.mjs";
import { differentialConfig } from "../differential/gates.mjs";

const check = new URL("../scripts/check-differential.mjs", import.meta.url).pathname;
const matrix = JSON.parse(await readFile(new URL("../differential/case-matrix.json", import.meta.url), "utf8"));

test("generated differential matrix, adapter registry and schemas pass the machine gate", () => {
  const output = execFileSync(process.execPath, [check], { encoding: "utf8" });
  assert.deepEqual(JSON.parse(output), { contracts: 78, public_cases: 82, uncovered_contracts: 0, schemas: 2, executable_cases: 3, blocked_without_adapter: 79 });
});

test("preflight without credentials is blocked before the SDK loader can execute", async () => {
  let loaded = false;
  const evidence = await runDifferential({
    matrix,
    selectedCases: [matrix.cases.find((item) => item.case_id === "GET /v2/box")],
    config: differentialConfig({}),
    sdkLoader: async () => {
      loaded = true;
      throw new Error("must not load");
    },
  });
  assert.equal(loaded, false);
  assert.equal(evidence.status, "blocked");
  assert.equal(evidence.results.executed_cases, 0);
  assert.equal(evidence.results.passed_cases, 0);
  assert.equal(evidence.results.blocked_cases, 1);
  assert.ok(evidence.gates.blockers.some((item) => item.gate === "credential"));
});

test("a selected case without an adapter is explicitly blocked before SDK loading", async () => {
  let loaded = false;
  const evidence = await runDifferential({
    matrix,
    selectedCases: [matrix.cases.find((item) => item.case_id === "DELETE /v2/box")],
    config: differentialConfig({
      BOXD_DIFF_OFFICIAL_BASE_URL: "https://official.example.test",
      BOXD_DIFF_LOCAL_BASE_URL: "http://127.0.0.1:7331",
      BOXD_DIFF_OFFICIAL_API_KEY: "official-key",
      BOXD_DIFF_LOCAL_API_KEY: "local-key",
      BOXD_DIFF_OFFICIAL_PREFIX: "OFFICIAL_DIFF",
      BOXD_DIFF_LOCAL_PREFIX: "LOCAL_DIFF",
    }),
    sdkLoader: async () => {
      loaded = true;
      throw new Error("must not load");
    },
  });
  assert.equal(loaded, false);
  assert.equal(evidence.status, "blocked");
  assert.equal(evidence.results.executed_cases, 0);
  assert.equal(evidence.results.blocked_cases, 1);
  assert.deepEqual(evidence.gates.blockers.map((item) => item.gate), ["adapter"]);
});
