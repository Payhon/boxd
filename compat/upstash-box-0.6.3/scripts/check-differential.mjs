import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { adapterCaseIds } from "../differential/adapters.mjs";

const root = new URL("../", import.meta.url);
const generated = execFileSync(
  process.execPath,
  [new URL("./generate-differential-matrix.mjs", import.meta.url).pathname, "--stdout"],
  { encoding: "utf8" },
);
const committed = await readFile(new URL("../differential/case-matrix.json", import.meta.url), "utf8");
assert.equal(committed, generated, "differential/case-matrix.json is stale; run npm run generate:differential");

const matrix = JSON.parse(committed);
const caseSchema = JSON.parse(await readFile(new URL("../differential/schemas/case-matrix.schema.json", import.meta.url), "utf8"));
const runSchema = JSON.parse(await readFile(new URL("../differential/schemas/run-manifest.schema.json", import.meta.url), "utf8"));
assert.equal(caseSchema.properties.summary.properties.contracts.const, 78);
assert.equal(caseSchema.properties.summary.properties.public_cases.const, 82);
assert.deepEqual(runSchema.properties.status.enum, ["blocked", "passed", "failed"]);
assert.equal(matrix.schema_version, 1);
assert.equal(matrix.sdk, "@upstash/box@0.6.3");
assert.equal(matrix.contracts.length, 78);
assert.equal(matrix.cases.length, 82);
assert.equal(matrix.summary.uncovered_contracts, 0);
assert.equal(new Set(matrix.contracts.map((item) => item.contract_id)).size, 78);
assert.equal(new Set(matrix.cases.map((item) => item.case_id)).size, 82);
assert.deepEqual(new Set(matrix.cases.map((item) => item.risk.classification)), new Set(["read_only", "sandbox_mutating", "externally_mutating", "cost_incurring"]));
const knownCases = new Set(matrix.cases.map((item) => item.case_id));
for (const contract of matrix.contracts) {
  assert.ok(contract.case_ids.length > 0, `uncovered differential contract ${contract.contract_id}`);
  for (const caseId of contract.case_ids) assert.ok(knownCases.has(caseId), `unknown case ${caseId}`);
}
assert.doesNotMatch(committed, /fixture-api-key|agent-key|BOXD_OFFICIAL_DIFFERENTIAL_API_KEY=/);
for (const caseId of adapterCaseIds()) assert.ok(knownCases.has(caseId), `adapter is not backed by public registry case ${caseId}`);
console.log(JSON.stringify({ contracts: 78, public_cases: 82, uncovered_contracts: 0, schemas: 2, executable_cases: adapterCaseIds().length, blocked_without_adapter: 82 - adapterCaseIds().length }, null, 2));
