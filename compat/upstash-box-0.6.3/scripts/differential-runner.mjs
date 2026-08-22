import { readFile } from "node:fs/promises";
import { runDifferential } from "../differential/executor.mjs";
import { differentialConfig } from "../differential/gates.mjs";

const matrix = JSON.parse(await readFile(new URL("../differential/case-matrix.json", import.meta.url), "utf8"));
const requested = [];
for (let index = 2; index < process.argv.length; index++) {
  if (process.argv[index] !== "--case" || !process.argv[index + 1]) throw new Error("usage: differential-runner.mjs [--case <case-id>]...");
  requested.push(process.argv[++index]);
}
const byId = new Map(matrix.cases.map((item) => [item.case_id, item]));
for (const id of requested) if (!byId.has(id)) throw new Error(`unknown differential case: ${id}`);
const selectedCases = requested.length > 0 ? requested.map((id) => byId.get(id)) : matrix.cases;
const evidence = await runDifferential({ matrix, selectedCases, config: differentialConfig() });
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
if (evidence.status === "failed") process.exitCode = 1;
else if (evidence.status === "blocked") process.exitCode = 2;
