// Coverage is runtime evidence, not a manifest projection.  The check runner
// is deliberately read-only; this explicit command is the only writer.
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";

const runner = new URL("./capture-runner.mjs", import.meta.url);
const output = execFileSync(process.execPath, [runner.pathname, "--write-coverage", "--json"], { encoding: "utf8" });
await writeFile(new URL("../coverage-table.json", import.meta.url), `${JSON.stringify(JSON.parse(output), null, 2)}\n`);
