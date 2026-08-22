import { browserAgentAdapters } from "./adapters/browser-agent.mjs";
import { coreAdapters } from "./adapters/core.mjs";
import { execFileGitAdapters } from "./adapters/exec-file-git.mjs";
import { lifecycleAdapters } from "./adapters/lifecycle.mjs";

const groups = [coreAdapters, lifecycleAdapters, execFileGitAdapters, browserAgentAdapters];
const entries = groups.flatMap((group) => [...group]);
const duplicateIds = entries
  .map(([caseId]) => caseId)
  .filter((caseId, index, all) => all.indexOf(caseId) !== index);

if (duplicateIds.length > 0) {
  throw new Error(`duplicate differential adapter case IDs: ${[...new Set(duplicateIds)].sort().join(", ")}`);
}

export const differentialAdapters = new Map(entries);

export function adapterCaseIds() {
  return [...differentialAdapters.keys()].sort();
}
