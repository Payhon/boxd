import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { publicCases } from "../public-case-registry.mjs";

const root = new URL("../", import.meta.url);
const routeUrl = new URL("../route-manifest.json", import.meta.url);
const registryUrl = new URL("../public-case-registry.mjs", import.meta.url);
const outputUrl = new URL("../differential/case-matrix.json", import.meta.url);
const stdout = process.argv.includes("--stdout");

const [routeSource, registrySource] = await Promise.all([
  readFile(routeUrl, "utf8"),
  readFile(registryUrl, "utf8"),
]);
const routeManifest = JSON.parse(routeSource);
// Building the registry does not execute a case. The SDK members are only
// referenced inside deferred callbacks, so no package build or network access
// is needed to enumerate the pinned public cases.
const registryCases = publicCases({ Box: {}, EphemeralBox: {} });
const contractId = (method, path) => `${method} ${path}`;
const declaredContract = (caseId) => caseId.replace(/#.*$/, "");
const isCostBearing = (item) =>
  item.setup === "Box.create" ||
  ["POST /v2/box", "POST /v2/box/from-snapshot"].includes(declaredContract(item.id));
const riskClassification = (item) => {
  if (/^(?:PUT|DELETE) \/v2\/box\/settings\/env/.test(item.id) || /\/git\/(?:push|create-pr)/.test(item.id)) return "externally_mutating";
  if (isCostBearing(item)) return "cost_incurring";
  if (!item.destructive) return "read_only";
  return "sandbox_mutating";
};

const cases = registryCases.map((item) => ({
  case_id: item.id,
  declared_contract: declaredContract(item.id),
  setup: item.setup,
  risk: {
    classification: riskClassification(item),
    destructive: item.destructive || item.setup !== null,
    may_incur_cost: isCostBearing(item),
  },
  credentials: ["official_api_key", "local_api_key"],
}));

const caseIds = new Set(cases.map((item) => item.case_id));
const contracts = routeManifest.routes.map((route) => {
  const id = contractId(route.method, route.path);
  let linked = cases.filter((item) => item.declared_contract === id).map((item) => item.case_id);
  const responseLinked = route.dispatch_ids.length === 0;
  if (responseLinked && linked.length === 0 && route.path.endsWith("/playlist")) {
    const parent = contractId(route.method, route.path.slice(0, -"/playlist".length));
    linked = cases.filter((item) => item.declared_contract === parent).map((item) => item.case_id);
  }
  return {
    contract_id: id,
    method: route.method,
    path: route.path,
    relation: responseLinked ? "response_linked_capability" : "direct",
    case_ids: linked.sort(),
  };
});

const uncovered = contracts.filter((item) => item.case_ids.length === 0);
const matrix = {
  schema_version: 1,
  sdk: "@upstash/box@0.6.3",
  source_commit: "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934",
  generated_from: [
    { path: "route-manifest.json", sha256: createHash("sha256").update(routeSource).digest("hex") },
    { path: "public-case-registry.mjs", sha256: createHash("sha256").update(registrySource).digest("hex") },
  ],
  summary: {
    contracts: contracts.length,
    public_cases: cases.length,
    uncovered_contracts: uncovered.length,
  },
  contracts,
  cases,
};

if (new Set(cases.map((item) => item.case_id)).size !== cases.length) throw new Error("differential case ids must be unique");
for (const item of cases) {
  if (!contracts.some((contract) => contract.contract_id === item.declared_contract)) {
    throw new Error(`case does not map to a pinned contract: ${item.case_id}`);
  }
  if (!caseIds.has(item.case_id)) throw new Error(`internal case registry error: ${item.case_id}`);
}
if (contracts.length !== 78 || cases.length !== 82 || uncovered.length !== 0) {
  throw new Error(`differential coverage gate failed: ${contracts.length} contracts, ${cases.length} cases, ${uncovered.length} uncovered`);
}

const rendered = `${JSON.stringify(matrix, null, 2)}\n`;
if (stdout) process.stdout.write(rendered);
else await writeFile(outputUrl, rendered);
