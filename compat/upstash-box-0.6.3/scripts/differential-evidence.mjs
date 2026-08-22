import { createHash } from "node:crypto";
import { lstat, mkdir, open, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import process from "node:process";

const COMMIT = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const CASE_ID = /^[a-z0-9][a-z0-9._:/-]{0,191}$/;
const MATRIX_CASE_ID = /^[A-Za-z0-9][A-Za-z0-9 ._:/#{}+\-]{0,191}$/;
const TOKEN = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const SENSITIVE_KEY = /(?:api[_-]?key|authorization|cookie|credential|password|secret|token|body)/i;
const REASONS = new Set(["cleanup_failed", "target_execution_failed", "artifact_mismatch", "adapter_missing"]);
const REDACTED = "<redacted>";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
const fail = (message) => { throw new Error(`invalid differential evidence input: ${message}`); };

function parseArgs(argv) {
  const args = {};
  for (let index = 2; index < argv.length; index += 1) {
    const option = argv[index];
    if (!option.startsWith("--") || !argv[index + 1] || argv[index + 1].startsWith("--")) fail(`missing value for ${option}`);
    const key = option.slice(2).replaceAll("-", "_");
    if (!["run", "matrix", "output", "commit", "virtualization", "local_binary", "runtime_bundle", "local_config"].includes(key)) fail(`unknown option ${option}`);
    if (args[key] !== undefined) fail(`duplicate option ${option}`);
    args[key] = argv[++index];
  }
  args.commit ||= process.env.GITHUB_SHA;
  args.virtualization ||= process.env.BOXD_DIFF_VIRTUALIZATION || "none";
  for (const key of ["run", "matrix", "output", "commit", "local_binary", "runtime_bundle", "local_config"]) if (!args[key]) fail(`--${key.replaceAll("_", "-")} is required`);
  return args;
}

async function readRegular(path, label) {
  let stat;
  try { stat = await lstat(path); } catch (error) { fail(`${label} cannot be read: ${error.message}`); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail(`${label} must be a unique regular file`);
  try { return await readFile(path); } catch (error) { fail(`${label} cannot be read: ${error.message}`); }
}

function walk(value, path = "$") {
  if (Array.isArray(value)) return value.flatMap((item, index) => walk(item, `${path}[${index}]`));
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, item]) => [{ key, item, path: `${path}.${key}` }, ...walk(item, `${path}.${key}`)]);
}

function scanSecrets(value, raw) {
  const findings = [];
  for (const { key, item, path } of walk(value)) {
    if (key === "secret_scan") continue;
    if (SENSITIVE_KEY.test(key) && item !== null && item !== REDACTED && item !== true && item !== false) {
      findings.push(`${path}:${key}`);
    }
  }
  const secretValues = Object.entries(process.env)
    .filter(([key, item]) => /(?:API_KEY|TOKEN|PASSWORD|SECRET)/i.test(key) && item && item.length >= 8)
    .map(([, item]) => item);
  for (const secret of secretValues) if (raw.includes(secret)) findings.push("environment-secret-value");
  return [...new Set(findings)];
}

function safeCaseId(caseId, used) {
  let id = caseId.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
  if (!id) id = "case";
  if (!CASE_ID.test(id) || used.has(id)) id = `${id.slice(0, 120)}-${hash(Buffer.from(caseId)).slice(0, 12)}`;
  used.add(id);
  return id;
}

function bareOrigin(value, label, requirePort = false) {
  if (typeof value !== "string" || value.length === 0) fail(`${label} must be a bare HTTP(S) origin`);
  let url;
  try { url = new URL(value); } catch { fail(`${label} is not a valid URL`); }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.pathname !== "/" || url.search || url.hash || (requirePort && url.port === "")) fail(`${label} must be a bare HTTP(S) origin`);
  return url;
}

function requireMatrixShape(matrix) {
  if (!matrix || !Array.isArray(matrix.cases) || matrix.cases.length !== 82) fail("matrix must contain exactly 82 cases");
  const ids = new Set();
  for (const item of matrix.cases) {
    if (!item || typeof item.case_id !== "string" || !MATRIX_CASE_ID.test(item.case_id)) fail("matrix case ID is invalid");
    if (ids.has(item.case_id)) fail(`duplicate matrix case ID ${item.case_id}`);
    ids.add(item.case_id);
  }
}

function requireRunShape(run, matrix) {
  if (!run || typeof run !== "object" || Array.isArray(run)) fail("run manifest must be an object");
  const required = ["schema_version", "sdk", "mode", "status", "selection", "targets", "limits", "executor", "gates", "results"];
  for (const key of required) if (!(key in run)) fail(`run manifest missing ${key}`);
  const allowed = new Set(required);
  for (const key of Object.keys(run)) if (!allowed.has(key)) fail(`run manifest has closed-schema field ${key}`);
  if (run.schema_version !== 1 || run.sdk !== "@upstash/box@0.6.3" || run.mode !== "authenticated-differential") fail("run manifest identity is not pinned");
  if (!["blocked", "passed", "failed"].includes(run.status)) fail("run status is invalid");
  if (!run.selection || run.selection.contracts !== 78 || run.selection.cases !== 82) fail("run selection must be 78 contracts / 82 cases");
  const official = bareOrigin(run.targets?.official, "official target");
  const local = bareOrigin(run.targets?.local, "local target", true);
  if (official.origin === local.origin) fail("official and local targets must be distinct");
  if (!(local.hostname === "localhost" || local.hostname === "127.0.0.1" || local.hostname === "[::1]" || local.hostname === "::1")) fail("local target must be loopback");
  if (!run.executor || run.executor.adapter_cases !== 82 || run.executor.blocked_without_adapter !== 0) fail("run adapter coverage is incomplete");
  if (!run.results || !Number.isInteger(run.results.executed_cases) || !Number.isInteger(run.results.passed_cases) || !Number.isInteger(run.results.failed_cases) || !Number.isInteger(run.results.blocked_cases) || !Number.isInteger(run.results.cleanup_failed_cases) || !Array.isArray(run.results.cases)) fail("run results are malformed");
  if (!run.gates || typeof run.gates !== "object" || !Array.isArray(run.gates.blockers)) fail("run gates are malformed");
  for (const [name, value, fields] of [["selection", run.selection, ["contracts", "cases"]], ["targets", run.targets, ["official", "local"]], ["limits", run.limits, ["request_timeout_ms", "global_timeout_ms", "concurrency", "budget_usd"]], ["executor", run.executor, ["adapter_cases", "blocked_without_adapter"]], ["gates", run.gates, ["allowed", "blockers"]], ["results", run.results, ["executed_cases", "passed_cases", "failed_cases", "blocked_cases", "cleanup_failed_cases", "evidence_redacted", "cases"]]]) {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${name} must be an object`);
    const accepted = new Set(fields);
    for (const key of Object.keys(value)) if (!accepted.has(key)) fail(`${name} has closed-schema field ${key}`);
  }
  if (run.results.evidence_redacted !== true) fail("run evidence must be marked redacted");
  requireMatrixShape(matrix);
  const expected = new Set(matrix.cases.map((item) => item.case_id));
  const seen = new Set();
  for (const item of run.results.cases) {
    requireCaseResult(item);
    if (seen.has(item.case_id)) fail(`duplicate case result ${item.case_id}`);
    seen.add(item.case_id);
    if (!expected.has(item.case_id)) fail(`extra case result ${item.case_id}`);
  }
  if (run.status === "blocked" && run.results.cases.length === 0) {
    if (run.results.executed_cases !== 0 || run.results.passed_cases !== 0 || run.results.failed_cases !== 0 || run.results.blocked_cases !== 82 || run.results.cleanup_failed_cases !== 0) fail("blocked result counts are not closed");
  } else {
    if (seen.size !== expected.size) fail("run results are missing one or more matrix cases");
    const counts = { passed: 0, failed: 0, blocked: 0 };
    let cleanup = 0;
    for (const item of run.results.cases) {
      counts[item.status] += 1;
      if (item.status !== "blocked" && (item.official.cleanup_error || item.local.cleanup_error)) cleanup += 1;
    }
    if (run.results.executed_cases !== counts.passed + counts.failed || run.results.passed_cases !== counts.passed || run.results.failed_cases !== counts.failed || run.results.blocked_cases !== counts.blocked || run.results.cleanup_failed_cases !== cleanup) fail("run result counts are not closed");
  }
  if (run.status === "passed" && (run.gates.allowed !== true || run.gates.blockers.length !== 0 || run.results.passed_cases !== 82 || run.results.failed_cases !== 0 || run.results.blocked_cases !== 0 || run.results.cleanup_failed_cases !== 0)) fail("passed status/gates/results are inconsistent");
  if (run.status === "failed" && (run.gates.allowed !== true || run.gates.blockers.length !== 0 || run.results.failed_cases < 1)) fail("failed status/gates/results are inconsistent");
  if (run.status === "blocked" && (run.gates.allowed !== false || run.gates.blockers.length < 1)) fail("blocked status/gates/results are inconsistent");
  for (const blocker of run.gates.blockers) {
    if (!blocker || typeof blocker !== "object" || Object.keys(blocker).some((key) => !["gate", "reason"].includes(key)) || typeof blocker.gate !== "string" || typeof blocker.reason !== "string") fail("run gate blocker is malformed");
  }
}

function requireCaseResult(item) {
  if (!item || typeof item !== "object" || Array.isArray(item)) fail("case result must be an object");
  const keys = new Set(["case_id", "status", "reason", "official", "local"]);
  for (const key of Object.keys(item)) if (!keys.has(key)) fail(`case result has closed-schema field ${key}`);
  if (typeof item.case_id !== "string" || !["passed", "failed", "blocked"].includes(item.status)) fail("case result identity/status is invalid");
  if (item.reason !== null && (!REASONS.has(item.reason))) fail("case result reason is not an executor enum");
  if (item.status === "blocked") return;
  for (const target of ["official", "local"]) {
    const value = item[target];
    if (!value || typeof value !== "object" || Array.isArray(value)) fail(`case result ${target} is missing`);
    const allowed = new Set(["execution_error", "cleanup_error", "execute", "cleanup"]);
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`case result ${target} has closed-schema field ${key}`);
    for (const key of ["execution_error", "cleanup_error"]) if (typeof value[key] !== "boolean") fail(`case result ${target}.${key} is invalid`);
    for (const phase of ["execute", "cleanup"]) {
      if (!value[phase] || typeof value[phase].artifact_hash !== "string" || !SHA256.test(value[phase].artifact_hash) || !Number.isInteger(value[phase].request_count) || value[phase].request_count < 0) fail(`case result ${target}.${phase} is invalid`);
    }
  }
}

function blockerRequirements(run) {
  const requirements = [];
  const used = new Set();
  for (const blocker of run.gates.blockers) {
    const rawId = String(blocker.gate).toLowerCase().replace(/[^a-z0-9._-]+/g, "-");
    let id = TOKEN.test(rawId) ? rawId : `gate-${hash(Buffer.from(rawId)).slice(0, 12)}`;
    if (used.has(id)) id = `${id.slice(0, 110)}-${hash(Buffer.from(String(blocker.reason))).slice(0, 12)}`;
    used.add(id);
    requirements.push({ id, status: "blocked", detail: String(blocker.reason) });
  }
  return requirements;
}

function evidenceDocument({ run, matrix, runBytes, matrixBytes, args, inputFiles }) {
  const matrixHash = hash(matrixBytes);
  if (!matrix || matrix.schema_version !== 1 || matrix.sdk !== "@upstash/box@0.6.3" || matrix.source_commit !== "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934" || matrix.summary?.contracts !== 78 || matrix.summary?.public_cases !== 82 || matrix.summary?.uncovered_contracts !== 0) fail("differential matrix is not the pinned 78/82 matrix");
  requireMatrixShape(matrix);
  if (!COMMIT.test(args.commit)) fail("commit must be a full lowercase 40-character SHA");
  const os = process.env.BOXD_DIFF_PLATFORM_OS || (process.platform === "darwin" ? "macos" : process.platform);
  const arch = process.env.BOXD_DIFF_PLATFORM_ARCH || (process.arch === "arm64" ? "aarch64" : process.arch === "x64" ? "x86_64" : process.arch);
  if (!["linux", "macos"].includes(os) || !["x86_64", "aarch64"].includes(arch) || !["none", "kvm", "hvf"].includes(args.virtualization)) fail("platform identity is invalid");
  if (run.status === "passed" && args.virtualization === "none") fail("a passing differential evidence requires native virtualization");
  const raw = runBytes.toString("utf8");
  const findings = scanSecrets(run, raw);
  if (findings.length > 0) fail(`secret scan found ${findings.join(", ")}`);
  const matrixCases = matrix.cases;
  const resultMap = new Map();
  const caseFiles = [];
  for (const result of run.results.cases) {
    requireCaseResult(result);
    if (resultMap.has(result.case_id)) fail(`duplicate case result ${result.case_id}`);
    resultMap.set(result.case_id, result);
  }
  const usedIds = new Set();
  const cases = matrixCases.map((item) => {
    const result = resultMap.get(item.case_id);
    if (run.status === "blocked") {
      return { id: safeCaseId(item.case_id, usedIds), expected: "authenticated official/local differential with successful cleanup", observed: `blocked before request: ${run.gates.blockers.map((blocker) => blocker.reason).join("; ") || "preflight gate"}`, status: "blocked" };
    }
    if (!result) return { id: safeCaseId(item.case_id, usedIds), expected: "normalized official/local response hashes match and cleanup completes", observed: "missing case result", status: run.status === "failed" ? "fail" : "blocked" };
    const status = run.status === "failed" && result.status !== "passed" ? "fail" : result.status === "passed" ? "pass" : result.status === "failed" ? "fail" : "blocked";
    const projection = { case_id: result.case_id, status: result.status, reason: result.reason, official: result.official, local: result.local };
    const id = safeCaseId(item.case_id, usedIds);
    const projectionBytes = jsonBytes(projection);
    const artifactSha256 = hash(projectionBytes);
    caseFiles.push({ path: `cases/${id}.json`, bytes: projectionBytes, sha256: artifactSha256 });
    return { id, expected: "normalized official/local response hashes match and cleanup completes", observed: `${item.case_id}: ${result.status}${result.reason ? ` (${result.reason})` : ""}`, status, artifact_sha256: artifactSha256 };
  });
  const requirements = run.status === "blocked" ? blockerRequirements(run) : [
    { id: "official-target", status: "satisfied", detail: "official target URL and credential gate passed" },
    { id: "local-target", status: "satisfied", detail: "local target URL and credential gate passed" },
    { id: "matrix-coverage", status: "satisfied", detail: "pinned matrix covers 78 contracts and 82 public cases" },
    { id: "runtime-provider", status: "satisfied", detail: "runtime and provider preflight gates passed" },
    { id: "mutation-budget", status: "satisfied", detail: "mutation opt-ins and selected-case budget gate passed" },
    { id: "external-fixtures", status: "satisfied", detail: "disposable Git and dedicated-account gates passed" },
    { id: "cleanup", status: run.results.cleanup_failed_cases === 0 ? "satisfied" : "blocked", detail: run.results.cleanup_failed_cases === 0 ? "all target cleanup steps completed" : "one or more target cleanup steps failed" },
  ];
  const counts = { pass: cases.filter((item) => item.status === "pass").length, fail: cases.filter((item) => item.status === "fail").length, blocked: cases.filter((item) => item.status === "blocked").length };
  const summaryStatus = counts.fail > 0 ? "fail" : counts.blocked > 0 ? "blocked" : "pass";
  const status = run.status === "blocked" || summaryStatus === "blocked" ? "blocked" : summaryStatus;
  const document = {
    schema: "boxd-phase4-evidence-v1",
    suite: "authenticated-differential",
    commit: args.commit,
    platform: { os, arch, virtualization: args.virtualization },
    toolchain: { node: process.version, sdk: matrix.source_commit, runner: process.env.RUNNER_OS || "local" },
    inputs: [
      { name: "differential-matrix", sha256: matrixHash },
      { name: "differential-run", sha256: hash(runBytes) },
      { name: "local-binary", sha256: hash(inputFiles.localBinary) },
      { name: "runtime-bundle", sha256: hash(inputFiles.runtimeBundle) },
      { name: "local-config", sha256: hash(inputFiles.localConfig) },
    ],
    cases,
    artifacts: [{ path: "differential-run.json", sha256: hash(runBytes) }, { path: "differential-matrix.json", sha256: matrixHash }, ...caseFiles.map(({ path, sha256 }) => ({ path, sha256 }))],
    external_requirements: requirements,
    secret_scan: { status: "pass", scanner: "differential-evidence-closed-schema", findings: 0 },
    summary: { status, passed: counts.pass, failed: counts.fail, blocked: counts.blocked, total: cases.length },
  };
  return { document, caseFiles };
}

async function writeExclusive(path, bytes) {
  await mkdir(dirname(path), { recursive: true });
  let handle;
  try { handle = await open(path, "wx", 0o600); } catch (error) { fail(`output cannot be created exclusively: ${error.message}`); }
  try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
}

const args = parseArgs(process.argv);
const inputPaths = [args.run, args.matrix, args.local_binary, args.runtime_bundle, args.local_config];
if (new Set(inputPaths).size !== inputPaths.length) fail("run, matrix, binary, runtime bundle, and config must be distinct files");
const [runBytes, matrixBytes, localBinary, runtimeBundle, localConfig] = await Promise.all([
  readRegular(args.run, "run manifest"),
  readRegular(args.matrix, "differential matrix"),
  readRegular(args.local_binary, "local binary"),
  readRegular(args.runtime_bundle, "runtime bundle"),
  readRegular(args.local_config, "local config"),
]);
let run;
let matrix;
try { run = JSON.parse(runBytes.toString("utf8")); } catch (error) { fail(`run manifest is not JSON: ${error.message}`); }
try { matrix = JSON.parse(matrixBytes.toString("utf8")); } catch (error) { fail(`differential matrix is not JSON: ${error.message}`); }
requireRunShape(run, matrix);
const { document: evidence, caseFiles } = evidenceDocument({ run, matrix, runBytes, matrixBytes, args, inputFiles: { localBinary, runtimeBundle, localConfig } });
const evidenceRaw = jsonBytes(evidence).toString("utf8");
if (scanSecrets(evidence, evidenceRaw).length > 0) fail("generated evidence failed its secret scan");
for (const file of caseFiles) await writeExclusive(`${dirname(args.output)}/${file.path}`, file.bytes);
await writeExclusive(args.output, Buffer.from(evidenceRaw, "utf8"));
process.stdout.write(`${JSON.stringify({ status: evidence.summary.status, output: args.output, cases: evidence.summary.total })}\n`);
process.exitCode = evidence.summary.status === "pass" ? 0 : evidence.summary.status === "blocked" ? 2 : 1;
