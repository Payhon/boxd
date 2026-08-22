#!/usr/bin/env node
// Live Phase 4 load collector. It intentionally requires an explicitly
// configured local boxd and native virtualization; no fixture is promoted.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync } from "node:fs";
import { readFile, readdir, lstat, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));
const counts = [1, 4, 16, 64];
const scenarios = ["exec", "sse", "browser", "preview"];
const required = ["BOXD_BASE_URL", "BOXD_API_KEY", "BOXD_BINARY", "BOXD_RUNTIME_BUNDLE", "BOXD_LOAD_ARTIFACT_ROOT", "BOXD_DATA_DIR", "BOXD_DAEMON_PID", "BOXD_RUNTIME", "BOXD_LOAD_CONFIG", "BOXD_LOAD_PROFILE"];
const PINNED_SDK_COMMIT = "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934";
const RUNTIMES = new Set(["node", "node-alpine", "python", "python-alpine", "golang", "golang-alpine", "ruby", "ruby-alpine", "rust", "rust-alpine"]);
const MAX_MATRIX_BOXES = 64;
const DEFAULT_SAMPLE_INTERVAL_MS = 250;
const PROFILE_REQUIREMENTS = Object.freeze({
  "phase4-1": Object.freeze({ max_boxes: 1, max_running_boxes: 1, max_total_memory_mib: 4096, max_total_vcpus: 2, default_disk_gib: 20, tenant_max_boxes: 1, tenant_max_disk_gib: 20, tenant_max_concurrent_runs: 1 }),
  "phase4-4": Object.freeze({ max_boxes: 4, max_running_boxes: 4, max_total_memory_mib: 16384, max_total_vcpus: 8, default_disk_gib: 20, tenant_max_boxes: 4, tenant_max_disk_gib: 80, tenant_max_concurrent_runs: 4 }),
  "phase4-16": Object.freeze({ max_boxes: 16, max_running_boxes: 16, max_total_memory_mib: 65536, max_total_vcpus: 32, default_disk_gib: 20, tenant_max_boxes: 16, tenant_max_disk_gib: 320, tenant_max_concurrent_runs: 16 }),
  "phase4-64": Object.freeze({ max_boxes: 64, max_running_boxes: 64, max_total_memory_mib: 262144, max_total_vcpus: 128, default_disk_gib: 20, tenant_max_boxes: 64, tenant_max_disk_gib: 1280, tenant_max_concurrent_runs: 64 }),
});
const sha256File = async (path) => createHash("sha256").update(await readFile(path)).digest("hex");
const command = (file, args) => { try { return execFileSync(file, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); } catch { return ""; } };
const requiredCommand = (file, args, label) => {
  try { return execFileSync(file, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim(); }
  catch { throw new Error(`${label} command failed`); }
};
const percentile = (values, p) => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)] ?? 0; };
const consume = async (stream) => { for await (const _chunk of stream) {} };
const resourceId = (box) => box?.id ?? box?.boxId ?? box?.box?.id;
const idsHash = (ids) => createHash("sha256").update(JSON.stringify([...ids].sort())).digest("hex");

const resourceNames = ["cpu_percent", "rss_bytes", "fd_count", "disk_bytes"];

function finiteNonNegative(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) throw new Error(`${label} must be a finite non-negative number`);
  return value;
}

export function resourceCeiling(samples) {
  if (!Array.isArray(samples) || samples.length === 0) throw new Error("resource sampler produced no samples");
  const ceiling = Object.fromEntries(resourceNames.map((name) => [name, 0]));
  for (const sample of samples) {
    if (!sample || typeof sample !== "object") throw new Error("resource sample must be an object");
    for (const name of resourceNames) ceiling[name] = Math.max(ceiling[name], finiteNonNegative(sample[name], `sample.${name}`));
  }
  return ceiling;
}

export function validateLoadProfile(name, configuredResources, maxBoxes = MAX_MATRIX_BOXES, runtime = "node") {
  const requirements = PROFILE_REQUIREMENTS[name];
  if (!requirements) throw new Error(`BOXD_LOAD_PROFILE must be one of ${Object.keys(PROFILE_REQUIREMENTS).join(", ")}`);
  if (requirements.max_boxes < maxBoxes) throw new Error(`load profile ${name} cannot prove the ${maxBoxes}-Box matrix`);
  if (name === "phase4-64" && runtime !== "node") throw new Error("phase4-64 load profile requires BOXD_RUNTIME=node");
  if (!configuredResources || typeof configuredResources !== "object") throw new Error("configured load resources are required");
  for (const key of ["max_running_boxes", "max_total_memory_mib", "max_total_vcpus", "default_disk_gib", "tenant_max_boxes", "tenant_max_disk_gib", "tenant_max_concurrent_runs"]) {
    const value = configuredResources[key];
    if (!Number.isInteger(value) || value < requirements[key]) throw new Error(`load config ${key} is below ${name} requirement (${requirements[key]})`);
  }
  const resourceRequirements = Object.fromEntries(Object.entries(requirements).filter(([key]) => key !== "max_boxes"));
  return { name, max_boxes: requirements.max_boxes, runtime, requirements: resourceRequirements, configured: configuredResources, runtime_asserted: true };
}

async function regularFile(path, label) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error(`${label} must be a unique regular non-symlink file`);
}

async function configuredResources(path) {
  await regularFile(path, "BOXD_LOAD_CONFIG");
  const script = "import json,sys,tomllib; d=tomllib.load(open(sys.argv[1], 'rb')); r=d.get('resources', {}); q=d.get('quotas', {}); print(json.dumps({k:r.get(k) for k in ('max_running_boxes','max_total_memory_mib','max_total_vcpus','default_disk_gib')} | {k:q.get(k) for k in ('tenant_max_boxes','tenant_max_disk_gib','tenant_max_concurrent_runs')}))";
  const value = JSON.parse(requiredCommand("python3", ["-c", script, path], "load config resource parser"));
  for (const key of ["max_running_boxes", "max_total_memory_mib", "max_total_vcpus", "default_disk_gib", "tenant_max_boxes", "tenant_max_disk_gib", "tenant_max_concurrent_runs"]) {
    if (!Number.isInteger(value[key]) || value[key] < 0) throw new Error(`BOXD_LOAD_CONFIG resources.${key} must be a non-negative integer`);
  }
  return value;
}

export async function fetchPreview(publicUrl) {
  if (!publicUrl || typeof publicUrl.url !== "string") throw new Error("preview response did not contain a URL");
  const target = new URL(publicUrl.url);
  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password) throw new Error("preview URL must be credential-free HTTP(S)");
  if (!["127.0.0.1", "localhost", "[::1]"].includes(target.hostname)) throw new Error("preview URL must resolve to the local loopback endpoint");
  const response = await fetch(target, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`preview fetch returned HTTP ${response.status}`);
  const body = await response.arrayBuffer();
  return body.byteLength;
}

function virtualization() {
  if (process.platform === "darwin") return command("sysctl", ["-n", "kern.hv_support"]) === "1" ? "hvf" : "none";
  if (process.platform === "linux") {
    try { accessSync("/dev/kvm"); return "kvm"; } catch { return "none"; }
  }
  return "none";
}

function platformIdentity() {
  const virtualizationType = virtualization();
  const os = process.platform === "darwin" ? "macos" : process.platform;
  const arch = process.platform === "darwin" ? "aarch64" : (process.arch === "arm64" ? "aarch64" : process.arch === "x64" ? "x86_64" : process.arch);
  if (!((os === "linux" && ["x86_64", "aarch64"].includes(arch) && virtualizationType === "kvm") || (os === "macos" && arch === "aarch64" && virtualizationType === "hvf"))) throw new Error("live load requires Linux x86_64/aarch64 KVM or macOS aarch64 HVF");
  return { os, arch, virtualization: virtualizationType };
}

async function daemonMetrics() {
  const pid = process.env.BOXD_DAEMON_PID;
  if (!/^[0-9]+$/.test(pid)) throw new Error("BOXD_DAEMON_PID must contain only decimal digits");
  return daemonMetricsFor(pid, process.env.BOXD_DATA_DIR);
}

export class ResourceSampler {
  constructor(pid, dataDir, intervalMs = DEFAULT_SAMPLE_INTERVAL_MS, sampleReader = daemonMetricsFor) {
    if (!/^[0-9]+$/.test(pid ?? "")) throw new Error("BOXD_DAEMON_PID must contain only decimal digits");
    if (!Number.isInteger(intervalMs) || intervalMs < 50 || intervalMs > 10_000) throw new Error("resource sampling interval must be an integer between 50 and 10000 ms");
    this.pid = pid;
    this.dataDir = dataDir;
    this.intervalMs = intervalMs;
    this.sampleReader = sampleReader;
    this.samples = [];
    this.timer = undefined;
    this.pending = Promise.resolve();
    this.error = undefined;
  }

  async sample() {
    const value = await this.sampleReader(this.pid, this.dataDir);
    this.samples.push(value);
    return value;
  }

  start() {
    if (this.timer) throw new Error("resource sampler already started");
    this.pending = this.sample().catch((error) => { this.error = error; });
    this.timer = setInterval(() => {
      this.pending = this.pending.then(() => this.sample()).catch((error) => { this.error ??= error; });
    }, this.intervalMs);
    return this.pending;
  }

  async stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.pending;
    if (this.error) throw this.error;
    const ceiling = resourceCeiling(this.samples);
    return { interval_ms: this.intervalMs, sample_count: this.samples.length, ceiling };
  }
}

export function aggregateProcessRows(rows, rootPid) {
  const root = Number(rootPid);
  if (!Number.isInteger(root) || root < 1) throw new Error("root process id is invalid");
  const parsed = rows.map((row) => {
    const match = String(row).trim().match(/^(\d+)\s+(\d+)\s+([0-9.]+)\s+(\d+)$/);
    if (!match) throw new Error("process-table metrics are invalid");
    return { pid: Number(match[1]), ppid: Number(match[2]), cpu: Number(match[3]), rssKib: Number(match[4]) };
  });
  if (!parsed.some(({ pid }) => pid === root)) throw new Error("boxd daemon is absent from the process table");
  const selected = new Set([root]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const process of parsed) {
      if (!selected.has(process.pid) && selected.has(process.ppid)) {
        selected.add(process.pid);
        changed = true;
      }
    }
  }
  const processes = parsed.filter(({ pid }) => selected.has(pid));
  return {
    pids: processes.map(({ pid }) => pid),
    cpu_percent: processes.reduce((total, process) => total + process.cpu, 0),
    rss_bytes: processes.reduce((total, process) => total + process.rssKib * 1024, 0),
  };
}

async function daemonMetricsFor(pid, dataDir) {
  const rows = requiredCommand("ps", ["-axo", "pid=,ppid=,%cpu=,rss="], "boxd process-tree ps").split("\n").filter((line) => line.trim());
  const tree = aggregateProcessRows(rows, pid);
  let fdCount = 0;
  for (const processPid of tree.pids) {
    try {
      if (process.platform === "linux") fdCount += (await readdir(`/proc/${processPid}/fd`)).length;
      else fdCount += requiredCommand("lsof", ["-n", "-P", "-p", String(processPid)], "boxd process-tree lsof").split("\n").filter(Boolean).length - 1;
    } catch (error) {
      if (processPid === Number(pid)) throw error;
      // A short-lived owned child may exit after the process-table snapshot.
    }
  }
  const disk = Number(requiredCommand("du", ["-sk", dataDir], "data directory du").split(/\s+/)[0]);
  if (!Number.isInteger(fdCount) || fdCount < 0 || !Number.isFinite(disk) || disk < 0) throw new Error("daemon fd or disk metrics are invalid");
  return { cpu_percent: tree.cpu_percent, rss_bytes: tree.rss_bytes, fd_count: fdCount, disk_bytes: disk * 1024 };
}

async function cleanupPinned(cleanup) {
  if (!cleanup?.dir || createHash("sha256").update(cleanup.dir).digest("hex") !== cleanup.token) throw new Error("invalid pinned SDK cleanup token");
  const info = await lstat(cleanup.dir); const resolved = await realpath(cleanup.dir); const temp = await realpath(tmpdir());
  if (!info.isDirectory() || info.isSymbolicLink() || !resolved.startsWith(`${temp}/`) || !resolved.split("/").at(-1).startsWith("boxd-pinned-sdk-")) throw new Error("unsafe pinned SDK cleanup target");
  await rm(resolved, { recursive: true, force: true });
}

async function boundArtifact(artifactRoot, inputPath, label) {
  const rootPath = resolve(artifactRoot); const rootInfo = await lstat(rootPath);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error("BOXD_LOAD_ARTIFACT_ROOT must be a real directory");
  const inputAbsolute = resolve(inputPath); const lexicalRelative = relative(rootPath, inputAbsolute);
  if (!lexicalRelative || lexicalRelative === ".." || lexicalRelative.startsWith("../") || isAbsolute(lexicalRelative)) throw new Error(`${label} must be below BOXD_LOAD_ARTIFACT_ROOT`);
  let current = rootPath;
  for (const component of lexicalRelative.split(/[\\/]/)) {
    current = join(current, component); const info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error(`${label} path may not traverse symlinks`);
  }
  const info = await lstat(current);
  if (!info.isFile() || info.nlink !== 1) throw new Error(`${label} must be a single-link regular file`);
  const rootResolved = await realpath(rootPath); const resolved = await realpath(current); const normalized = relative(rootResolved, resolved);
  if (!normalized || normalized === ".." || normalized.startsWith("../") || isAbsolute(normalized)) throw new Error(`${label} escaped BOXD_LOAD_ARTIFACT_ROOT`);
  return { path: normalized.split(/[\\/]/).join("/"), sha256: await sha256File(resolved) };
}

async function main() {
  if (process.env.BOXD_LOAD_MODE !== "live") throw new Error("live mode requires BOXD_LOAD_MODE=live; fixture mode is blocked");
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length) throw new Error(`missing live load configuration: ${missing.join(",")}`);
  const resourceOverrides = Object.keys(process.env).filter((key) => /^BOXD__RESOURCES__/.test(key));
  if (resourceOverrides.length) throw new Error("resource environment overrides are forbidden; use the hash-bound BOXD_LOAD_CONFIG profile");
  const baseUrl = new URL(process.env.BOXD_BASE_URL);
  if (!["http:", "https:"].includes(baseUrl.protocol) || !["127.0.0.1", "localhost", "[::1]"].includes(baseUrl.hostname) || baseUrl.username || baseUrl.password) throw new Error("BOXD_BASE_URL must identify an explicit credential-free loopback boxd endpoint");
  if (!RUNTIMES.has(process.env.BOXD_RUNTIME)) throw new Error("BOXD_RUNTIME is not in the pinned runtime set");
  const sampleIntervalMs = Number(process.env.BOXD_LOAD_SAMPLE_INTERVAL_MS || DEFAULT_SAMPLE_INTERVAL_MS);
  if (!Number.isInteger(sampleIntervalMs) || sampleIntervalMs < 50 || sampleIntervalMs > 10_000) throw new Error("BOXD_LOAD_SAMPLE_INTERVAL_MS must be an integer between 50 and 10000 ms");
  const previewPort = Number(process.env.BOXD_LOAD_PREVIEW_PORT || 3000);
  if (!Number.isInteger(previewPort) || previewPort < 1 || previewPort > 65_535) throw new Error("BOXD_LOAD_PREVIEW_PORT must be an integer between 1 and 65535");
  const platform = platformIdentity();
  const binary = await boundArtifact(process.env.BOXD_LOAD_ARTIFACT_ROOT, process.env.BOXD_BINARY, "boxd binary");
  const runtime = await boundArtifact(process.env.BOXD_LOAD_ARTIFACT_ROOT, process.env.BOXD_RUNTIME_BUNDLE, "runtime bundle");
  const config = await boundArtifact(process.env.BOXD_LOAD_ARTIFACT_ROOT, process.env.BOXD_LOAD_CONFIG, "load config");
  const configured = await configuredResources(process.env.BOXD_LOAD_CONFIG);
  const profile = validateLoadProfile(process.env.BOXD_LOAD_PROFILE, configured, MAX_MATRIX_BOXES, process.env.BOXD_RUNTIME);
  const built = JSON.parse(command(process.execPath, [join(root, "../compat/upstash-box-0.6.3/scripts/build-pinned-sdk.mjs"), "--json"]));
  try {
    if (built.source_commit !== PINNED_SDK_COMMIT) throw new Error("pinned SDK commit mismatch");
    const sdk = await import(built.entry);
    const matrix = [];
    const daemonSamples = [];
    let daemonSampleCount = 1;
    let daemon = await daemonMetrics();
    daemonSamples.push(daemon);
    for (const boxes of counts) for (const scenario of scenarios) {
      const started = Date.now(); const latencies = []; const handles = [];
      let operationSucceeded = 0; let operationFailures = 0; let cleanupFailures = 0; let deletedCount = 0; const createdIds = [];
      let previewFetchCount = 0; let previewBytesConsumed = 0; const previewResponseBytes = []; let sampling;
      const sampler = new ResourceSampler(process.env.BOXD_DAEMON_PID, process.env.BOXD_DATA_DIR, sampleIntervalMs);
      try {
        await sampler.start();
        try {
          for (let i = 0; i < boxes; i++) {
            const box = await sdk.Box.create({ apiKey: process.env.BOXD_API_KEY, baseUrl: process.env.BOXD_BASE_URL, name: `boxd-phase4-load-${boxes}-${scenario}-${i}`, keepAlive: true, browser: scenario === "browser", runtime: process.env.BOXD_RUNTIME });
            const id = resourceId(box); if (typeof id !== "string" || !id) throw new Error("created Box did not expose an id");
            handles.push(box); createdIds.push(id);
          }
        } catch { /* remaining create attempts are recorded as create failures */ }
        await Promise.all(handles.map(async (box) => {
          const t = performance.now();
          let succeeded = false;
          try {
            if (scenario === "exec") await box.exec.command("printf phase4-load");
            else if (scenario === "sse") await consume(await box.exec.stream("printf phase4-load"));
            else if (scenario === "browser") await box.browser.tab.create("data:text/html,<!doctype html><title>boxd-load</title>");
            else {
              const boxKey = createHash("sha256").update(resourceId(box)).digest("hex").slice(0, 16);
              const previewPidPath = `/tmp/boxd-phase4-preview-${boxKey}.pid`;
              const previewLogPath = `/tmp/boxd-phase4-preview-${boxKey}.log`;
              const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
              const serverCode = `const http=require("http");http.createServer((_req,res)=>{res.writeHead(200,{"content-type":"text/plain"});res.end("boxd-phase4-preview-ok")}).listen(${previewPort},"0.0.0.0")`;
              const startServer = await box.exec.command(`rm -f ${shellQuote(previewPidPath)} ${shellQuote(previewLogPath)}; nohup node -e ${shellQuote(serverCode)} >${shellQuote(previewLogPath)} 2>&1 </dev/null & echo $! >${shellQuote(previewPidPath)}; sleep 1; kill -0 "$(cat ${shellQuote(previewPidPath)})"`);
              if (startServer.exitCode !== 0) throw new Error("guest preview HTTP server failed to start");
              const publicUrl = await box.getPublicURL(previewPort);
              const bytes = await fetchPreview(publicUrl);
              if (!Number.isInteger(bytes) || bytes < 1) throw new Error("preview response body was empty");
              await box.deletePublicURL(previewPort);
              previewBytesConsumed += bytes;
              previewResponseBytes.push(bytes);
              previewFetchCount++;
            }
            succeeded = true;
          } catch { operationFailures++; } finally { if (succeeded) operationSucceeded++; latencies.push(performance.now() - t); }
        }));
      } finally {
        const cleanup = await Promise.allSettled(handles.map((box) => box.delete()));
        deletedCount = cleanup.filter(({ status }) => status === "fulfilled").length;
        cleanupFailures = cleanup.filter(({ status }) => status === "rejected").length;
        sampling = await sampler.stop();
      }
      const finished = Date.now();
      daemon = sampling.ceiling;
      daemonSamples.push(daemon);
      daemonSampleCount += sampling.sample_count;
      const created = handles.length; const createFailures = boxes - created; const attempted = created; const failed = createFailures + operationFailures;
      const metrics = { p50_ms: percentile(latencies, 50), p95_ms: percentile(latencies, 95), p99_ms: percentile(latencies, 99), error_rate: boxes ? failed / boxes : 1 };
      matrix.push({ boxes, scenario, metrics, resource_sampling: sampling, proof: { created_count: created, create_failure_count: createFailures, operation_attempted_count: attempted, operation_succeeded_count: operationSucceeded, operation_failure_count: operationFailures, deleted_count: deletedCount, cleanup_failure_count: cleanupFailures, failure_count: failed, preview_fetch_count: previewFetchCount, preview_bytes_consumed: previewBytesConsumed, preview_response_bytes: previewResponseBytes, resource_sample_count: sampling.sample_count, resource_sampling_error_count: 0, started_at_unix_ms: started, finished_at_unix_ms: finished, created_ids_sha256: idsHash(createdIds) } });
      if (cleanupFailures) process.exitCode = 1;
    }
    const commit = process.env.BOXD_COMMIT_SHA || command("git", ["rev-parse", "HEAD"]);
    if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("live load requires a full lowercase commit hash");
    const daemonCeiling = resourceCeiling(daemonSamples);
    const result = { schema: "boxd-phase4-load-v1", mode: "live", commit, platform, pinned_sdk_commit: built.source_commit, profile, artifacts: { binary, runtime_bundle: runtime, config }, daemon: daemonCeiling, daemon_sampling: { interval_ms: sampleIntervalMs, sample_count: daemonSampleCount }, runs: matrix };
    const output = process.env.BOXD_LOAD_RESULT || join(process.cwd(), "phase4-load-live.json");
    await import("node:fs/promises").then(({ writeFile }) => writeFile(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx", mode: 0o600 }));
    if (matrix.some(({ metrics }) => metrics.error_rate > 0)) process.exitCode = 1;
    process.stdout.write(JSON.stringify({ schema: result.schema, mode: result.mode, status: process.exitCode ? "failed" : "pass", matrix_cells: matrix.length }) + "\n");
  } finally { await cleanupPinned(built.cleanup); }
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch((error) => { process.stderr.write(`phase4 load blocked: ${error.message}\n`); process.exitCode = 2; });
}
