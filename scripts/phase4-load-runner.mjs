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
const required = ["BOXD_BASE_URL", "BOXD_API_KEY", "BOXD_BINARY", "BOXD_RUNTIME_BUNDLE", "BOXD_LOAD_ARTIFACT_ROOT", "BOXD_DATA_DIR", "BOXD_DAEMON_PID", "BOXD_RUNTIME"];
const PINNED_SDK_COMMIT = "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934";
const RUNTIMES = new Set(["node", "node-alpine", "python", "python-alpine", "golang", "golang-alpine", "ruby", "ruby-alpine", "rust", "rust-alpine"]);
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
  const ps = requiredCommand("ps", ["-p", pid, "-o", "%cpu=,rss="], "daemon ps").split(/\s+/).filter(Boolean).map(Number);
  if (ps.length !== 2 || ps.some((value) => !Number.isFinite(value) || value < 0)) throw new Error("daemon ps metrics are invalid");
  let fdCount;
  if (process.platform === "linux") fdCount = (await readdir(`/proc/${pid}/fd`)).length;
  else fdCount = requiredCommand("lsof", ["-p", pid], "daemon lsof").split("\n").filter(Boolean).length - 1;
  const disk = Number(requiredCommand("du", ["-sk", process.env.BOXD_DATA_DIR], "data directory du").split(/\s+/)[0]);
  if (!Number.isInteger(fdCount) || fdCount < 0 || !Number.isFinite(disk) || disk < 0) throw new Error("daemon fd or disk metrics are invalid");
  return { cpu_percent: ps[0], rss_bytes: ps[1] * 1024, fd_count: fdCount, disk_bytes: disk * 1024 };
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
  const baseUrl = new URL(process.env.BOXD_BASE_URL);
  if (!["http:", "https:"].includes(baseUrl.protocol) || !["127.0.0.1", "localhost", "[::1]"].includes(baseUrl.hostname) || baseUrl.username || baseUrl.password) throw new Error("BOXD_BASE_URL must identify an explicit credential-free loopback boxd endpoint");
  if (!RUNTIMES.has(process.env.BOXD_RUNTIME)) throw new Error("BOXD_RUNTIME is not in the pinned runtime set");
  const platform = platformIdentity();
  const binary = await boundArtifact(process.env.BOXD_LOAD_ARTIFACT_ROOT, process.env.BOXD_BINARY, "boxd binary");
  const runtime = await boundArtifact(process.env.BOXD_LOAD_ARTIFACT_ROOT, process.env.BOXD_RUNTIME_BUNDLE, "runtime bundle");
  const built = JSON.parse(command(process.execPath, [join(root, "../compat/upstash-box-0.6.3/scripts/build-pinned-sdk.mjs"), "--json"]));
  try {
    if (built.source_commit !== PINNED_SDK_COMMIT) throw new Error("pinned SDK commit mismatch");
    const sdk = await import(built.entry);
    const matrix = [];
    let daemon = await daemonMetrics();
    for (const boxes of counts) for (const scenario of scenarios) {
      const started = Date.now(); const latencies = []; let failures = 0; const handles = [];
      let operationSucceeded = 0; let operationFailures = 0; let cleanupFailures = 0; let deletedCount = 0; const createdIds = [];
      try {
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
            else await box.getPublicURL(Number(process.env.BOXD_LOAD_PREVIEW_PORT || 3000));
            succeeded = true;
          } catch { operationFailures++; } finally { if (succeeded) operationSucceeded++; latencies.push(performance.now() - t); }
        }));
      } finally {
        const cleanup = await Promise.allSettled(handles.map((box) => box.delete()));
        deletedCount = cleanup.filter(({ status }) => status === "fulfilled").length;
        cleanupFailures = cleanup.filter(({ status }) => status === "rejected").length;
      }
      const finished = Date.now();
      daemon = await daemonMetrics();
      const created = handles.length; const createFailures = boxes - created; const attempted = created; const failed = createFailures + operationFailures;
      const metrics = { p50_ms: percentile(latencies, 50), p95_ms: percentile(latencies, 95), p99_ms: percentile(latencies, 99), error_rate: boxes ? failed / boxes : 1, ...daemon };
      matrix.push({ boxes, scenario, metrics, proof: { created_count: created, create_failure_count: createFailures, operation_attempted_count: attempted, operation_succeeded_count: operationSucceeded, operation_failure_count: operationFailures, deleted_count: deletedCount, cleanup_failure_count: cleanupFailures, failure_count: failed, started_at_unix_ms: started, finished_at_unix_ms: finished, created_ids_sha256: idsHash(createdIds) } });
      if (cleanupFailures) process.exitCode = 1;
    }
    const commit = process.env.BOXD_COMMIT_SHA || command("git", ["rev-parse", "HEAD"]);
    if (!/^[0-9a-f]{40}$/.test(commit)) throw new Error("live load requires a full lowercase commit hash");
    const result = { schema: "boxd-phase4-load-v1", mode: "live", commit, platform, pinned_sdk_commit: built.source_commit, artifacts: { binary, runtime_bundle: runtime }, daemon, runs: matrix };
    const output = process.env.BOXD_LOAD_RESULT || join(process.cwd(), "phase4-load-live.json");
    await import("node:fs/promises").then(({ writeFile }) => writeFile(output, JSON.stringify(result, null, 2) + "\n", { flag: "wx", mode: 0o600 }));
    if (matrix.some(({ metrics }) => metrics.error_rate > 0)) process.exitCode = 1;
    process.stdout.write(JSON.stringify({ schema: result.schema, mode: result.mode, status: process.exitCode ? "failed" : "pass", matrix_cells: matrix.length }) + "\n");
  } finally { await cleanupPinned(built.cleanup); }
}

main().catch((error) => { process.stderr.write(`phase4 load blocked: ${error.message}\n`); process.exitCode = 2; });
