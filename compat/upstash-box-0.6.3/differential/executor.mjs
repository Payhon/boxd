import { AsyncLocalStorage } from "node:async_hooks";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { differentialAdapters } from "./adapters.mjs";
import { evaluateDifferentialGates, redactEvidence, redactUrl } from "./gates.mjs";
import { normalizeBinary, normalizeHeaders, normalizeJson, normalizeSse } from "./normalizers.mjs";

const captureStorage = new AsyncLocalStorage();
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const canonical = (value) => JSON.stringify(value);
const PINNED_SDK_COMMIT = "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934";

async function loadPinnedSdk() {
  const output = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL("../scripts/build-pinned-sdk.mjs", import.meta.url)), "--json"], {
      cwd: fileURLToPath(new URL("../", import.meta.url)),
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("close", (code) => code === 0 ? resolve(stdout) : reject(new Error(stderr || `SDK build exited ${code}`)));
  });
  const built = JSON.parse(output);
  try {
    if (built.source_commit !== PINNED_SDK_COMMIT) throw new Error("pinned SDK commit mismatch");
    return { sdk: await import(built.entry), cleanup: built.cleanup, sourceCommit: built.source_commit };
  } catch (error) {
    await cleanupPinned(built.cleanup);
    throw error;
  }
}

async function cleanupPinned(cleanup) {
  if (!cleanup?.dir || sha256(cleanup.dir) !== cleanup.token) throw new Error("invalid pinned SDK cleanup token");
  const metadata = await lstat(cleanup.dir);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error("unsafe pinned SDK cleanup target");
  if (!basename(cleanup.dir).startsWith("boxd-pinned-sdk-") || dirname(await realpath(cleanup.dir)) !== await realpath(tmpdir())) {
    throw new Error("pinned SDK cleanup escaped the temporary directory");
  }
  await rm(cleanup.dir, { recursive: true, force: true });
}

async function normalizedCapture(response) {
  const clone = response.clone();
  const bytes = new Uint8Array(await clone.arrayBuffer());
  const contentType = clone.headers.get("content-type") ?? "";
  let body;
  if (/text\/event-stream/i.test(contentType)) body = normalizeSse(bytes);
  else if (/json/i.test(contentType) && bytes.length > 0) {
    try {
      body = normalizeJson(JSON.parse(new TextDecoder().decode(bytes)));
    } catch {
      body = { kind: "invalid_json", sha256: sha256(bytes), bytes: bytes.length };
    }
  } else if (captureStorage.getStore()?.adapter?.binaryBodyKind === "media") body = normalizeBinary(bytes, contentType);
  else body = { kind: "bytes", sha256: sha256(bytes), bytes: bytes.length };
  return { status: clone.status, headers: normalizeHeaders(clone.headers), body };
}

function installCaptureFetch(config) {
  const upstreamFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const context = captureStorage.getStore();
    if (!context) return upstreamFetch(input, init);
    const timeout = AbortSignal.timeout(config.requestTimeoutMs);
    const signals = [init.signal, context.signal, timeout].filter(Boolean);
    const response = await upstreamFetch(input, { ...init, signal: AbortSignal.any(signals) });
    context.records.push({ phase: context.phase, response: await normalizedCapture(response) });
    return response;
  };
  return () => {
    globalThis.fetch = upstreamFetch;
  };
}

async function withDeadline(promise, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("global timeout")), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function artifact(records, phase) {
  const selected = records.filter((record) => record.phase === phase).map((record) => record.response);
  return { artifact_hash: sha256(canonical(selected)), request_count: selected.length };
}

async function executeTarget(adapter, sdk, target, config, runSignal) {
  const execution = new AbortController();
  const context = { records: [], phase: "execute", signal: AbortSignal.any([runSignal, execution.signal]), adapter };
  const state = await adapter.prepare({ target, config });
  let executionError = false;
  let cleanupError = false;
  await captureStorage.run(context, async () => {
    try {
      await withDeadline(adapter.execute({ sdk, target, state, config }), config.globalTimeoutMs);
    } catch {
      executionError = true;
      execution.abort(new Error("differential target execution ended"));
    } finally {
      if (adapter.cleanup) {
        context.phase = "cleanup";
        context.signal = AbortSignal.timeout(Math.max(config.requestTimeoutMs * 2, 1000));
        try {
          await withDeadline(adapter.cleanup({ sdk, target, state, config }), Math.max(config.requestTimeoutMs * 2, 1000));
        } catch {
          cleanupError = true;
        }
      }
    }
  });
  return {
    execution_error: executionError,
    cleanup_error: cleanupError,
    execute: artifact(context.records, "execute"),
    cleanup: artifact(context.records, "cleanup"),
  };
}

async function mapLimit(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await worker(items[index]);
    }
  }));
  return results;
}

function safeTargetUrl(value) {
  try {
    return value ? redactUrl(value) : null;
  } catch {
    return null;
  }
}

function emptyResults(blockedCases) {
  return { executed_cases: 0, passed_cases: 0, failed_cases: 0, blocked_cases: blockedCases, cleanup_failed_cases: 0, evidence_redacted: true, cases: [] };
}

export async function runDifferential({ matrix, selectedCases, config, sdkLoader = loadPinnedSdk }) {
  const selectedIds = new Set(selectedCases.map((item) => item.case_id));
  const selectionContracts = matrix.contracts.filter((contract) => contract.case_ids.some((caseId) => selectedIds.has(caseId)));
  const base = {
    schema_version: 1,
    sdk: matrix.sdk,
    mode: "authenticated-differential",
    selection: { contracts: selectionContracts.length, cases: selectedCases.length },
    targets: { official: safeTargetUrl(config.official.baseUrl), local: safeTargetUrl(config.local.baseUrl) },
    limits: { request_timeout_ms: config.requestTimeoutMs, global_timeout_ms: config.globalTimeoutMs, concurrency: config.concurrency, budget_usd: config.budgetUsd },
    executor: { adapter_cases: differentialAdapters.size, blocked_without_adapter: matrix.cases.length - differentialAdapters.size },
  };
  const gateCases = selectedCases.map((item) => {
    const adapter = differentialAdapters.get(item.case_id);
    if (!adapter) return item;
    return {
      ...item,
      setup: adapter.requiresRuntime ? "Box.create" : item.setup,
      risk: { ...item.risk, may_incur_cost: item.risk.may_incur_cost || adapter.mayIncurCost === true },
    };
  });
  const gates = evaluateDifferentialGates(gateCases, config);
  if (!gates.allowed) return redactEvidence({ ...base, status: "blocked", gates, results: emptyResults(selectedCases.length) });

  const runnable = selectedCases.filter((item) => differentialAdapters.has(item.case_id));
  const missing = selectedCases.filter((item) => !differentialAdapters.has(item.case_id));
  if (runnable.length === 0) {
    const adapterGates = { allowed: false, blockers: [{ gate: "adapter", reason: "no selected case has an executable adapter" }] };
    return redactEvidence({ ...base, status: "blocked", gates: adapterGates, results: emptyResults(selectedCases.length) });
  }

  const built = await sdkLoader();
  const restoreFetch = installCaptureFetch(config);
  const runSignal = AbortSignal.timeout(config.globalTimeoutMs);
  let executed;
  try {
    executed = await mapLimit(runnable, config.concurrency, async (item) => {
      const adapter = differentialAdapters.get(item.case_id);
      const [official, local] = await Promise.all([
        executeTarget(adapter, built.sdk, config.official, config, runSignal),
        executeTarget(adapter, built.sdk, config.local, config, runSignal),
      ]);
      const cleanupFailed = official.cleanup_error || local.cleanup_error;
      const executionFailed = official.execution_error || local.execution_error;
      const equal = official.execute.artifact_hash === local.execute.artifact_hash;
      const status = cleanupFailed || executionFailed || !equal ? "failed" : "passed";
      const reason = cleanupFailed ? "cleanup_failed" : executionFailed ? "target_execution_failed" : !equal ? "artifact_mismatch" : null;
      return { case_id: item.case_id, status, reason, official, local };
    });
  } finally {
    restoreFetch();
    await cleanupPinned(built.cleanup);
  }

  const blocked = missing.map((item) => ({ case_id: item.case_id, status: "blocked", reason: "adapter_missing" }));
  const cases = [...executed, ...blocked].sort((left, right) => left.case_id.localeCompare(right.case_id));
  const passedCases = executed.filter((item) => item.status === "passed").length;
  const failedCases = executed.filter((item) => item.status === "failed").length;
  const cleanupFailedCases = executed.filter((item) => item.reason === "cleanup_failed").length;
  const status = failedCases > 0 ? "failed" : blocked.length > 0 ? "blocked" : "passed";
  return redactEvidence({
    ...base,
    status,
    gates: { allowed: true, blockers: [] },
    results: {
      executed_cases: executed.length,
      passed_cases: passedCases,
      failed_cases: failedCases,
      blocked_cases: blocked.length,
      cleanup_failed_cases: cleanupFailedCases,
      evidence_redacted: true,
      cases,
    },
  });
}
