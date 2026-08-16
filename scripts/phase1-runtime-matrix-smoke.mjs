#!/usr/bin/env node

import { createHash } from "node:crypto";
import { open, readFile, unlink } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const [mode, runtime, sdkEntry, evidencePath] = process.argv.slice(2);
const supported = new Set([
  "node",
  "python",
  "golang",
  "ruby",
  "rust",
  "node-alpine",
  "python-alpine",
  "golang-alpine",
  "ruby-alpine",
  "rust-alpine",
]);
if (!["lifecycle", "restart"].includes(mode) || !supported.has(runtime) || !sdkEntry || !evidencePath) {
  throw new Error(
    "usage: phase1-runtime-matrix-smoke.mjs lifecycle|restart <runtime> <sdk-entry> <evidence.json>",
  );
}
if (!process.env.UPSTASH_BOX_API_KEY || !process.env.UPSTASH_BOX_BASE_URL) {
  throw new Error("UPSTASH_BOX_API_KEY and UPSTASH_BOX_BASE_URL are required");
}

const sourceCommit = "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934";
const probeFamily = runtime.replace(/-alpine$/, "");
const probes = {
  node: `node -e 'process.stdout.write("runtime-node-ok")'`,
  python: `python3 -c 'import sys; sys.stdout.write("runtime-python-ok")'`,
  golang: `go version >/dev/null && printf runtime-golang-ok`,
  ruby: `ruby -e 'print "runtime-ruby-ok"'`,
  rust: `rustc --version >/dev/null && printf runtime-rust-ok`,
};
const expected = `runtime-${probeFamily}-ok`;
const marker = `matrix-${runtime}-persistent`;
const { Box } = await import(pathToFileURL(sdkEntry).href);
let cleanupIds = [];

function assertProbe(result, label) {
  if (result.exitCode !== 0 || result.stdout.trim() !== expected) {
    throw new Error(`${label} failed for ${runtime}`);
  }
}

async function lifecycle() {
  let box;
  let completed = false;
  try {
    const started = Date.now();
    box = await Box.create({
      runtime,
      name: `phase1-matrix-${runtime}`,
      networkPolicy: { mode: "deny-all" },
      timeout: 300_000,
    });
    cleanupIds = [box.id];
    const createElapsedMs = Date.now() - started;
    assertProbe(await box.exec.command(probes[probeFamily]), "initial language probe");
    await box.files.write({ path: "runtime-matrix.txt", content: marker });
    if ((await box.files.read("runtime-matrix.txt")) !== marker) {
      throw new Error(`file roundtrip failed for ${runtime}`);
    }
    await box.pause();
    if ((await box.getStatus()).status !== "paused") {
      throw new Error(`pause failed for ${runtime}`);
    }
    await box.resume();
    if ((await box.getStatus()).status !== "idle") {
      throw new Error(`resume failed for ${runtime}`);
    }
    assertProbe(await box.exec.command(probes[probeFamily]), "post-resume language probe");
    completed = true;
    return {
      schema: "boxd-phase1-runtime-matrix-lifecycle-v1",
      source_commit: sourceCommit,
      runtime,
      box_id: box.id,
      create_elapsed_ms: createElapsedMs,
      language_probe: true,
      file_roundtrip: true,
      pause_resume: true,
      status: "idle",
    };
  } finally {
    if (!completed && box) await Box.delete({ boxIds: [box.id] }).catch(() => {});
  }
}

async function restart() {
  const priorPath = process.env.BOXD_RUNTIME_MATRIX_LIFECYCLE_EVIDENCE;
  if (!priorPath) throw new Error("BOXD_RUNTIME_MATRIX_LIFECYCLE_EVIDENCE is required");
  const priorBytes = await readFile(priorPath);
  const prior = JSON.parse(priorBytes.toString("utf8"));
  if (
    prior.schema !== "boxd-phase1-runtime-matrix-lifecycle-v1" ||
    prior.runtime !== runtime ||
    typeof prior.box_id !== "string"
  ) {
    throw new Error(`invalid lifecycle evidence for ${runtime}`);
  }
  cleanupIds = [prior.box_id];
  const box = await Box.get(prior.box_id);
  try {
    if ((await box.getStatus()).status !== "idle") {
      throw new Error(`reconciled status is not idle for ${runtime}`);
    }
    if ((await box.files.read("runtime-matrix.txt")) !== marker) {
      throw new Error(`persisted file failed for ${runtime}`);
    }
    assertProbe(await box.exec.command(probes[probeFamily]), "post-restart language probe");
    await Box.delete({ boxIds: [prior.box_id] });
    cleanupIds = [];
    return {
      schema: "boxd-phase1-runtime-matrix-restart-v1",
      source_commit: sourceCommit,
      runtime,
      box_id: prior.box_id,
      lifecycle_evidence_sha256: createHash("sha256").update(priorBytes).digest("hex"),
      daemon_restart_reconcile: true,
      persisted_file: true,
      language_probe: true,
      delete: true,
      status: "deleted",
    };
  } finally {
    if (cleanupIds.length > 0) await Box.delete({ boxIds: cleanupIds }).catch(() => {});
  }
}

const output = await open(evidencePath, "wx", 0o600);
let committed = false;
try {
  const evidence = mode === "lifecycle" ? await lifecycle() : await restart();
  await output.writeFile(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  await output.sync();
  committed = true;
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} finally {
  await output.close();
  if (!committed) {
    if (cleanupIds.length > 0) await Box.delete({ boxIds: cleanupIds }).catch(() => {});
    await unlink(evidencePath).catch(() => {});
  }
}
