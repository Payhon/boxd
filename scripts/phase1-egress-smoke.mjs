#!/usr/bin/env node

import { createHash } from "node:crypto";
import { open, readFile, unlink } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const [mode, sdkEntry, evidencePath] = process.argv.slice(2);
if (!["lifecycle", "restart"].includes(mode) || !sdkEntry || !evidencePath) {
  throw new Error(
    "usage: phase1-egress-smoke.mjs lifecycle|restart SDK_ENTRY EVIDENCE_JSON",
  );
}
if (!process.env.UPSTASH_BOX_API_KEY || !process.env.UPSTASH_BOX_BASE_URL) {
  throw new Error(
    "UPSTASH_BOX_API_KEY and UPSTASH_BOX_BASE_URL are required",
  );
}

const sourceCommit = "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934";
const { Box } = await import(
  sdkEntry.startsWith("file:") ? sdkEntry : pathToFileURL(sdkEntry).href,
);

function shellQuote(value) {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function nodeCommand(source) {
  return `node -e ${shellQuote(source)}`;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function assertRun(run, label) {
  if (run.exitCode !== 0) {
    throw new Error(`${label} failed: ${run.stderr || run.stdout}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(run.stdout.trim());
  } catch {
    throw new Error(`${label} returned non-JSON output`);
  }
  return parsed;
}

const restrictedProbe = String.raw`
const dns = require("node:dns").promises;
(async () => {
  const addresses = await dns.resolve4("example.com");
  const http = await fetch("http://example.com/", { signal: AbortSignal.timeout(10000) });
  const https = await fetch("https://example.com/", { signal: AbortSignal.timeout(10000) });
  const blocked = async (url) => {
    try {
      await fetch(url, { signal: AbortSignal.timeout(2500) });
      return false;
    } catch {
      return true;
    }
  };
  const net = require("node:net");
  const blockedPort = await new Promise((resolve) => {
    const socket = net.connect({ host: "1.1.1.1", port: 22 });
    const timer = setTimeout(() => { socket.destroy(); resolve(true); }, 2500);
    socket.once("connect", () => { clearTimeout(timer); socket.destroy(); resolve(false); });
    socket.once("error", () => { clearTimeout(timer); resolve(true); });
  });
  const result = {
    dns_public: addresses.length > 0 && addresses.every((value) => !/^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(value)),
    http_80: http.ok,
    https_443: https.ok,
    metadata_blocked: await blocked("http://169.254.169.254/latest/meta-data/"),
    loopback_blocked: await blocked("http://127.0.0.1:7331/health/live"),
    private_blocked: await blocked("http://10.0.0.1/"),
    non_web_port_blocked: blockedPort,
  };
  console.log(JSON.stringify(result));
})().catch((error) => { console.error(error); process.exit(1); });
`;

const denyAllProbe = String.raw`
(async () => {
  let blocked = false;
  try {
    await fetch("https://example.com/", { signal: AbortSignal.timeout(2500) });
  } catch {
    blocked = true;
  }
  console.log(JSON.stringify({ public_https_blocked: blocked }));
})().catch((error) => { console.error(error); process.exit(1); });
`;

function assertRestricted(result) {
  for (const [name, value] of Object.entries(result)) {
    if (value !== true) throw new Error(`restricted egress assertion failed: ${name}`);
  }
}

function assertDenyAll(result) {
  if (result.public_https_blocked !== true) {
    throw new Error("deny-all unexpectedly allowed public HTTPS");
  }
}

async function lifecycle() {
  const created = [];
  let completed = false;
  try {
    const restricted = await Box.create({
      runtime: "node",
      name: "phase1-restricted-default-egress",
      timeout: 300_000,
    });
    created.push(restricted.id);
    if (restricted.networkPolicy.mode !== "allow-all") {
      throw new Error("omitted network policy did not round-trip as SDK allow-all");
    }
    const restrictedResult = assertRun(
      await restricted.exec.command(nodeCommand(restrictedProbe), { timeout: 30_000 }),
      "restricted-default probe",
    );
    assertRestricted(restrictedResult);

    const denied = await Box.create({
      runtime: "node",
      name: "phase1-deny-all-egress",
      networkPolicy: { mode: "deny-all" },
      timeout: 300_000,
    });
    created.push(denied.id);
    if (denied.networkPolicy.mode !== "deny-all") {
      throw new Error("explicit deny-all did not round-trip");
    }
    const denyResult = assertRun(
      await denied.exec.command(nodeCommand(denyAllProbe), { timeout: 10_000 }),
      "deny-all probe",
    );
    assertDenyAll(denyResult);

    completed = true;
    return {
      schema: "boxd-phase1-egress-smoke-v1",
      source_commit: sourceCommit,
      restricted_box_id: restricted.id,
      deny_all_box_id: denied.id,
      restricted_default_sdk_mode: restricted.networkPolicy.mode,
      restricted: restrictedResult,
      deny_all: denyResult,
      status: "idle",
    };
  } finally {
    if (!completed && created.length > 0) {
      await Box.delete({ boxIds: created }).catch(() => {});
    }
  }
}

async function restart() {
  const priorPath = process.env.BOXD_SMOKE_EGRESS_EVIDENCE;
  if (!priorPath) throw new Error("BOXD_SMOKE_EGRESS_EVIDENCE is required");
  const priorBytes = await readFile(priorPath);
  const prior = JSON.parse(priorBytes.toString("utf8"));
  if (
    prior.schema !== "boxd-phase1-egress-smoke-v1" ||
    typeof prior.restricted_box_id !== "string" ||
    typeof prior.deny_all_box_id !== "string"
  ) {
    throw new Error("egress lifecycle evidence is invalid");
  }

  const restricted = await Box.get(prior.restricted_box_id);
  const denied = await Box.get(prior.deny_all_box_id);
  if (restricted.networkPolicy.mode !== "allow-all") {
    throw new Error("restricted-default policy changed after restart");
  }
  if (denied.networkPolicy.mode !== "deny-all") {
    throw new Error("deny-all policy changed after restart");
  }
  const restrictedResult = assertRun(
    await restricted.exec.command(nodeCommand(restrictedProbe), { timeout: 30_000 }),
    "post-restart restricted-default probe",
  );
  assertRestricted(restrictedResult);
  const denyResult = assertRun(
    await denied.exec.command(nodeCommand(denyAllProbe), { timeout: 10_000 }),
    "post-restart deny-all probe",
  );
  assertDenyAll(denyResult);
  await Box.delete({ boxIds: [restricted.id, denied.id] });
  return {
    schema: "boxd-phase1-egress-restart-v1",
    source_commit: prior.source_commit,
    lifecycle_evidence_sha256: sha256(priorBytes),
    daemon_restart_reconcile: true,
    restricted_policy_persisted: true,
    deny_all_policy_persisted: true,
    restricted: restrictedResult,
    deny_all: denyResult,
    bulk_delete_count: 2,
    status: "deleted",
  };
}

const evidenceFile = await open(evidencePath, "wx", 0o600);
let committed = false;
try {
  const evidence = mode === "lifecycle" ? await lifecycle() : await restart();
  await evidenceFile.writeFile(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  await evidenceFile.sync();
  committed = true;
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} finally {
  await evidenceFile.close();
  if (!committed) await unlink(evidencePath).catch(() => {});
}
