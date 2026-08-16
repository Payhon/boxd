#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdtemp, open, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [mode, sdkEntry, evidencePath] = process.argv.slice(2);
if (!["lifecycle", "restart"].includes(mode) || !sdkEntry || !evidencePath) {
  throw new Error(
    "usage: phase1-sdk-smoke.mjs lifecycle|restart SDK_ENTRY EVIDENCE_JSON",
  );
}
if (!process.env.UPSTASH_BOX_API_KEY || !process.env.UPSTASH_BOX_BASE_URL) {
  throw new Error(
    "UPSTASH_BOX_API_KEY and UPSTASH_BOX_BASE_URL are required",
  );
}

const sourceCommit = "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934";
const expectedDiskBytes = Number(
  process.env.BOXD_SMOKE_EXPECTED_DISK_BYTES ?? 20 * 1024 ** 3,
);
if (!Number.isSafeInteger(expectedDiskBytes) || expectedDiskBytes <= 0) {
  throw new Error("BOXD_SMOKE_EXPECTED_DISK_BYTES must be a positive safe integer");
}

const fetchEvidence = {
  initialCreateStatuses: [],
  createPolls: 0,
};
const realFetch = globalThis.fetch;
if (typeof realFetch !== "function") {
  throw new Error("this smoke requires a Node.js runtime with global fetch");
}
globalThis.fetch = async (input, init) => {
  const response = await realFetch(input, init);
  const rawUrl = typeof input === "string" || input instanceof URL ? input : input.url;
  const url = new URL(rawUrl, process.env.UPSTASH_BOX_BASE_URL);
  const method = (init?.method ?? (typeof input === "object" && "method" in input ? input.method : "GET")).toUpperCase();
  if (method === "POST" && url.pathname === "/v2/box") {
    const payload = await response.clone().json().catch(() => null);
    if (payload && typeof payload.status === "string") {
      fetchEvidence.initialCreateStatuses.push(payload.status);
    }
  } else if (method === "GET" && /^\/v2\/box\/[^/]+$/.test(url.pathname)) {
    fetchEvidence.createPolls += 1;
  }
  return response;
};

const { Box } = await import(pathToFileURL(sdkEntry).href);
let retainedOnEvidenceFailure = [];

function assertRun(run, expected, label) {
  if (run.exitCode !== 0 || run.stdout.trim() !== expected) {
    throw new Error(`${label} contract mismatch`);
  }
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function invalidInitCommandContract() {
  try {
    await Box.create({
      runtime: "node",
      name: "phase1-invalid-init-command",
      initCommand: "printf should-not-run",
      keepAlive: false,
    });
  } catch (error) {
    if (String(error).includes("initCommand requires keepAlive: true")) return;
    throw error;
  }
  throw new Error("initCommand with keepAlive=false was unexpectedly accepted");
}

async function lifecycle() {
  const local = await mkdtemp(join(tmpdir(), "boxd-sdk-smoke-"));
  const createdIds = [];
  let completed = false;
  try {
    await invalidInitCommandContract();
    let initBox;
    try {
      initBox = await Box.create({
        runtime: "node",
        name: "phase1-init-command",
        keepAlive: true,
        initCommand:
          "printf init-command-ok > /workspace/home/init-command.txt",
        timeout: 300_000,
      });
      createdIds.push(initBox.id);
      if ((await initBox.files.read("init-command.txt")) !== "init-command-ok") {
        throw new Error("keep-alive init command did not create its expected file");
      }
      assertRun(
        await initBox.exec.command("cat /workspace/home/init-command.txt"),
        "init-command-ok",
        "keep-alive init command exec verification",
      );
    } finally {
      if (initBox) {
        await Box.delete({ boxIds: [initBox.id] });
        const index = createdIds.indexOf(initBox.id);
        if (index >= 0) createdIds.splice(index, 1);
      }
    }

    const createStatusOffset = fetchEvidence.initialCreateStatuses.length;
    const createPollOffset = fetchEvidence.createPolls;
    const createStarted = Date.now();
    const box = await Box.create({
      runtime: "node",
      name: "phase1-platform-smoke",
      timeout: 300_000,
    });
    createdIds.push(box.id);
    const createElapsedMs = Date.now() - createStarted;
    const createStatuses = fetchEvidence.initialCreateStatuses.slice(createStatusOffset);
    const createPollCount = fetchEvidence.createPolls - createPollOffset;
    if (!createStatuses.includes("creating") || createPollCount < 1) {
      throw new Error("SDK did not observe the asynchronous create/poll contract");
    }

    assertRun(
      await box.exec.command("printf phase1-platform-ok"),
      "phase1-platform-ok",
      "initial exec",
    );
    const longStarted = Date.now();
    assertRun(
      await box.exec.command("sleep 2; printf long-exec-ok"),
      "long-exec-ok",
      "long exec",
    );
    const longExecElapsedMs = Date.now() - longStarted;
    if (longExecElapsedMs < 1_000) throw new Error("long exec returned too early");

    assertRun(
      await box.exec.code({
        lang: "ts",
        code: "const value: number = 21 * 2; console.log(`ts-${value}`);",
        timeout: 30_000,
      }),
      "ts-42",
      "TypeScript exec",
    );

    await box.files.write({ path: "phase1.txt", content: "persistent-file-ok" });
    if ((await box.files.read("phase1.txt")) !== "persistent-file-ok") {
      throw new Error("file read contract mismatch");
    }
    const listed = await box.files.list();
    if (!listed.some((entry) => entry.name === "phase1.txt" && entry.is_dir === false)) {
      throw new Error("file list contract mismatch");
    }
    const mtimeBefore = (
      await box.exec.command("stat -c %Y /workspace/home/phase1.txt")
    ).stdout.trim();

    const binary = Buffer.alloc(5 * 1024 * 1024 + 17);
    for (let index = 0; index < binary.length; index += 1) binary[index] = index % 251;
    const binaryHash = sha256(binary);
    const localUpload = join(local, "payload.bin");
    await writeFile(localUpload, binary, { mode: 0o600 });
    assertRun(await box.exec.command("mkdir -p binary"), "", "binary directory");
    await box.files.upload([{ path: localUpload, destination: "binary/payload.bin" }]);
    assertRun(
      await box.exec.command("sha256sum binary/payload.bin | cut -d' ' -f1"),
      binaryHash,
      "uploaded binary hash",
    );
    const priorCwd = process.cwd();
    process.chdir(local);
    try {
      await box.files.download({ folder: "binary" });
    } finally {
      process.chdir(priorCwd);
    }
    const downloaded = await readFile(join(local, "binary", "payload.bin"));
    if (sha256(downloaded) !== binaryHash) throw new Error("downloaded binary hash mismatch");

    assertRun(
      await box.exec.command(
        "mkdir -p nested/left nested/right && printf left-content > nested/left/same.txt && printf right-content > nested/right/same.txt",
      ),
      "",
      "nested tree fixture",
    );
    let nestedDownloadFailedClosed = false;
    process.chdir(local);
    try {
      await box.files.download({ folder: "nested" });
    } catch (error) {
      nestedDownloadFailedClosed =
        error?.statusCode === 501 && String(error).includes("feature_not_supported");
      if (!nestedDownloadFailedClosed) throw error;
    } finally {
      process.chdir(priorCwd);
    }
    if (!nestedDownloadFailedClosed) {
      throw new Error("nested tree download was unexpectedly accepted");
    }

    const df = await box.exec.command("df -B1 --output=size / | tail -n 1 | tr -d ' '");
    const rootfsBytes = Number(df.stdout.trim());
    if (
      df.exitCode !== 0 ||
      !Number.isSafeInteger(rootfsBytes) ||
      rootfsBytes < expectedDiskBytes * 0.95 ||
      rootfsBytes > expectedDiskBytes
    ) {
      throw new Error(
        `rootfs df is outside the expected ext4 capacity range: raw=${expectedDiskBytes}, df=${df.stdout.trim()}`,
      );
    }

    await box.pause();
    if ((await box.getStatus()).status !== "paused") throw new Error("pause contract mismatch");
    await box.resume();
    if ((await box.getStatus()).status !== "idle") throw new Error("resume contract mismatch");
    const mtimeAfter = (
      await box.exec.command("stat -c %Y /workspace/home/phase1.txt")
    ).stdout.trim();
    if (mtimeAfter !== mtimeBefore) throw new Error("file mtime changed across pause/resume");
    assertRun(
      await box.exec.command("cat /workspace/home/phase1.txt"),
      "persistent-file-ok",
      "post-resume exec",
    );

    const secondary = await Box.create({
      runtime: "node",
      name: "phase1-bulk-delete-secondary",
      timeout: 300_000,
    });
    createdIds.push(secondary.id);
    retainedOnEvidenceFailure = [...createdIds];
    completed = true;
    return {
      schema: "boxd-phase1-platform-smoke-v2",
      source_commit: sourceCommit,
      box_id: box.id,
      bulk_delete_box_ids: createdIds,
      async_create_initial_status: "creating",
      async_create_poll_count: createPollCount,
      create_elapsed_ms: createElapsedMs,
      long_exec_elapsed_ms: longExecElapsedMs,
      typescript_exec: true,
      file_write_read_list: true,
      mtime_preserved: true,
      binary_bytes: binary.length,
      binary_sha256: binaryHash,
      upload_download_over_4mib: true,
      nested_download_fail_closed: true,
      rootfs_df_bytes: rootfsBytes,
      invalid_init_command_keep_alive_false_rejected_by_sdk: true,
      init_command_keep_alive_true_separate_box: true,
      pause_resume: true,
      status: "idle",
    };
  } finally {
    await rm(local, { recursive: true, force: true });
    if (!completed && createdIds.length > 0) {
      await Box.delete({ boxIds: createdIds }).catch(() => {});
    }
  }
}

async function restart() {
  const priorPath = process.env.BOXD_SMOKE_LIFECYCLE_EVIDENCE;
  if (!priorPath) {
    throw new Error("BOXD_SMOKE_LIFECYCLE_EVIDENCE is required for restart mode");
  }
  const priorBytes = await readFile(priorPath);
  const prior = JSON.parse(priorBytes.toString("utf8"));
  if (
    prior.schema !== "boxd-phase1-platform-smoke-v2" ||
    typeof prior.box_id !== "string" ||
    !Array.isArray(prior.bulk_delete_box_ids) ||
    prior.bulk_delete_box_ids.length < 2
  ) {
    throw new Error("lifecycle evidence is invalid");
  }
  const box = await Box.get(prior.box_id);
  if ((await box.getStatus()).status !== "idle") {
    throw new Error("reconciled status is not idle");
  }
  if ((await box.files.read("phase1.txt")) !== "persistent-file-ok") {
    throw new Error("persisted file contract mismatch");
  }
  assertRun(
    await box.exec.command("printf phase1-restart-ok"),
    "phase1-restart-ok",
    "post-restart exec",
  );
  await Box.delete({ boxIds: prior.bulk_delete_box_ids });
  return {
    schema: "boxd-phase1-platform-restart-v2",
    source_commit: prior.source_commit,
    box_id: prior.box_id,
    lifecycle_evidence_sha256: sha256(priorBytes),
    daemon_restart_reconcile: true,
    persisted_file: true,
    post_restart_exec: true,
    bulk_delete_count: prior.bulk_delete_box_ids.length,
    bulk_delete: true,
    status: "deleted",
  };
}

const evidenceFile = await open(evidencePath, "wx", 0o600);
let evidenceCommitted = false;
try {
  const evidence = mode === "lifecycle" ? await lifecycle() : await restart();
  await evidenceFile.writeFile(`${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  await evidenceFile.sync();
  evidenceCommitted = true;
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
} finally {
  await evidenceFile.close();
  if (!evidenceCommitted) {
    if (retainedOnEvidenceFailure.length > 0) {
      await Box.delete({ boxIds: retainedOnEvidenceFailure }).catch(() => {});
    }
    await unlink(evidencePath).catch(() => {});
  }
}
