import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";

const runCommand = promisify(execFile);
const root = new URL("../", import.meta.url);
const script = new URL("../scripts/differential-evidence.mjs", import.meta.url).pathname;
const matrixPath = new URL("../differential/case-matrix.json", import.meta.url).pathname;
const matrix = JSON.parse(await readFile(matrixPath, "utf8"));
const commit = "0123456789abcdef0123456789abcdef01234567";
const sha = "a".repeat(64);

function target(cleanupError = false) {
  return {
    execution_error: false,
    cleanup_error: cleanupError,
    execute: { artifact_hash: sha, request_count: 1 },
    cleanup: { artifact_hash: sha, request_count: 1 },
  };
}

function manifest(status = "passed") {
  return {
    schema_version: 1,
    sdk: "@upstash/box@0.6.3",
    mode: "authenticated-differential",
    status,
    selection: { contracts: 78, cases: 82 },
    targets: { official: "https://official.example.test", local: "http://127.0.0.1:7331" },
    limits: { request_timeout_ms: 30000, global_timeout_ms: 900000, concurrency: 1, budget_usd: 3.85 },
    executor: { adapter_cases: 82, blocked_without_adapter: 0 },
    gates: { allowed: status !== "blocked", blockers: status === "blocked" ? [{ gate: "credential", reason: "test credentials are absent" }] : [] },
    results: {
      executed_cases: status === "blocked" ? 0 : 82,
      passed_cases: status === "passed" ? 82 : status === "failed" ? 81 : 0,
      failed_cases: status === "failed" ? 1 : 0,
      blocked_cases: status === "blocked" ? 82 : 0,
      cleanup_failed_cases: status === "failed" ? 1 : 0,
      evidence_redacted: true,
      cases: status === "blocked" ? [] : matrix.cases.map((item, index) => ({
        case_id: item.case_id,
        status: status === "failed" && index === 0 ? "failed" : "passed",
        reason: status === "failed" && index === 0 ? "artifact_mismatch" : null,
        official: target(status === "failed" && index === 0),
        local: target(false),
      })),
    },
  };
}

async function withFixture(manifestValue, callback) {
  const directory = await mkdtemp(join(tmpdir(), "boxd-differential-evidence-"));
  const run = join(directory, "run.json");
  const matrixFile = join(directory, "matrix.json");
  const output = join(directory, "evidence.json");
  const binary = join(directory, "boxd");
  const runtime = join(directory, "runtime.tar");
  const config = join(directory, "boxd.toml");
  await writeFile(run, `${JSON.stringify(manifestValue)}\n`, { mode: 0o600 });
  await writeFile(matrixFile, `${JSON.stringify(matrix)}\n`, { mode: 0o600 });
  await writeFile(binary, "current-checkout-release-binary\n", { mode: 0o600 });
  await writeFile(runtime, "signed-runtime-bundle\n", { mode: 0o600 });
  await writeFile(config, "[server]\nlisten = \"127.0.0.1:7331\"\n", { mode: 0o600 });
  try { return await callback({ directory, run, output, matrix: matrixFile, binary, runtime, config }); } finally { await rm(directory, { recursive: true, force: true }); }
}

async function emit(run, output, files, extraEnv = {}) {
  return runCommand(process.execPath, [script, "--run", run, "--matrix", files.matrix ?? matrixPath, "--output", output, "--commit", commit, "--local-binary", files.binary, "--runtime-bundle", files.runtime, "--local-config", files.config], {
    env: { PATH: process.env.PATH, BOXD_DIFF_VIRTUALIZATION: "kvm", BOXD_DIFF_PLATFORM_OS: "linux", BOXD_DIFF_PLATFORM_ARCH: "x86_64", ...extraEnv },
  });
}

test("pass emits strict 82-case evidence with input and artifact hashes", async () => {
  await withFixture(manifest(), async (files) => {
    const result = await emit(files.run, files.output, files);
    assert.match(result.stdout, /"status":"pass"/);
    const evidence = JSON.parse(await readFile(files.output, "utf8"));
    assert.equal(evidence.schema, "boxd-phase4-evidence-v1");
    assert.equal(evidence.cases.length, 82);
    assert.equal(evidence.summary.status, "pass");
    assert.equal(evidence.summary.passed, 82);
    assert.equal(evidence.inputs.length, 5);
    assert.deepEqual(evidence.inputs.slice(2).map((item) => item.name), ["local-binary", "runtime-bundle", "local-config"]);
    assert.ok(evidence.cases.every((item) => item.status === "pass" && /^[0-9a-f]{64}$/.test(item.artifact_sha256)));
    assert.equal(evidence.secret_scan.findings, 0);
    await runCommand("python3", [new URL("../../../scripts/phase4-evidence.py", import.meta.url).pathname, files.output]);
  });
});

test("blocked emits 82 blocked cases and exits 2", async () => {
  await withFixture(manifest("blocked"), async (files) => {
    await assert.rejects(() => emit(files.run, files.output, files), (error) => error.code === 2);
    const evidence = JSON.parse(await readFile(files.output, "utf8"));
    assert.equal(evidence.summary.status, "blocked");
    assert.equal(evidence.summary.blocked, 82);
    assert.ok(evidence.external_requirements.some((item) => item.status === "blocked"));
  });
});

test("failed case emits fail evidence and exits 1", async () => {
  await withFixture(manifest("failed"), async (files) => {
    await assert.rejects(() => emit(files.run, files.output, files), (error) => error.code === 1);
    const evidence = JSON.parse(await readFile(files.output, "utf8"));
    assert.equal(evidence.summary.status, "fail");
    assert.equal(evidence.summary.failed, 1);
  });
});

test("tampered body and unknown fields are rejected closed-schema", async () => {
  await withFixture({ ...manifest(), unknown: true }, async (files) => {
    await assert.rejects(() => emit(files.run, files.output, files), /closed-schema field unknown/);
  });
  const tampered = manifest();
  tampered.results.cases[0].official.extra = true;
  await withFixture(tampered, async (files) => {
    await assert.rejects(() => emit(files.run, files.output, files), /closed-schema field extra/);
  });
});

test("secret-like values are rejected before evidence is written", async () => {
  const tampered = manifest("blocked");
  tampered.gates.blockers[0].reason = "super-secret-api-key";
  await withFixture(tampered, async (files) => {
    await assert.rejects(() => emit(files.run, files.output, files, { BOXD_DIFF_TEST_SECRET: "super-secret-api-key" }), /secret scan found/);
  });
});

test("output uses exclusive creation and refuses overwrite", async () => {
  await withFixture(manifest(), async (files) => {
    await emit(files.run, files.output, files);
    await assert.rejects(() => emit(files.run, files.output, files), /output cannot be created exclusively/);
  });
});

test("closed counts and exact matrix IDs reject forged results", async () => {
  const cases = [
    ["伪造 passed count", (value) => { value.results.passed_cases = 81; }, /counts are not closed/],
    ["extra case", (value) => { value.results.cases[0].case_id = "extra-case"; }, /extra case result/],
    ["missing case", (value) => { value.results.cases.pop(); value.results.executed_cases = 81; value.results.passed_cases = 81; }, /missing one or more/],
    ["duplicate case", (value) => { value.results.cases[1].case_id = value.results.cases[0].case_id; }, /duplicate case result/],
    ["non-loopback local", (value) => { value.targets.local = "http://attacker.example.test:7331"; }, /local target must be loopback/],
    ["non-enum reason", (value) => { value.results.cases[0].reason = "invented"; }, /executor enum/],
  ];
  for (const [, mutate, expected] of cases) {
    const value = manifest(); mutate(value);
    await withFixture(value, async (files) => assert.rejects(() => emit(files.run, files.output, files), expected));
  }
});

test("input files are hashed and changing the local binary changes its evidence hash", async () => {
  await withFixture(manifest(), async (files) => {
    await emit(files.run, files.output, files);
    const first = JSON.parse(await readFile(files.output, "utf8"));
    await rm(files.output);
    await rm(join(files.directory, "cases"), { recursive: true, force: true });
    await writeFile(files.binary, "different checkout binary\n", { mode: 0o600 });
    await emit(files.run, files.output, files);
    const second = JSON.parse(await readFile(files.output, "utf8"));
    assert.notEqual(first.inputs.find((item) => item.name === "local-binary").sha256, second.inputs.find((item) => item.name === "local-binary").sha256);
  });
});

test("matrix duplicate and invalid case IDs are rejected", async () => {
  for (const mutate of [
    (value) => { value.cases[1].case_id = value.cases[0].case_id; },
    (value) => { value.cases[0].case_id = "bad\ncase"; },
  ]) {
    await withFixture(manifest(), async (files) => {
      const altered = JSON.parse(await readFile(files.matrix, "utf8"));
      mutate(altered);
      await writeFile(files.matrix, `${JSON.stringify(altered)}\n`, { mode: 0o600 });
      await assert.rejects(() => emit(files.run, files.output, files), /(?:duplicate matrix case ID|matrix case ID is invalid)/);
    });
  }
});
