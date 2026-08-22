import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, stat, symlink, writeFile } from "node:fs/promises";
import net from "node:net";
import { promisify } from "node:util";
import test from "node:test";

const exec = promisify(execFile);
const helper = new URL("../../../scripts/phase4-differential-native.sh", import.meta.url).pathname;
const workflow = new URL("../../../.github/workflows/phase4-authenticated-differential.yml", import.meta.url).pathname;

test("native helper owns the current-checkout build and readiness lifecycle", async () => {
  const source = await (await import("node:fs/promises")).readFile(helper, "utf8");
  assert.match(source, /cargo build --release --locked -p boxd/);
  assert.match(source, /config validate/);
  assert.match(source, /runtime import/);
  assert.match(source, /doctor .*--json/);
  assert.match(source, /overall.*true/);
  assert.match(source, /health\/ready/);
  assert.match(source, /trap phase4_native_stop EXIT INT TERM/);
  assert.match(source, /phase4_native_hash runtime-bundle/);
  assert.match(source, /phase4_native_hash config/);
  assert.match(source, /init --config/);
  assert.match(source, /compat_api_key=/);
  assert.match(source, /::add-mask::/);
  assert.match(source, /phase4_native_capture_compat_key/);
  assert.ok(source.indexOf("export BOXD_EMBEDDED_LIBKRUN_PATH") < source.indexOf("cargo build --release --locked -p boxd"));
  assert.ok(source.indexOf("export BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH") < source.indexOf("cargo build --release --locked -p boxd"));
});

test("occupied endpoint is rejected instead of reusing a pre-running daemon", async () => {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    await assert.rejects(
      exec("bash", ["-c", `source "$1"; BOXD_DIFF_LOCAL_BASE_URL="http://127.0.0.1:${port}"; phase4_native_port_free`, "phase4-test", helper]),
      /already occupied/,
    );
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("native helper rejects non-loopback and non-origin URLs", async () => {
  await assert.rejects(
    exec("bash", ["-c", `source "$1"; BOXD_DIFF_LOCAL_BASE_URL="https://remote.example.test/path"; phase4_native_origin`, "phase4-test", helper]),
    /bare loopback HTTP origin/,
  );
});

test("regular-file guard fails closed when invoked from a conditional", async () => {
  const temp = await (await import("node:fs/promises")).mkdtemp("/tmp/boxd-phase4-regular-test-");
  const target = `${temp}/target`;
  const alias = `${temp}/alias`;
  try {
    await writeFile(target, "value", { mode: 0o600 });
    await symlink(target, alias);
    await assert.rejects(
      exec("bash", ["-c", `source "$1"; if phase4_native_regular test "$2"; then exit 0; else exit 42; fi`, "phase4-test", helper, alias]),
      (error) => error.code === 42,
    );
  } finally {
    await exec("python3", ["-c", "import shutil,sys; shutil.rmtree(sys.argv[1])", temp]);
  }
});

test("generated config is run-local, leaves the template unchanged, and rewrites all state paths", async () => {
  const temp = await (await import("node:fs/promises")).mkdtemp("/tmp/boxd-phase4-native-test-");
  const template = new URL("../../../config/boxd.example.toml", import.meta.url).pathname;
  const before = await readFile(template, "utf8");
  try {
    const command = `source "$1"; RUNNER_TEMP="$2"; phase4_native_prepare_run; phase4_native_write_config "$3" "$BOXD_DIFF_RUN_ROOT/boxd.toml" "$BOXD_DIFF_RUN_ROOT" "$BOXD_DIFF_LOCAL_PORT"; printf '%s\\n%s\\n%s\\n' "$BOXD_DIFF_RUN_ROOT" "$BOXD_DIFF_RUN_ROOT/boxd.toml" "$BOXD_DIFF_LOCAL_BASE_URL"`;
    const { stdout } = await exec("bash", ["-c", command, "phase4-test", helper, temp, template]);
    const [runRoot, generated, url] = stdout.trim().split("\n");
    assert.match(runRoot, new RegExp(`^${temp.replaceAll("/", "\\/")}\\/boxd-phase4-native\\.`));
    assert.match(generated, /\/boxd\.toml$/);
    assert.match(url, /^http:\/\/127\.0\.0\.1:\d+$/);
    const config = await readFile(generated, "utf8");
    assert.equal((await stat(generated)).mode & 0o777, 0o600);
    assert.match(config, new RegExp(`127\\.0\\.0\\.1:${url.split(":").at(-1)}`));
    assert.match(config, new RegExp(`${runRoot.replaceAll("/", "\\/")}\/data`));
    assert.match(config, /sqlite:\/\/\/.*boxd\.sqlite3\?mode=rwc/);
    assert.equal(await readFile(template, "utf8"), before);
  } finally {
    await exec("python3", ["-c", "import shutil,sys; shutil.rmtree(sys.argv[1])", temp]);
  }
});

test("workflow cannot let a failed evidence validator become a passing exit", async () => {
  const source = await readFile(workflow, "utf8");
  assert.match(source, /if \[\[ \"\$validation_status\" -ne 0 \]\]; then\s+evidence_status=1/);
  await assert.rejects(
    exec("bash", ["-c", "runner_status=0; evidence_status=0; validation_status=1; if [[ \"$validation_status\" -ne 0 ]]; then evidence_status=1; elif [[ \"$runner_status\" -eq 0 ]]; then evidence_status=0; fi; exit \"$evidence_status\""]),
    (error) => error.code === 1,
  );
});

test("workflow has no pre-provisioned local API-key secret and bootstrap key is shell-only", async () => {
  const source = await readFile(workflow, "utf8");
  assert.doesNotMatch(source, /BOXD_DIFF_LOCAL_API_KEY:\s*\$\{\{\s*secrets\./);
  assert.doesNotMatch(source, /BOXD_DIFF_LOCAL_API_KEY BOXD_DIFF_PROVIDER_API_KEY/);
  const temp = await (await import("node:fs/promises")).mkdtemp("/tmp/boxd-phase4-key-test-");
  const output = `${temp}/init.stdout`;
  try {
    await (await import("node:fs/promises")).writeFile(output, "created x\ncompat_api_key=boxd_compat_abc_def\nadministrator=local\n", { mode: 0o600 });
    const command = `source "$1"; phase4_native_capture_compat_key "$2" >/dev/null; test "$BOXD_DIFF_LOCAL_API_KEY" = boxd_compat_abc_def; test "$UPSTASH_BOX_API_KEY" = boxd_compat_abc_def; test ! -e "$2"`;
    await exec("bash", ["-c", command, "phase4-test", helper, output]);
  } finally {
    await exec("python3", ["-c", "import os,sys; os.unlink(sys.argv[1]) if os.path.exists(sys.argv[1]) else None", output]);
    await exec("python3", ["-c", "import shutil,sys; shutil.rmtree(sys.argv[1])", temp]);
  }
});
