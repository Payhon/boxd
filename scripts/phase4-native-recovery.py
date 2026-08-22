#!/usr/bin/env python3
"""Run the safe native subset of the Phase 4 recovery matrix.

This runner builds boxd from the checked-out commit, starts only processes it
owns, and writes evidence below a dedicated RUNNER_TEMP directory. Faults that
would require unsafe host-wide disk pressure, arbitrary worker injection, or a
destructive migration are recorded as blocked rather than simulated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as platform_module
import re
import shutil
import signal
import sqlite3
import stat
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


SCENARIOS = (
    "graceful-stop",
    "sigterm",
    "worker-sigkill",
    "daemon-restart",
    "disk-full",
    "runtime-pull-interruption",
    "sqlite-backup-restore",
    "migration-journal",
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
PINNED_SDK_COMMIT = "677ca0827a6f54bc328b4b3e97d32a7cc5ac1934"
REQUIRED_SECRETS = ("BOXD_MASTER_KEY", "BOXD_ADMIN_PASSWORD")
EMBEDDED_ASSETS = (
    "BOXD_EMBEDDED_LIBKRUN_PATH",
    "BOXD_EMBEDDED_LIBKRUN_LICENSE_PATH",
    "BOXD_EMBEDDED_LIBKRUNFW_PATH",
    "BOXD_EMBEDDED_LIBKRUNFW_LICENSE_PATH",
)
EMBEDDED_ASSET_HASHES = {
    "BOXD_EMBEDDED_LIBKRUN_PATH": "BOXD_EMBEDDED_LIBKRUN_SHA256",
    "BOXD_EMBEDDED_LIBKRUNFW_PATH": "BOXD_EMBEDDED_LIBKRUNFW_SHA256",
}


class RunnerError(RuntimeError):
    """The native runner cannot produce trustworthy evidence."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_hash(path: Path, expected: str, label: str) -> None:
    if sha256(path) != expected:
        raise RunnerError(f"{label} changed after hash binding")


def regular_file(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RunnerError(f"{label} is unavailable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
        raise RunnerError(f"{label} must be a single-link regular file")
    return path


def copy_input(source: Path, destination: Path, label: str, *, mode: int = 0o600) -> str:
    regular_file(source, label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise RunnerError(f"refusing to overwrite {label} input")
    shutil.copyfile(source, destination)
    destination.chmod(mode)
    regular_file(destination, label)
    return sha256(destination)


def command_log(
    work: Path,
    name: str,
    result: subprocess.CompletedProcess[str],
    redact_values: tuple[str, ...] = (),
) -> None:
    log = work / "logs" / f"{name}.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    stdout = result.stdout
    stderr = result.stderr
    for value in redact_values:
        if value:
            stdout = stdout.replace(value, "[REDACTED]")
            stderr = stderr.replace(value, "[REDACTED]")
    log.write_text(
        f"returncode={result.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}\n",
        encoding="utf-8",
    )
    log.chmod(0o600)


def run_command(
    work: Path,
    name: str,
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    redact_values: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RunnerError(f"{name} timed out after {timeout}s") from error
    command_log(work, name, result, redact_values)
    return result


def native_platform() -> dict[str, str]:
    system = sys.platform
    machine = platform_module.machine().lower()
    if system == "darwin" and machine == "arm64":
        try:
            result = subprocess.run(
                ["sysctl", "-n", "kern.hv_support"], capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RunnerError(f"cannot inspect Hypervisor.framework support: {error}") from error
        if result.returncode != 0 or result.stdout.strip() != "1":
            raise RunnerError("macOS Apple Silicon HVF support is not enabled")
        return {"os": "macos", "arch": "aarch64", "virtualization": "hvf"}
    if system == "linux" and machine in ("x86_64", "amd64", "aarch64", "arm64"):
        kvm = Path("/dev/kvm")
        controllers = Path("/sys/fs/cgroup/cgroup.controllers")
        if not stat.S_ISCHR(kvm.stat().st_mode) or not os.access(kvm, os.R_OK | os.W_OK):
            raise RunnerError("Linux native recovery requires a readable and writable /dev/kvm")
        if not controllers.is_file():
            raise RunnerError("Linux native recovery requires cgroup v2")
        available = controllers.read_text(encoding="utf-8").split()
        if not {"cpu", "memory", "pids"}.issubset(available):
            raise RunnerError("Linux cgroup v2 must expose cpu, memory and pids controllers")
        arch = "x86_64" if machine in ("x86_64", "amd64") else "aarch64"
        return {"os": "linux", "arch": arch, "virtualization": "kvm"}
    raise RunnerError(f"unsupported native recovery host: {system}/{machine}")


def prepare_work_dir(path: Path) -> Path:
    runner_temp = Path(os.environ.get("RUNNER_TEMP", "")).resolve()
    if not runner_temp.is_absolute() or not runner_temp.is_dir():
        raise RunnerError("RUNNER_TEMP must be an existing directory")
    if path.is_symlink() or path.exists() and not path.is_dir():
        raise RunnerError("work directory must be a real directory")
    path = path.resolve()
    try:
        path.relative_to(runner_temp)
    except ValueError as error:
        raise RunnerError("work directory must be below RUNNER_TEMP") from error
    if path.exists() and any(path.iterdir()):
        raise RunnerError("work directory must be new or empty")
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    (path / "tmp").mkdir(mode=0o700)
    return path


def replace_config(source: Path, target: Path, data_dir: Path, port: int) -> None:
    regular_file(source, "recovery config")
    sections: dict[str, dict[str, str]] = {
        "server": {"listen": f"127.0.0.1:{port}", "public_url": f"http://127.0.0.1:{port}"},
        "preview": {"base_url": f"http://127.0.0.1:{port}"},
        "database": {"url": f"sqlite://{data_dir / 'boxd.sqlite3'}?mode=rwc"},
        "storage": {
            "data_dir": str(data_dir),
            "images_dir": str(data_dir / "images"),
            "boxes_dir": str(data_dir / "boxes"),
            "snapshots_dir": str(data_dir / "snapshots"),
            "recordings_dir": str(data_dir / "recordings"),
        },
    }
    lines = source.read_text(encoding="utf-8").splitlines()
    current = ""
    replaced: set[tuple[str, str]] = set()
    output: list[str] = []
    for line in lines:
        section_match = re.match(r"^\s*\[([^\]]+)\]\s*$", line)
        if section_match:
            current = section_match.group(1)
        replacement = None
        assignment = re.match(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if assignment and current in sections and assignment.group(2) in sections[current]:
            key = assignment.group(2)
            replacement = f'{assignment.group(1)}{key} = {json.dumps(sections[current][key])}'
            replaced.add((current, key))
        output.append(replacement if replacement is not None else line)
    missing = {
        (section, key)
        for section, values in sections.items()
        for key in values
        if (section, key) not in replaced
    }
    if missing:
        raise RunnerError(f"recovery config is missing required assignments: {sorted(missing)}")
    target.write_text("\n".join(output) + "\n", encoding="utf-8")
    target.chmod(0o600)
    regular_file(target, "generated recovery config")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def verify_data_tree(data_dir: Path, work: Path) -> dict[str, int]:
    """Verify the daemon's private data tree did not escape or alias the work dir."""
    root = data_dir.resolve(strict=True)
    work_root = work.resolve(strict=True)
    try:
        root.relative_to(work_root)
    except ValueError as error:
        raise RunnerError("daemon data directory escaped RUNNER_TEMP work directory") from error
    files = 0
    bytes_written = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories + filenames:
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise RunnerError(f"daemon data tree contains a symlink: {path}")
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise RunnerError(f"daemon data tree contains a hardlink: {path}")
                files += 1
                bytes_written += info.st_size
    return {"regular_files": files, "bytes": bytes_written}


def verify_sqlite(database: Path) -> dict[str, object]:
    """Run SQLite's own integrity check against the stopped daemon database."""
    regular_file(database, "recovery SQLite database")
    uri = f"file:{database}?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            page_count = connection.execute("PRAGMA page_count").fetchone()
        finally:
            connection.close()
    except sqlite3.DatabaseError as error:
        raise RunnerError(f"SQLite integrity check failed: {error}") from error
    if not integrity or integrity[0] != "ok":
        raise RunnerError(f"SQLite integrity check returned {integrity!r}")
    if not page_count or not isinstance(page_count[0], int) or page_count[0] < 1:
        raise RunnerError("SQLite page count is invalid")
    return {"integrity_check": "ok", "page_count": page_count[0]}


def initialize_database(work: Path, binary: Path, target: Path, env: dict[str, str]) -> str:
    """Initialize the disposable database and redact its one-time key from logs."""
    result = subprocess.run(
        [str(binary), "init", "--config", str(target)],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    key_lines = [line for line in result.stdout.splitlines() if line.startswith("compat_api_key=")]
    redacted_stdout = re.sub(r"(?m)^compat_api_key=.*$", "compat_api_key=[REDACTED]", result.stdout)
    redacted_stderr = re.sub(r"(?m)^compat_api_key=.*$", "compat_api_key=[REDACTED]", result.stderr)
    command_log(
        work,
        "database-init",
        subprocess.CompletedProcess(result.args, result.returncode, redacted_stdout, redacted_stderr),
    )
    if result.returncode != 0:
        raise RunnerError("disposable database initialization failed")
    if len(key_lines) != 1:
        raise RunnerError("boxd init must return exactly one compatibility key")
    key = key_lines[0].split("=", 1)[1].strip()
    if not re.fullmatch(r"boxd_compat_[A-Za-z0-9]+_[A-Za-z0-9]+", key):
        raise RunnerError("boxd init did not return a valid one-time compatibility key")
    return key


def build_pinned_sdk(work: Path, repo: Path, env: dict[str, str]) -> tuple[Path, str, dict[str, str]]:
    """Build the reviewed SDK source from this checkout and return its temporary entry."""
    script = repo / "compat/upstash-box-0.6.3/scripts/build-pinned-sdk.mjs"
    result = run_command(work, "pinned-sdk-build", ["node", str(script), "--json"], cwd=repo, env=env, timeout=120)
    if result.returncode != 0:
        raise RunnerError("pinned SDK build failed")
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RunnerError("pinned SDK build did not emit JSON metadata") from error
    if metadata.get("source_commit") != PINNED_SDK_COMMIT:
        raise RunnerError("pinned SDK source commit is not the reviewed @upstash/box commit")
    cleanup = metadata.get("cleanup")
    if not isinstance(cleanup, dict) or set(cleanup) != {"dir", "token"}:
        raise RunnerError("pinned SDK cleanup metadata is closed and required")
    sdk_dir = Path(cleanup["dir"]).resolve()
    temp_root = (work / "tmp").resolve()
    try:
        sdk_dir.relative_to(temp_root)
    except ValueError as error:
        raise RunnerError("pinned SDK temp directory escaped RUNNER_TEMP") from error
    if not sdk_dir.name.startswith("boxd-pinned-sdk-") or sdk_dir.is_symlink() or not sdk_dir.is_dir():
        raise RunnerError("pinned SDK cleanup directory is not an owned temporary directory")
    expected_token = hashlib.sha256(str(sdk_dir).encode()).hexdigest()
    if cleanup["token"] != expected_token:
        raise RunnerError("pinned SDK cleanup token mismatch")
    entry_url = metadata.get("entry")
    if not isinstance(entry_url, str) or not entry_url.startswith("file:"):
        raise RunnerError("pinned SDK entry must be a file URL")
    entry_path = Path(urllib.parse.unquote(urllib.parse.urlparse(entry_url).path)).resolve()
    try:
        entry_path.relative_to(sdk_dir)
    except ValueError as error:
        raise RunnerError("pinned SDK entry escaped its temporary directory") from error
    regular_file(entry_path, "pinned SDK entry")
    return entry_path, cleanup["token"], {"source_commit": PINNED_SDK_COMMIT, "entry_sha256": sha256(entry_path)}


def cleanup_pinned_sdk(work: Path, sdk_dir: Path | None, token: str | None) -> None:
    if sdk_dir is None or token is None:
        return
    sdk_dir = sdk_dir.resolve()
    temp_root = (work / "tmp").resolve()
    try:
        sdk_dir.relative_to(temp_root)
    except ValueError:
        return
    if sdk_dir.is_symlink() or not sdk_dir.name.startswith("boxd-pinned-sdk-"):
        return
    if hashlib.sha256(str(sdk_dir).encode()).hexdigest() != token:
        return
    if sdk_dir.is_dir():
        shutil.rmtree(sdk_dir)


class Daemon:
    def __init__(self, work: Path, binary: Path, config: Path, env: dict[str, str], port: int) -> None:
        self.work = work
        self.binary = binary
        self.config = config
        self.env = env
        self.port = port
        self.process: subprocess.Popen[str] | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self, name: str) -> None:
        if self.process is not None and self.process.poll() is None:
            raise RunnerError("daemon is already running")
        stdout = (self.work / "logs" / f"{name}.stdout").open("w", encoding="utf-8")
        stderr = (self.work / "logs" / f"{name}.stderr").open("w", encoding="utf-8")
        stdout.chmod(0o600)
        stderr.chmod(0o600)
        daemon_env = dict(self.env)
        daemon_env["TMPDIR"] = str(self.work / "tmp")
        try:
            self.process = subprocess.Popen(
                [str(self.binary), "serve", "--config", str(self.config)],
                cwd=self.work,
                env=daemon_env,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
                text=True,
            )
        finally:
            stdout.close()
            stderr.close()
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RunnerError(f"daemon exited before readiness ({name})")
            try:
                with urllib.request.urlopen(f"{self.url}/health/ready", timeout=3) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(1)
        raise RunnerError(f"daemon readiness timed out ({name})")

    def stop(self, sig: signal.Signals = signal.SIGTERM) -> tuple[bool, str]:
        process = self.process
        if process is None:
            return True, "daemon was not running"
        if process.poll() is not None:
            self.process = None
            return process.returncode == 0, f"daemon already exited with code {process.returncode}"
        process.send_signal(sig)
        try:
            returncode = process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            self.process = None
            return False, "daemon did not stop after SIGTERM and required owned process-group SIGKILL"
        self.process = None
        if returncode != 0:
            return False, f"daemon exited with code {returncode}"
        return True, "daemon exited cleanly after SIGTERM"

    def cleanup(self) -> None:
        if self.process is not None and self.process.poll() is None:
            try:
                self.process.send_signal(signal.SIGTERM)
                self.process.wait(timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
                try:
                    self.process.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    pass
        self.process = None


def step(operation: str, expected: str, observed: str, status: str) -> dict[str, str]:
    return {"operation": operation, "expected": expected, "observed": observed, "status": status}


def case_result(
    scenario: str,
    status: str,
    expected: str,
    observed: str,
    steps: list[dict[str, str]],
    started_at_unix_ms: int,
    finished_at_unix_ms: int,
) -> dict[str, object]:
    return {
        "scenario": scenario,
        "status": status,
        "expected": expected,
        "observed": observed,
        "steps": steps,
        "started_at_unix_ms": started_at_unix_ms,
        "finished_at_unix_ms": finished_at_unix_ms,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--runtime-bundle", required=True, type=Path)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--commit")
    args = parser.parse_args()
    daemon: Daemon | None = None
    sdk_dir: Path | None = None
    sdk_cleanup_token: str | None = None
    compatibility_key: str | None = None
    try:
        native = native_platform()
        work = prepare_work_dir(args.work_dir)
        repo = Path(__file__).resolve().parents[1]
        current_commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        commit = args.commit or current_commit
        if not COMMIT.fullmatch(commit) or not COMMIT.fullmatch(current_commit):
            raise RunnerError("current commit must be a full lowercase Git object id")
        if commit != current_commit:
            raise RunnerError(f"requested commit {commit} does not match checked-out HEAD {current_commit}")
        for name in REQUIRED_SECRETS:
            if not os.environ.get(name):
                raise RunnerError(f"missing required environment secret: {name}")
        for name in EMBEDDED_ASSETS:
            asset = regular_file(Path(os.environ.get(name, "")), name)
            hash_name = EMBEDDED_ASSET_HASHES.get(name)
            if hash_name:
                expected = os.environ.get(hash_name, "")
                if not SHA256.fullmatch(expected):
                    raise RunnerError(f"missing or invalid protected hash variable: {hash_name}")
                assert_hash(asset, expected, name)

        artifacts = work / "artifacts"
        evidence_dir = work / "evidence"
        artifacts.mkdir(mode=0o700)
        evidence_dir.mkdir(mode=0o700)
        binary_target = work / "target"
        build_env = dict(os.environ)
        build_env["CARGO_TARGET_DIR"] = str(binary_target)
        build_env["CARGO_HOME"] = str(work / "cargo-home")
        build_env["CARGO_INCREMENTAL"] = "0"
        build_env["TMPDIR"] = str(work / "tmp")
        build_env.pop("UPSTASH_BOX_API_KEY", None)
        build = run_command(
            work,
            "cargo-build",
            ["cargo", "build", "--release", "--locked", "-p", "boxd"],
            cwd=repo,
            env=build_env,
            timeout=1800,
        )
        if build.returncode != 0:
            raise RunnerError("boxd release build failed")
        binary = regular_file(binary_target / "release" / "boxd", "built boxd")

        input_paths = {
            "boxd": "inputs/boxd",
            "runtime": "inputs/runtime.bundle",
            "config": "inputs/boxd.toml",
            "sdk": "inputs/sdk-entry.js",
            "artifact": "inputs/release-artifact",
        }
        input_hashes = {
            "boxd": copy_input(binary, artifacts / input_paths["boxd"], "boxd", mode=0o700),
            "runtime": copy_input(args.runtime_bundle, artifacts / input_paths["runtime"], "runtime bundle"),
            "artifact": copy_input(args.artifact, artifacts / input_paths["artifact"], "release artifact"),
        }
        bound_binary = artifacts / input_paths["boxd"]
        bound_runtime = artifacts / input_paths["runtime"]
        bound_artifact = artifacts / input_paths["artifact"]
        daemon_env = dict(build_env)
        daemon_env["TMPDIR"] = str(work / "tmp")
        daemon_env["CARGO_HOME"] = str(work / "cargo-home")
        sdk, sdk_cleanup_token, sdk_metadata = build_pinned_sdk(work, repo, daemon_env)
        sdk_dir = sdk.parent
        sdk_hash = sdk_metadata["entry_sha256"]
        input_hashes["sdk"] = copy_input(sdk, artifacts / input_paths["sdk"], "pinned SDK entry")
        bound_sdk = artifacts / input_paths["sdk"]
        if input_hashes["sdk"] != sdk_hash:
            raise RunnerError("pinned SDK entry hash changed before evidence binding")
        template = work / "config-template.toml"
        copy_input(args.config, template, "config template")
        bootstrap_config = work / "bootstrap" / "boxd.toml"
        compatibility_key = initialize_database(work, bound_binary, bootstrap_config, daemon_env)
        assert_hash(bound_binary, input_hashes["boxd"], "bound boxd after init")
        data_dir = bootstrap_config.parent / "data"
        port = free_port()
        generated_config = work / "boxd.toml"
        replace_config(template, generated_config, data_dir, port)
        bootstrap_config.unlink()
        input_hashes["config"] = copy_input(generated_config, artifacts / input_paths["config"], "config")
        config = artifacts / input_paths["config"]
        daemon = Daemon(work, bound_binary, config, daemon_env, port)
        assert_hash(bound_binary, input_hashes["boxd"], "bound boxd")
        assert_hash(bound_sdk, input_hashes["sdk"], "bound SDK")
        assert_hash(bound_runtime, input_hashes["runtime"], "bound runtime bundle")
        assert_hash(bound_artifact, input_hashes["artifact"], "bound release artifact")
        assert_hash(config, input_hashes["config"], "bound config")
        config_validation = run_command(
            work,
            "config-validate",
            [str(bound_binary), "config", "validate", "--config", str(config)],
            cwd=repo,
            env=daemon_env,
            timeout=120,
        )
        if config_validation.returncode != 0:
            raise RunnerError("generated recovery config failed boxd config validation")
        import_result = run_command(
            work,
            "runtime-import",
            [str(bound_binary), "runtime", "import", "--config", str(config), str(artifacts / input_paths["runtime"])],
            cwd=repo,
            env=daemon_env,
            timeout=1800,
        )
        if import_result.returncode != 0:
            raise RunnerError("runtime import failed")
        doctor_result = run_command(
            work,
            "doctor",
            [str(bound_binary), "doctor", "--config", str(config), "--json"],
            cwd=repo,
            env=daemon_env,
            timeout=180,
        )
        if doctor_result.returncode != 0:
            raise RunnerError("boxd doctor failed")
        doctor = json.loads(doctor_result.stdout)
        if doctor.get("overall") is not True:
            raise RunnerError("boxd doctor did not report overall=true")
        assert_hash(bound_binary, input_hashes["boxd"], "bound boxd before serve")
        assert_hash(bound_sdk, input_hashes["sdk"], "bound SDK before serve")
        assert_hash(bound_runtime, input_hashes["runtime"], "bound runtime before serve")
        assert_hash(bound_artifact, input_hashes["artifact"], "bound release artifact before serve")

        api_env = dict(daemon_env)
        api_env["UPSTASH_BOX_BASE_URL"] = daemon.url
        api_env["TMPDIR"] = str(work / "tmp")
        api_env["UPSTASH_BOX_API_KEY"] = compatibility_key
        results: dict[str, dict[str, object]] = {}
        lifecycle_path = work / "lifecycle.json"

        lifecycle_started = int(time.time() * 1000)
        daemon.start("lifecycle")
        lifecycle = run_command(
            work,
            "sdk-lifecycle",
            ["node", str(repo / "scripts/phase1-sdk-smoke.mjs"), "lifecycle", str(bound_sdk), str(lifecycle_path)],
            cwd=repo,
            env=api_env,
            timeout=1200,
            redact_values=(compatibility_key,),
        )
        assert_hash(bound_binary, input_hashes["boxd"], "bound boxd after lifecycle")
        assert_hash(bound_sdk, input_hashes["sdk"], "bound SDK after lifecycle")
        assert_hash(config, input_hashes["config"], "bound config after lifecycle")
        stop_ok, stop_observed = daemon.stop()
        lifecycle_finished = int(time.time() * 1000)
        lifecycle_ok = lifecycle.returncode == 0 and stop_ok
        results["graceful-stop"] = case_result(
            "graceful-stop",
            "pass" if lifecycle_ok else "fail",
            "real boxd lifecycle completes and owned daemon stops cleanly",
            f"SDK lifecycle exit={lifecycle.returncode}; {stop_observed}",
            [
                step("sdk-lifecycle", "real lifecycle succeeds", f"exit={lifecycle.returncode}", "pass" if lifecycle.returncode == 0 else "fail"),
                step("daemon-stop", "daemon exits cleanly", stop_observed, "pass" if stop_ok else "fail"),
            ],
            lifecycle_started,
            lifecycle_finished,
        )

        restart_ok = False
        restart_observed = "lifecycle prerequisite unavailable"
        restart_started = int(time.time() * 1000)
        if lifecycle_ok and lifecycle_path.is_file():
            daemon.start("reconcile")
            restart = run_command(
                work,
                "sdk-restart-reconcile",
                ["node", str(repo / "scripts/phase1-sdk-smoke.mjs"), "restart", str(bound_sdk), str(work / "restart.json")],
                cwd=repo,
                env={**api_env, "BOXD_SMOKE_LIFECYCLE_EVIDENCE": str(lifecycle_path)},
                timeout=900,
                redact_values=(compatibility_key,),
            )
            assert_hash(bound_binary, input_hashes["boxd"], "bound boxd after restart")
            assert_hash(bound_sdk, input_hashes["sdk"], "bound SDK after restart")
            assert_hash(config, input_hashes["config"], "bound config after restart")
            restart_ok = restart.returncode == 0
            restart_observed = f"SDK restart/reconciliation exit={restart.returncode}"
            daemon.cleanup()
        restart_finished = int(time.time() * 1000)
        results["daemon-restart"] = case_result(
            "daemon-restart",
            "pass" if restart_ok else "fail",
            "real daemon restart reconciles persisted Box state and executes after restart",
            restart_observed,
            [step("daemon-restart-reconciliation", "persisted state and post-restart exec succeed", restart_observed, "pass" if restart_ok else "fail")],
            restart_started,
            restart_finished,
        )

        sigterm_started = int(time.time() * 1000)
        daemon.start("sigterm")
        sigterm_ok, sigterm_observed = daemon.stop(signal.SIGTERM)
        sigterm_finished = int(time.time() * 1000)
        results["sigterm"] = case_result(
            "sigterm",
            "pass" if sigterm_ok else "fail",
            "owned daemon exits cleanly on SIGTERM",
            sigterm_observed,
            [step("sigterm", "daemon exits cleanly", sigterm_observed, "pass" if sigterm_ok else "fail")],
            sigterm_started,
            sigterm_finished,
        )
        assert_hash(bound_binary, input_hashes["boxd"], "bound boxd after SIGTERM")
        assert_hash(bound_sdk, input_hashes["sdk"], "bound SDK after SIGTERM")
        assert_hash(bound_runtime, input_hashes["runtime"], "bound runtime after SIGTERM")
        assert_hash(bound_artifact, input_hashes["artifact"], "bound release artifact after SIGTERM")
        assert_hash(config, input_hashes["config"], "bound config after SIGTERM")

        data_tree = verify_data_tree(data_dir, work)
        database = data_dir / "boxd.sqlite3"
        database_check = verify_sqlite(database)

        blocked_reasons = {
            "worker-sigkill": "blocked: no safe runner-owned Box-to-worker fault injection contract",
            "disk-full": "blocked: filling a native runner filesystem is unsafe and non-reproducible",
            "runtime-pull-interruption": "blocked: runtime pull fault injection is not isolated from the runner",
            "sqlite-backup-restore": "blocked: no isolated production migration/restore scenario is available",
            "migration-journal": "blocked: forcing a failed production migration requires a dedicated migration scenario",
        }
        for scenario, reason in blocked_reasons.items():
            blocked_started = int(time.time() * 1000)
            blocked_finished = int(time.time() * 1000)
            results[scenario] = case_result(
                scenario,
                "blocked",
                "real recovery scenario requires a safe isolated fault-injection harness",
                reason,
                [step("fault-injection", "isolated trigger exists", reason, "blocked")],
                blocked_started,
                blocked_finished,
            )

        db_source = regular_file(database, "recovery SQLite database")
        input_paths["db"] = "inputs/boxd.sqlite3"
        input_hashes["db"] = copy_input(db_source, artifacts / input_paths["db"], "database")
        input_records = [{"name": name, "path": input_paths[name], "sha256": input_hashes[name]} for name in ("boxd", "runtime", "config", "sdk", "db", "artifact")]
        case_records = []
        for scenario in SCENARIOS:
            result = results[scenario]
            case_path = f"cases/{scenario}.json"
            artifact = {
                "schema": "boxd-phase4-recovery-artifact-v1",
                "scenario": scenario,
                "commit": commit,
                "platform": native,
                "input_hashes": input_hashes,
                "producer": "boxd-phase4-recovery-runner",
                "steps": result["steps"],
                "started_at_unix_ms": result["started_at_unix_ms"],
                "finished_at_unix_ms": result["finished_at_unix_ms"],
                "status": result["status"],
            }
            path = artifacts / case_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            path.chmod(0o600)
            case_hash = sha256(path)
            case_records.append(
                {
                    "scenario": result["scenario"],
                    "expected": result["expected"],
                    "observed": result["observed"],
                    "status": result["status"],
                    "artifact_path": case_path,
                    "artifact_sha256": case_hash,
                }
            )
        live_doc = {"schema": "boxd-phase4-recovery-v1", "mode": "live", "commit": commit, "platform": native, "inputs": input_records, "cases": case_records}
        live_path = artifacts / "recovery-input.json"
        live_path.write_text(json.dumps(live_doc, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        live_path.chmod(0o600)
        harness = repo / "scripts/phase4-recovery-harness.py"
        evidence_path = evidence_dir / "recovery-evidence.json"
        validation = run_command(
            work,
            "recovery-evidence",
            [sys.executable, str(harness), "--live", str(live_path), "--artifact-root", str(artifacts), "--emit-evidence", str(evidence_path), "--commit", commit],
            cwd=repo,
            env=daemon_env,
            timeout=120,
        )
        if validation.returncode != 0:
            raise RunnerError("live recovery evidence validation failed")
        shutil.copyfile(live_path, evidence_dir / "recovery-input.json")
        (evidence_dir / "recovery-input.json").chmod(0o600)
        (evidence_dir / "cases").mkdir(mode=0o700)
        for case in case_records:
            shutil.copyfile(artifacts / case["artifact_path"], evidence_dir / case["artifact_path"])
            (evidence_dir / case["artifact_path"]).chmod(0o600)
        metadata = {"schema": "boxd-phase4-native-recovery-run-v1", "commit": commit, "platform": native, "executed_boxd_sha256": input_hashes["boxd"], "runtime_sha256": input_hashes["runtime"], "config_sha256": input_hashes["config"], "db_sha256": input_hashes["db"], "release_artifact_sha256": input_hashes["artifact"], "sdk_sha256": input_hashes["sdk"], "doctor_overall": True, "database": database_check, "data_tree": data_tree, "evidence_sha256": sha256(evidence_path)}
        (evidence_dir / "native-recovery-summary.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (evidence_dir / "native-recovery-summary.json").chmod(0o600)
        print(json.dumps({"status": json.loads(evidence_path.read_text(encoding="utf-8"))["summary"]["status"], "evidence": str(evidence_path), "work_dir": str(work)}, indent=2))
        return 0
    except (OSError, RunnerError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        print(f"native recovery runner failed: {error}", file=sys.stderr)
        return 1
    finally:
        if daemon is not None:
            daemon.cleanup()
        cleanup_pinned_sdk(work if 'work' in locals() else args.work_dir, sdk_dir, sdk_cleanup_token)


if __name__ == "__main__":
    raise SystemExit(main())
