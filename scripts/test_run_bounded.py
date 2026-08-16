#!/usr/bin/env python3
"""Hermetic regression tests for scripts/run_bounded.py."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


RUNNER = Path(__file__).resolve().parent / "run_bounded.py"


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def main() -> None:
    completed = subprocess.run(
        [sys.executable, str(RUNNER), "--timeout", "2", "--", sys.executable, "-c", "raise SystemExit(7)"],
        check=False,
    )
    assert completed.returncode == 7

    interrupted = subprocess.Popen(
        [sys.executable, str(RUNNER), "--timeout", "10", "--", sys.executable, "-c", "import time; time.sleep(60)"]
    )
    time.sleep(0.5)
    interrupted.send_signal(signal.SIGTERM)
    assert interrupted.wait(timeout=3) == 128 + signal.SIGTERM

    with tempfile.TemporaryDirectory(prefix="boxd-bounded-runner-") as raw:
        pid_path = Path(raw) / "child.pid"
        child_program = (
            "import os,pathlib,signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)"
        )
        parent_program = "\n".join(
            (
                "import pathlib,subprocess,sys,time",
                "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])",
                "path=pathlib.Path(sys.argv[2])",
                "deadline=time.monotonic()+2",
                "while not path.exists() and time.monotonic()<deadline: time.sleep(0.01)",
                "if not path.exists(): raise SystemExit('child did not become ready')",
                "time.sleep(60)",
            )
        )
        timed_out = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--timeout",
                "2",
                "--grace",
                "0.1",
                "--",
                sys.executable,
                "-c",
                parent_program,
                child_program,
                str(pid_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert timed_out.returncode == 124
        assert "bounded command timed out" in timed_out.stderr
        child_pid = int(pid_path.read_text(encoding="utf-8"))
        for _ in range(50):
            if not process_exists(child_pid):
                break
            time.sleep(0.02)
        assert not process_exists(child_pid), "timed-out descendant survived its owned process group"

    print("bounded command runner tests passed")


if __name__ == "__main__":
    main()
