#!/usr/bin/env python3
"""Run one command in an owned process group with a hard timeout."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def terminate_group(process: subprocess.Popen[bytes], grace_seconds: float) -> None:
    process.poll()
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (PermissionError, ProcessLookupError):
        return
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except (PermissionError, ProcessLookupError):
            return
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (PermissionError, ProcessLookupError):
        return
    if process.poll() is None:
        process.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, required=True, help="positive total seconds")
    parser.add_argument("--grace", type=float, default=5.0, help="non-negative TERM grace seconds")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if args.timeout <= 0 or args.grace < 0 or not command:
        parser.error("a command, positive timeout, and non-negative grace are required")

    process = subprocess.Popen(command, start_new_session=True)
    interrupted: int | None = None

    def handle_signal(signum: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = signum
        terminate_group(process, args.grace)

    previous = {
        signum: signal.signal(signum, handle_signal)
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    }
    try:
        deadline = time.monotonic() + args.timeout
        while True:
            if interrupted is not None:
                return 128 + interrupted
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_group(process, args.grace)
                name = Path(command[0]).name
                print(f"bounded command timed out after {args.timeout:g}s: {name}", file=sys.stderr)
                return 124
            try:
                status = process.wait(timeout=min(remaining, 1.0))
                return 128 + interrupted if interrupted is not None else status
            except subprocess.TimeoutExpired:
                continue
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        terminate_group(process, args.grace)


if __name__ == "__main__":
    raise SystemExit(main())
