#!/usr/bin/env python3
"""Probe the host KVM device; this does not start boxd or a guest VM."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import platform
import stat
import sys
from pathlib import Path
from typing import Any, Callable

KVM_GET_API_VERSION = 0xAE00
EXPECTED_API_VERSION = 12
BLOCKED_EXIT = 77


class ProbeBlocked(Exception):
    """An expected host capability is unavailable or does not match."""


def _api_version(ioctl: Callable[..., Any], fd: int) -> int:
    value = ioctl(fd, KVM_GET_API_VERSION, 0)
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, byteorder=sys.byteorder, signed=True)
    raise ProbeBlocked("KVM_GET_API_VERSION returned an unsupported value")


def probe(
    *,
    system: str | None = None,
    machine: str | None = None,
    device: str | os.PathLike[str] = "/dev/kvm",
    stat_fn: Callable[[str | os.PathLike[str]], os.stat_result] = os.stat,
    open_fn: Callable[..., int] = os.open,
    ioctl_fn: Callable[..., Any] = fcntl.ioctl,
    close_fn: Callable[[int], None] = os.close,
) -> dict[str, Any]:
    system = system or platform.system()
    machine = machine or platform.machine()
    result: dict[str, Any] = {
        "schema_version": 1,
        "status": "blocked",
        "probe": "host-kvm-api",
        "system": system,
        "architecture": machine,
        "device": str(device),
        "checks": {},
    }
    try:
        if system != "Linux":
            raise ProbeBlocked(f"Linux required; detected {system}")
        result["checks"]["linux"] = "pass"
        if machine not in {"x86_64", "aarch64"}:
            raise ProbeBlocked(f"unsupported architecture: {machine}")
        result["checks"]["architecture"] = "pass"
        try:
            device_stat = stat_fn(device)
        except OSError as exc:
            raise ProbeBlocked(f"cannot stat {device}: {exc.strerror or exc}") from exc
        if not stat.S_ISCHR(device_stat.st_mode):
            raise ProbeBlocked(f"{device} is not a character device")
        result["checks"]["character_device"] = "pass"
        try:
            fd = open_fn(device, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        except OSError as exc:
            raise ProbeBlocked(f"cannot open {device} O_RDWR: {exc.strerror or exc}") from exc
        try:
            result["checks"]["open_rdwr"] = "pass"
            try:
                version = _api_version(ioctl_fn, fd)
            except OSError as exc:
                raise ProbeBlocked(f"KVM_GET_API_VERSION failed: {exc.strerror or exc}") from exc
            result["kvm_api_version"] = version
            if version != EXPECTED_API_VERSION:
                raise ProbeBlocked(f"KVM API version {version}, expected {EXPECTED_API_VERSION}")
            result["checks"]["kvm_api_version"] = "pass"
        finally:
            close_fn(fd)
        result["status"] = "pass"
    except ProbeBlocked as exc:
        result["blocked_reason"] = str(exc)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = probe()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "pass" else BLOCKED_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
