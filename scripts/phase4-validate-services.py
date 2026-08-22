#!/usr/bin/env python3
"""Statically validate the reviewed boxd systemd and launchd templates."""

from __future__ import annotations

import argparse
import configparser
import plistlib
import sys
from pathlib import Path
from typing import Any


class ServiceError(ValueError):
    pass


def validate_systemd(path: Path) -> None:
    try:
        raw_unit = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ServiceError(f"invalid systemd unit: {error}") from error
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    try:
        parser.read_string(raw_unit)
    except configparser.Error as error:
        raise ServiceError(f"invalid systemd unit: {error}") from error
    if set(parser.sections()) != {"Unit", "Service", "Install"}:
        raise ServiceError("systemd unit must contain exactly Unit, Service, and Install")
    expected_unit = {
        "Description": "boxd sandbox service",
        "After": "network-online.target",
        "Wants": "network-online.target",
    }
    if dict(parser["Unit"]) != expected_unit:
        raise ServiceError("systemd Unit section has unreviewed or missing settings")
    required = {
        "Type": "simple",
        "User": "boxd",
        "Group": "boxd",
        "WorkingDirectory": "/var/lib/boxd",
        "ExecStart": "/usr/local/bin/boxd serve -c /etc/boxd/boxd.toml",
        "Restart": "on-failure",
        "RestartSec": "5s",
        "NoNewPrivileges": "true",
        "PrivateTmp": "true",
        "ProtectSystem": "strict",
        "ProtectHome": "true",
        "ProtectKernelTunables": "true",
        "ProtectKernelModules": "true",
        "ProtectControlGroups": "true",
        "RestrictSUIDSGID": "true",
        "LockPersonality": "true",
        "DevicePolicy": "closed",
        "ReadWritePaths": "/var/lib/boxd",
    }
    service = parser["Service"]
    allowed_service_keys = set(required) | {"LimitNOFILE", "DeviceAllow"}
    unknown_service_keys = set(service) - allowed_service_keys
    if unknown_service_keys:
        raise ServiceError(f"systemd unit has unreviewed Service keys: {', '.join(sorted(unknown_service_keys))}")
    for key, expected in required.items():
        if service.get(key) != expected:
            raise ServiceError(f"systemd Service.{key} must be {expected!r}")
    try:
        if int(service.get("LimitNOFILE", "0")) < 65536:
            raise ServiceError("systemd LimitNOFILE must be at least 65536")
    except ValueError as error:
        raise ServiceError("systemd LimitNOFILE must be an integer") from error
    if any(character in service["ExecStart"] for character in (";", "|", "`", "$", "\n")):
        raise ServiceError("systemd ExecStart must not invoke shell syntax")
    device_rules = [line.strip() for line in raw_unit.splitlines() if line.startswith("DeviceAllow=")]
    if device_rules != ["DeviceAllow=/dev/kvm rw", "DeviceAllow=/dev/net/tun rw"]:
        raise ServiceError("systemd DeviceAllow must bind exactly /dev/kvm and /dev/net/tun read-write")
    if dict(parser["Install"]) != {"WantedBy": "multi-user.target"}:
        raise ServiceError("systemd unit must install into multi-user.target")


def exact_type(value: Any, expected: type, where: str) -> Any:
    if type(value) is not expected:
        raise ServiceError(f"launchd {where} must be {expected.__name__}")
    return value


def validate_launchd(path: Path) -> None:
    try:
        with path.open("rb") as source:
            document = plistlib.load(source)
    except (OSError, plistlib.InvalidFileException) as error:
        raise ServiceError(f"invalid launchd plist: {error}") from error
    exact_type(document, dict, "root")
    allowed = {
        "Label", "ProgramArguments", "UserName", "GroupName", "WorkingDirectory", "RunAtLoad",
        "KeepAlive", "ProcessType", "SoftResourceLimits", "StandardOutPath", "StandardErrorPath",
    }
    unknown = set(document) - allowed
    if unknown:
        raise ServiceError(f"launchd plist has unreviewed keys: {', '.join(sorted(unknown))}")
    expected = {
        "Label": "com.payhon.boxd",
        "ProgramArguments": [
            "/usr/local/bin/boxd", "serve", "-c", "/Library/Application Support/boxd/boxd.toml",
        ],
        "UserName": "boxd",
        "GroupName": "boxd",
        "WorkingDirectory": "/Library/Application Support/boxd",
        "RunAtLoad": True,
        "KeepAlive": {"SuccessfulExit": False},
        "ProcessType": "Background",
        "SoftResourceLimits": {"NumberOfFiles": 1048576},
        "StandardOutPath": "/var/log/boxd/boxd.stdout.log",
        "StandardErrorPath": "/var/log/boxd/boxd.stderr.log",
    }
    if document != expected:
        missing = set(expected) - set(document)
        drift = {key for key in set(expected) & set(document) if document[key] != expected[key]}
        raise ServiceError(f"launchd template drift; missing={sorted(missing)}, changed={sorted(drift)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--systemd", required=True, type=Path)
    parser.add_argument("--launchd", required=True, type=Path)
    args = parser.parse_args()
    try:
        validate_systemd(args.systemd)
        validate_launchd(args.launchd)
    except ServiceError as error:
        print(f"service template validation failed: {error}", file=sys.stderr)
        return 1
    print("service template validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
