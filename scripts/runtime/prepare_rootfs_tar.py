#!/usr/bin/env python3
"""Normalize a pinned runtime OCI export and inject the current box-agent."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import posixpath
import tarfile
from pathlib import Path
from pathlib import PurePosixPath


def normalized_name(name: str) -> str:
    if "\x00" in name or name.startswith("/"):
        raise SystemExit(f"unsafe absolute OCI export entry: {name!r}")
    while name.startswith("./"):
        name = name[2:]
    parts = PurePosixPath(name).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise SystemExit(f"unsafe OCI export entry: {name!r}")
    return "/".join(parts)


def link_target(entry_name: str, target: str) -> str:
    if "\x00" in target or not target:
        raise SystemExit("unsafe empty or NUL-containing OCI symlink target")
    parent = posixpath.dirname(entry_name)
    if target.startswith("/"):
        guest_target = posixpath.normpath(target.lstrip("/"))
        return posixpath.relpath(guest_target, parent or ".")
    guest_target = posixpath.normpath(posixpath.join(parent, target))
    if guest_target == ".." or guest_target.startswith("../"):
        raise SystemExit(f"OCI symlink escapes guest root: {entry_name} -> {target}")
    return target


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int, uid: int, gid: int, epoch: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = uid
    info.gid = gid
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    archive.addfile(info, io.BytesIO(data))


def add_directory(archive: tarfile.TarFile, name: str, mode: int, uid: int, gid: int, epoch: int) -> None:
    info = tarfile.TarInfo(name.rstrip("/") + "/")
    info.type = tarfile.DIRTYPE
    info.mode = mode
    info.uid = uid
    info.gid = gid
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    archive.addfile(info)


def add_symlink(archive: tarfile.TarFile, name: str, target: str, epoch: int) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.mode = 0o777
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = epoch
    info.linkname = target
    archive.addfile(info)


def member_index(source: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    result: dict[str, tarfile.TarInfo] = {}
    for member in source.getmembers():
        name = normalized_name(member.name)
        if name in result:
            raise SystemExit(f"duplicate OCI export entry: {name}")
        result[name] = member
    return result


def regular_bytes(source: tarfile.TarFile, member: tarfile.TarInfo, name: str) -> bytes:
    if not (member.isfile() or member.islnk()):
        raise SystemExit(f"required OCI entry is not a regular file: {name}")
    stream = source.extractfile(member)
    if stream is None:
        raise SystemExit(f"cannot read OCI file: {name}")
    return stream.read()


def resolved_regular_bytes(
    source: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    member: tarfile.TarInfo,
    name: str,
    *,
    allow_missing_symlink_target: bool = False,
) -> bytes | None:
    current_name = name
    current = member
    visited: set[str] = set()
    for _ in range(16):
        if current.isfile() or current.islnk():
            return regular_bytes(source, current, current_name)
        if not current.issym():
            raise SystemExit(f"required OCI entry is not a regular file or safe symlink: {name}")
        if current_name in visited:
            raise SystemExit(f"OCI symlink cycle while resolving required file: {name}")
        visited.add(current_name)
        target = current.linkname
        if "\x00" in target or not target:
            raise SystemExit(f"unsafe OCI symlink while resolving required file: {name}")
        if target.startswith("/"):
            resolved = posixpath.normpath(target.lstrip("/"))
        else:
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(current_name), target))
        if resolved in {"", ".", ".."} or resolved.startswith("../"):
            raise SystemExit(f"OCI symlink escapes guest root while resolving required file: {name}")
        current_name = normalized_name(resolved)
        try:
            current = members[current_name]
        except KeyError as error:
            if allow_missing_symlink_target:
                return None
            raise SystemExit(f"OCI symlink target is missing while resolving required file: {name}") from error
    raise SystemExit(f"OCI symlink chain exceeds 16 entries while resolving required file: {name}")


def rewritten_accounts(
    source: tarfile.TarFile, members: dict[str, tarfile.TarInfo], source_user: str
) -> tuple[bytes, bytes]:
    try:
        passwd_member = members["etc/passwd"]
        group_member = members["etc/group"]
    except KeyError as error:
        raise SystemExit(f"pinned Node image is missing {error.args[0]}") from error
    passwd = regular_bytes(source, passwd_member, "etc/passwd").decode("utf-8")
    group = regular_bytes(source, group_member, "etc/group").decode("utf-8")
    passwd_lines = passwd.splitlines()
    group_lines = group.splitlines()
    source_users = [line for line in passwd_lines if line.startswith(f"{source_user}:x:1000:1000:")]
    source_groups = [line for line in group_lines if line.startswith(f"{source_user}:x:1000:")]
    box_users = [line for line in passwd_lines if line.startswith("boxuser:x:1000:1000:")]
    box_groups = [line for line in group_lines if line.startswith("boxuser:x:1000:")]
    uid_1000_users = [line for line in passwd_lines if len(line.split(":")) > 3 and line.split(":")[2:4] == ["1000", "1000"]]
    gid_1000_groups = [line for line in group_lines if len(line.split(":")) > 2 and line.split(":")[2] == "1000"]
    if (len(source_users), len(source_groups), len(box_users), len(box_groups)) not in {
        (1, 1, 0, 0),
        (0, 0, 1, 1),
        (0, 0, 0, 0),
    }:
        raise SystemExit(
            "pinned runtime image must contain exactly one uid/gid 1000 source user or boxuser"
        )
    if len(uid_1000_users) != len(source_users) + len(box_users) or len(gid_1000_groups) != len(source_groups) + len(box_groups):
        raise SystemExit("uid/gid 1000 is occupied by an unexpected runtime account")
    passwd_lines = [line for line in passwd_lines if not line.startswith(f"{source_user}:") and not line.startswith("boxuser:")]
    group_lines = [line for line in group_lines if not line.startswith(f"{source_user}:") and not line.startswith("boxuser:")]
    passwd_lines.append("boxuser:x:1000:1000:boxd runtime user:/home/boxuser:/bin/sh")
    group_lines.append("boxuser:x:1000:")
    return (
        ("\n".join(passwd_lines) + "\n").encode(),
        ("\n".join(group_lines) + "\n").encode(),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--oci-export", required=True, type=Path)
    parser.add_argument("--agent", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--family", choices=("debian", "alpine"), default="debian")
    parser.add_argument("--source-user", default="node")
    parser.add_argument("--runtime-license-source")
    parser.add_argument("--runtime-license-output", type=Path)
    parser.add_argument("--allow-missing-runtime-license", action="store_true")
    parser.add_argument("--browser-chromium-source")
    parser.add_argument("--browser-chromium-version")
    parser.add_argument("--package-status-output", type=Path)
    parser.add_argument("--os-licenses-output", type=Path)
    parser.add_argument("--os-licenses-index-output", type=Path)
    # Legacy aliases keep the reviewed Node builder stable while generic
    # publishers migrate to the neutral option names above.
    parser.add_argument("--node-license-output", type=Path)
    parser.add_argument("--dpkg-status-output", type=Path)
    parser.add_argument("--debian-licenses-output", type=Path)
    parser.add_argument("--debian-licenses-index-output", type=Path)
    parser.add_argument("--epoch", required=True, type=int)
    parser.add_argument("--release", required=True)
    args = parser.parse_args()
    package_status_output = args.dpkg_status_output or args.package_status_output
    os_licenses_output = args.debian_licenses_output or args.os_licenses_output
    os_licenses_index_output = args.debian_licenses_index_output or args.os_licenses_index_output
    runtime_license_output = args.node_license_output or args.runtime_license_output
    if not package_status_output or not os_licenses_output or not os_licenses_index_output:
        raise SystemExit("package status and OS license outputs are required")
    if args.runtime_license_source and not runtime_license_output:
        raise SystemExit("runtime license source requires an output path")
    if bool(args.browser_chromium_source) != bool(args.browser_chromium_version):
        raise SystemExit("browser Chromium source and version must be provided together")
    browser_root = (
        PurePosixPath(normalized_name(args.browser_chromium_source)).parent
        if args.browser_chromium_source
        else None
    )
    if args.epoch < 0 or "\n" in args.release or "\x00" in args.release:
        raise SystemExit("invalid deterministic build metadata")
    agent = args.agent.read_bytes()
    if not agent.startswith(b"\x7fELF"):
        raise SystemExit("box-agent is not an ELF executable")

    excluded = {"etc/passwd", "etc/group", "usr/local/bin/box-agent"}
    excluded_homes = {"home/node", "home/boxuser", f"home/{args.source_user}"}
    excluded_prefixes = tuple(f"{home}/" for home in sorted(excluded_homes)) + ("workspace/",)
    with tarfile.open(args.oci_export, "r:*") as source:
        members = member_index(source)
        passwd, group = rewritten_accounts(source, members, args.source_user)
        status_source = "var/lib/dpkg/status" if args.family == "debian" else "lib/apk/db/installed"
        required_files = {status_source: package_status_output}
        if args.runtime_license_source:
            required_files[normalized_name(args.runtime_license_source)] = runtime_license_output
        elif args.node_license_output:
            required_files["usr/local/LICENSE"] = args.node_license_output
        for name, destination in required_files.items():
            try:
                data = resolved_regular_bytes(source, members, members[name], name)
            except KeyError as error:
                if destination == runtime_license_output and args.allow_missing_runtime_license:
                    continue
                raise SystemExit(f"pinned runtime image is missing {name}") from error
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)

        os_licenses_output.parent.mkdir(parents=True, exist_ok=True)
        os_licenses: list[tuple[PurePosixPath, bytes]] = []
        for name, member in sorted(members.items()):
            if args.family == "debian":
                selected = name.startswith("usr/share/doc/") and name.endswith("/copyright")
                prefix = "usr/share/doc"
            else:
                selected = name.startswith("usr/share/licenses/") and not member.isdir()
                prefix = "usr/share/licenses"
            if not selected:
                continue
            data = resolved_regular_bytes(
                source,
                members,
                member,
                name,
                allow_missing_symlink_target=True,
            )
            if data is None:
                continue
            if len(data) > 4 * 1024 * 1024:
                raise SystemExit(f"Debian license file exceeds bundle limit: {name}")
            relative = PurePosixPath(name).relative_to(prefix)
            os_licenses.append((relative, data))
        if not os_licenses:
            raise SystemExit(f"pinned runtime image contains no {args.family} license files")
        license_index: list[dict[str, object]] = []
        with tarfile.open(os_licenses_output, "w", format=tarfile.GNU_FORMAT) as licenses:
            for relative, data in os_licenses:
                relative_name = relative.as_posix()
                if len(relative_name.encode("utf-8")) > 100:
                    raise SystemExit(f"Debian license path is too long: {relative_name}")
                info = tarfile.TarInfo(relative_name)
                info.size = len(data)
                info.mode = 0o444
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = args.epoch
                licenses.addfile(info, io.BytesIO(data))
                license_index.append(
                    {
                        "path": relative_name,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "size_bytes": len(data),
                        "mode": "0444",
                        "uid": 0,
                        "gid": 0,
                        "mtime": args.epoch,
                    }
                )
        os_licenses_index_output.write_text(
            json.dumps(
                {"format_version": 1, "files": license_index},
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )

        with tarfile.open(args.output, "w", format=tarfile.GNU_FORMAT) as output:
            for original in source.getmembers():
                name = normalized_name(original.name)
                if not name or name in excluded or name in excluded_homes or name == "workspace":
                    continue
                if any(name.startswith(prefix) for prefix in excluded_prefixes):
                    continue
                if original.ischr() or original.isblk() or original.isfifo():
                    raise SystemExit(f"unsupported special OCI export entry: {name}")
                if not (original.isfile() or original.islnk() or original.isdir() or original.issym()):
                    raise SystemExit(f"unsupported OCI export entry type: {name}")
                info = tarfile.TarInfo(name + ("/" if original.isdir() else ""))
                info.type = original.type
                info.mode = original.mode
                info.uid = original.uid
                info.gid = original.gid
                info.uname = ""
                info.gname = ""
                info.mtime = args.epoch
                info.linkname = link_target(name, original.linkname) if original.issym() else ""
                if browser_root and (
                    PurePosixPath(name) == browser_root or browser_root in PurePosixPath(name).parents
                ):
                    info.uid = 0
                    info.gid = 0
                    if original.isdir():
                        info.mode = 0o555
                    elif PurePosixPath(name).name == "chrome_sandbox":
                        info.mode = 0o4755
                    elif original.mode & 0o111:
                        info.mode = 0o555
                    else:
                        info.mode = 0o444
                if original.isfile() or original.islnk():
                    data = regular_bytes(source, original, name)
                    info.type = tarfile.REGTYPE
                    info.linkname = ""
                    info.size = len(data)
                    output.addfile(info, io.BytesIO(data))
                else:
                    output.addfile(info)

            add_bytes(output, "etc/passwd", passwd, 0o644, 0, 0, args.epoch)
            add_bytes(output, "etc/group", group, 0o644, 0, 0, args.epoch)
            add_bytes(output, "etc/boxd-runtime-release", (args.release + "\n").encode(), 0o644, 0, 0, args.epoch)
            add_bytes(output, "usr/local/bin/box-agent", agent, 0o755, 0, 0, args.epoch)
            if args.browser_chromium_source:
                source_name = normalized_name(args.browser_chromium_source)
                try:
                    chromium = regular_bytes(source, members[source_name], source_name)
                except KeyError as error:
                    raise SystemExit(f"pinned browser image is missing {source_name}") from error
                if not chromium.startswith(b"\x7fELF"):
                    raise SystemExit("browser Chromium executable is not ELF")
                add_symlink(
                    output,
                    "usr/bin/chromium",
                    posixpath.relpath(source_name, "usr/bin"),
                    args.epoch,
                )
                add_bytes(
                    output,
                    "etc/boxd-browser-release",
                    (f"chromium={args.browser_chromium_version}\n").encode(),
                    0o644,
                    0,
                    0,
                    args.epoch,
                )
            add_directory(output, "home/boxuser", 0o755, 1000, 1000, args.epoch)
            add_directory(output, "workspace", 0o755, 1000, 1000, args.epoch)
            add_directory(output, "workspace/home", 0o755, 1000, 1000, args.epoch)


if __name__ == "__main__":
    main()
