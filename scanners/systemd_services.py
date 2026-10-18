"""Read-only audit of systemd unit-file permissions."""

from __future__ import annotations

import os
import platform
import stat
from pathlib import Path

from core.finding import Finding
from core.risk_engine import RiskEngine

DEFAULT_SEARCH_PATHS = (
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
)
UNIT_SUFFIXES = (
    ".service", ".socket", ".timer", ".path", ".target",
    ".mount", ".automount", ".slice", ".scope",
)
MAX_ENTRIES = 30_000


def scan_systemd_services(
    search_paths: list[str] | None = None,
    max_entries: int = MAX_ENTRIES,
) -> list[Finding]:
    """Find writable systemd unit files and directories without following links."""
    if platform.system() != "Linux":
        return [Finding(
            category="services",
            title="Systemd permission scanner unavailable",
            description="This scanner is intended for Linux systems.",
            severity="INFO",
            confidence="HIGH",
            detection_reason="Unsupported operating system.",
            mitigation="Run the audit on a Linux system.",
            scanner="services",
        )]

    roots = DEFAULT_SEARCH_PATHS if search_paths is None else search_paths
    limit = max(1, int(max_entries))
    findings: list[Finding] = []
    inspected = 0
    seen: set[tuple[int, int]] = set()
    limit_reached = False

    def inspect(path: Path) -> None:
        nonlocal inspected, limit_reached
        if inspected >= limit:
            limit_reached = True
            return

        try:
            metadata = path.lstat()
        except OSError:
            return

        if stat.S_ISLNK(metadata.st_mode):
            return

        mode = metadata.st_mode
        is_file = stat.S_ISREG(mode)
        is_dir = stat.S_ISDIR(mode)
        if not (is_file or is_dir):
            return

        if is_file and not path.name.endswith(UNIT_SUFFIXES):
            return

        inspected += 1
        if inspected >= limit:
            limit_reached = True

        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen:
            return
        seen.add(identity)

        world_writable = bool(mode & stat.S_IWOTH)
        root_group_writable = (
            metadata.st_uid == 0 and bool(mode & stat.S_IWGRP)
        )

        if is_dir and mode & stat.S_ISVTX:
            return
        if not (world_writable or root_group_writable):
            return

        reasons = []
        if world_writable:
            reasons.append("world-writable")
        if root_group_writable:
            reasons.append("root-owned and group-writable")

        finding = Finding(
            category="services",
            title="Potentially unsafe systemd permissions",
            description=(
                f"{path} is {' and '.join(reasons)}. Verify whether "
                "untrusted users can change a unit or a relevant directory."
            ),
            severity="HIGH" if world_writable else "MEDIUM",
            confidence="MEDIUM",
            affected_path=str(path),
            owner=str(metadata.st_uid),
            permissions=stat.filemode(mode),
            evidence=(
                f"path={path}; uid={metadata.st_uid}; gid={metadata.st_gid}; "
                f"mode={oct(stat.S_IMODE(mode))}"
            ),
            detection_reason=(
                "Filesystem metadata matched a writable systemd-path rule."
            ),
            potential_impact=(
                "If an affected unit or directory is consumed by a privileged "
                "service manager, unauthorized changes could alter service behavior."
            ),
            attack_path_description=(
                "Review the unit, its parent directories, ownership, and service "
                "execution context. This permission finding alone does not prove "
                "a privilege-escalation path."
            ),
            mitigation=(
                "Restrict write access to trusted administrators and validate "
                "service ownership and directory permissions."
            ),
            scanner="services",
        )
        RiskEngine.apply(
            finding,
            privileged_context=(metadata.st_uid == 0),
            writable_by_unprivileged=world_writable,
        )
        findings.append(finding)

    for root_string in roots:
        root = Path(root_string)
        if not root.exists() or root.is_symlink():
            continue

        inspect(root)
        if root.is_dir() and not root.is_symlink():
            try:
                for current, directories, files in os.walk(
                    root, topdown=True, followlinks=False
                ):
                    current_path = Path(current)
                    directories[:] = [
                        name for name in directories
                        if not (current_path / name).is_symlink()
                    ]
                    for name in directories:
                        inspect(current_path / name)
                        if inspected >= limit:
                            limit_reached = True
                            break
                    if inspected >= limit:
                        break

                    for name in files:
                        inspect(current_path / name)
                        if inspected >= limit:
                            limit_reached = True
                            break
                    if inspected >= limit:
                        break
            except OSError:
                continue

        if inspected >= limit:
            limit_reached = True
            break

    if limit_reached:
        findings.append(Finding(
            category="services",
            title="Systemd scan reached its entry limit",
            description=f"Inspection stopped at the safety limit of {limit} entries.",
            severity="INFO",
            confidence="HIGH",
            detection_reason="The configured limit prevented unbounded traversal.",
            mitigation="Review search paths or increase the limit deliberately.",
            scanner="services",
        ))

    return findings
