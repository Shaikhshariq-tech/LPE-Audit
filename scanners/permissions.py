"""Read-only checks for world-writable and root-owned group-writable paths."""

from __future__ import annotations

import os
import platform
import stat
from pathlib import Path

from core.finding import Finding
from core.risk_engine import RiskEngine
from core.scanner import Scanner


DEFAULT_SEARCH_PATHS = [
    "/etc",
    "/opt",
    "/usr/local/bin",
    "/usr/local/sbin",
]

MAX_ENTRIES = 100_000


def _ignored_sticky_directory(mode: int) -> bool:
    """Sticky world-writable directories restrict who can delete entries."""
    return stat.S_ISDIR(mode) and bool(mode & stat.S_ISVTX)


class PermissionsScanner(Scanner):
    name = "permissions"

    def __init__(
        self,
        search_paths: list[str] | None = None,
        max_entries: int = MAX_ENTRIES,
    ) -> None:
        self.search_paths = search_paths or DEFAULT_SEARCH_PATHS
        self.max_entries = max(1, int(max_entries))

    def scan(self) -> list[Finding]:
        if platform.system().lower() != "linux":
            return [self.unavailable_finding(
                "This permissions scanner is designed for Linux."
            )]

        findings: list[Finding] = []
        seen: set[tuple[int, int]] = set()
        inspected = 0

        def inspect(path: Path) -> None:
            nonlocal inspected
            if inspected >= self.max_entries:
                return

            try:
                metadata = path.lstat()
            except OSError:
                return

            # Do not follow symbolic links.
            if stat.S_ISLNK(metadata.st_mode):
                return

            inspected += 1
            mode = metadata.st_mode
            is_dir = stat.S_ISDIR(mode)
            is_file = stat.S_ISREG(mode)
            if not (is_dir or is_file):
                return

            world_writable = bool(mode & stat.S_IWOTH)
            root_group_writable_file = (
                is_file and metadata.st_uid == 0 and bool(mode & stat.S_IWGRP)
            )

            if world_writable and _ignored_sticky_directory(mode):
                return
            if not world_writable and not root_group_writable_file:
                return

            identity = (metadata.st_dev, metadata.st_ino)
            if identity in seen:
                return
            seen.add(identity)

            if world_writable and is_file and metadata.st_uid == 0:
                severity = "HIGH"
            elif world_writable:
                severity = "MEDIUM"
            else:
                severity = "MEDIUM"

            reasons = []
            if world_writable:
                reasons.append("world-writable")
            if root_group_writable_file:
                reasons.append("group-writable file owned by root")

            finding = Finding(
                category=self.name,
                title=f"Potentially weak permissions: {path.name or str(path)}",
                description=f"Review the access permissions on {path}.",
                severity=severity,
                confidence="HIGH",
                affected_path=str(path),
                owner=str(metadata.st_uid),
                permissions=stat.filemode(mode),
                evidence=(
                    f"mode={oct(stat.S_IMODE(mode))}; "
                    f"permissions={stat.filemode(mode)}; "
                    f"uid={metadata.st_uid}; gid={metadata.st_gid}"
                ),
                detection_reason="The path is " + " and ".join(reasons) + ".",
                potential_impact=(
                    "Unexpected write access may allow unauthorized modification "
                    "of files or directories used by system services."
                ),
                attack_path_description=(
                    "Verify intended ownership, write access, parent-directory "
                    "permissions, and service dependencies. This finding is a "
                    "configuration warning, not proof of privilege escalation."
                ),
                mitigation=(
                    "Restrict write permissions to authorized users or groups and "
                    "confirm that the application's required access still works."
                ),
                scanner=self.name,
            )
            RiskEngine.apply(
                finding,
                privileged_context=(metadata.st_uid == 0),
                writable_by_unprivileged=world_writable,
            )
            findings.append(finding)

        for root_string in self.search_paths:
            root = Path(root_string)
            if not root.exists():
                continue

            inspect(root)
            if root.is_file() or root.is_symlink():
                continue

            try:
                for current_root, directories, files in os.walk(
                    root, topdown=True, followlinks=False
                ):
                    current = Path(current_root)
                    directories[:] = [
                        name for name in directories
                        if not (current / name).is_symlink()
                    ]

                    for name in directories:
                        inspect(current / name)
                        if inspected >= self.max_entries:
                            break

                    for name in files:
                        inspect(current / name)
                        if inspected >= self.max_entries:
                            break

                    if inspected >= self.max_entries:
                        break
            except OSError:
                continue

            if inspected >= self.max_entries:
                break

        return findings


def scan_weak_permissions(
    search_paths: list[str] | None = None,
    max_entries: int = MAX_ENTRIES,
) -> list[Finding]:
    """Public function interface used by the CLI and tests."""
    return PermissionsScanner(search_paths, max_entries).run()
