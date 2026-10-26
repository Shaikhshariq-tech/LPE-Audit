"""Read-only checks for weak filesystem permissions."""

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
    """Sticky world-writable directories restrict deletion by other users."""
    return stat.S_ISDIR(mode) and bool(mode & stat.S_ISVTX)


class PermissionsScanner(Scanner):
    name = "permissions"

    def __init__(
        self,
        search_paths: list[str] | None = None,
        max_entries: int = MAX_ENTRIES,
    ) -> None:
        self.explicit_search_paths = search_paths is not None
        self.search_paths = list(
            DEFAULT_SEARCH_PATHS if search_paths is None else search_paths
        )
        self.max_entries = max(1, int(max_entries))

    def scan(self) -> list[Finding]:
        if platform.system().lower() != "linux":
            return [
                self.unavailable_finding(
                    "This permissions scanner is designed for Linux."
                )
            ]

        # An explicit empty scope means there is nothing to scan.
        if not self.search_paths:
            return []

        findings: list[Finding] = []
        seen: set[tuple[int, int]] = set()
        inspected = 0
        error_count = 0
        limit_reached = False

        def record_walk_error(_error: OSError) -> None:
            """Record traversal errors without exposing sensitive path data."""
            nonlocal error_count
            error_count += 1

        def inspect(path: Path) -> bool:
            """Inspect one path. Return False when the entry budget is exceeded."""
            nonlocal inspected, error_count, limit_reached

            if inspected >= self.max_entries:
                limit_reached = True
                return False

            inspected += 1

            try:
                metadata = path.lstat()
            except OSError:
                error_count += 1
                return True

            # Never follow or report symbolic links as ordinary files.
            if stat.S_ISLNK(metadata.st_mode):
                return True

            mode = metadata.st_mode
            is_dir = stat.S_ISDIR(mode)
            is_file = stat.S_ISREG(mode)

            if not (is_dir or is_file):
                return True

            world_writable = bool(mode & stat.S_IWOTH)
            root_group_writable_file = (
                is_file
                and metadata.st_uid == 0
                and bool(mode & stat.S_IWGRP)
            )

            # Sticky world-writable directories are intentionally excluded.
            if world_writable and _ignored_sticky_directory(mode):
                return True

            if not world_writable and not root_group_writable_file:
                return True

            identity = (metadata.st_dev, metadata.st_ino)
            if identity in seen:
                return True
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
            return True

        for root_string in self.search_paths:
            root = Path(root_string)

            try:
                root_metadata = root.lstat()
            except FileNotFoundError:
                # Optional default paths may legitimately be absent.
                if self.explicit_search_paths:
                    error_count += 1
                continue
            except OSError:
                error_count += 1
                continue

            # A root symlink is not a traversal target.
            if stat.S_ISLNK(root_metadata.st_mode):
                if not inspect(root):
                    break
                continue

            if not inspect(root):
                break

            # Regular-file roots are inspected directly, without walking.
            if not stat.S_ISDIR(root_metadata.st_mode):
                continue

            stop_traversal = False

            try:
                for current_root, directories, files in os.walk(
                    root,
                    topdown=True,
                    followlinks=False,
                    onerror=record_walk_error,
                ):
                    current = Path(current_root)

                    # Do not descend into symlinked directories.
                    directories[:] = [
                        name
                        for name in directories
                        if not (current / name).is_symlink()
                    ]

                    for name in directories:
                        if not inspect(current / name):
                            stop_traversal = True
                            break

                    if stop_traversal:
                        break

                    for name in files:
                        if not inspect(current / name):
                            stop_traversal = True
                            break

                    if stop_traversal:
                        break

            except OSError:
                error_count += 1
                stop_traversal = True

            if stop_traversal:
                break

        if error_count or limit_reached:
            reasons = []
            if error_count:
                reasons.append(
                    f"{error_count} filesystem access or traversal error(s)"
                )
            if limit_reached:
                reasons.append(
                    f"the maximum entry limit of {self.max_entries} was reached "
                    "before all requested paths could be inspected"
                )

            findings.append(
                self._error_finding(
                    "Permissions scan was incomplete because "
                    + " and ".join(reasons)
                    + ". Review the search paths and rerun the scan."
                )
            )

        return findings


def scan_weak_permissions(
    search_paths: list[str] | None = None,
    max_entries: int = MAX_ENTRIES,
) -> list[Finding]:
    """Public function interface used by the CLI and tests."""
    return PermissionsScanner(search_paths, max_entries).run()
