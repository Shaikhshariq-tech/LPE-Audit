"""Read-only checks for risky cron configuration permissions."""

from __future__ import annotations

import os
import platform
import stat
from pathlib import Path

from core.finding import Finding


DEFAULT_CRON_PATHS = (
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
)

MAX_ENTRIES = 10_000


def _incomplete_finding(message: str) -> Finding:
    """Create a standard finding that the coordinator recognizes."""
    return Finding(
        category="cron",
        title="cron scanner could not complete",
        description=message,
        severity="INFO",
        confidence="HIGH",
        detection_reason="The scanner reported incomplete audit coverage.",
        mitigation="Review the search paths and permissions, then rerun the scan.",
        scanner="cron",
    )


def _risky_permission_finding(path: Path, metadata: os.stat_result) -> Finding | None:
    """Return a finding when filesystem permissions match a risk rule."""
    mode = metadata.st_mode
    is_file = stat.S_ISREG(mode)
    is_dir = stat.S_ISDIR(mode)

    if not (is_file or is_dir):
        return None

    # Sticky directories have special deletion semantics and are not
    # automatically classified as unsafe cron configuration directories.
    if is_dir and mode & stat.S_ISVTX:
        return None

    world_writable = bool(mode & stat.S_IWOTH)
    group_writable = bool(mode & stat.S_IWGRP)

    risky = world_writable or (
        group_writable and metadata.st_uid == 0
    )
    if not risky:
        return None

    reasons = []
    if world_writable:
        reasons.append("world-writable")
    if group_writable and metadata.st_uid == 0:
        reasons.append("root-owned and group-writable")

    return Finding(
        category="cron",
        title="Potentially unsafe cron configuration permissions",
        description=(
            f"The cron-related path is {' and '.join(reasons)}. "
            "Confirm whether an untrusted user can modify it and whether "
            "a privileged scheduled task consumes it."
        ),
        severity="MEDIUM" if world_writable else "LOW",
        confidence="MEDIUM",
        affected_path=str(path),
        owner=str(metadata.st_uid),
        permissions=stat.filemode(mode),
        evidence=(
            f"path={path}; uid={metadata.st_uid}; "
            f"mode={stat.filemode(mode)}"
        ),
        detection_reason=(
            "Filesystem metadata matched a writable-permission rule."
        ),
        potential_impact=(
            "If the path controls a privileged scheduled job, unauthorized "
            "changes may affect commands run by that job."
        ),
        mitigation=(
            "Restrict write permissions to trusted administrators and review "
            "ownership and the scheduled task's execution context."
        ),
        scanner="cron",
    )


def scan_cron_jobs(
    search_paths: list[str] | None = None,
    max_entries: int = MAX_ENTRIES,
) -> list[Finding]:
    """Audit cron-related paths without changing the filesystem.

    Missing explicitly requested paths, filesystem access errors, traversal
    errors, and exhausted entry budgets are reported as incomplete scans.
    Missing optional default paths are ignored.
    """
    if platform.system() != "Linux" or os.name != "posix":
        return [
            Finding(
                category="cron",
                title="Cron scanner unavailable",
                description="Cron permission checks require Linux.",
                severity="INFO",
                confidence="HIGH",
                detection_reason="Unsupported operating system.",
                mitigation="Run the audit on Linux.",
                scanner="cron",
            )
        ]

    explicit_search_paths = search_paths is not None
    roots = list(
        DEFAULT_CRON_PATHS if search_paths is None else search_paths
    )

    if not roots:
        return []

    # Keep the limit positive, matching the project's existing scanner style.
    max_entries = max(1, int(max_entries))

    findings: list[Finding] = []
    seen_paths: set[str] = set()
    inspected = 0
    error_count = 0
    limit_reached = False
    stop_scanning = False

    def record_walk_error(_error: OSError) -> None:
        """Record traversal errors without exposing sensitive path details."""
        nonlocal error_count
        error_count += 1

    def inspect(path: Path, metadata: os.stat_result | None = None) -> bool:
        """Inspect one unique path; return False if the budget is exhausted."""
        nonlocal inspected, error_count, limit_reached

        key = str(path)
        if key in seen_paths:
            return True

        if inspected >= max_entries:
            limit_reached = True
            return False

        seen_paths.add(key)
        inspected += 1

        try:
            if metadata is None:
                metadata = path.lstat()
        except OSError:
            error_count += 1
            return True

        # Do not follow or report symlinks as ordinary cron configuration.
        if stat.S_ISLNK(metadata.st_mode):
            return True

        finding = _risky_permission_finding(path, metadata)
        if finding is not None:
            findings.append(finding)

        return True

    for root_string in roots:
        root = Path(root_string)

        try:
            root_metadata = root.lstat()
        except FileNotFoundError:
            # Optional default locations may not exist on every Linux system.
            if explicit_search_paths:
                error_count += 1
            continue
        except OSError:
            error_count += 1
            continue

        if not inspect(root, root_metadata):
            limit_reached = True
            break

        # A symlink or regular-file root is inspected but never traversed.
        if (
            stat.S_ISLNK(root_metadata.st_mode)
            or not stat.S_ISDIR(root_metadata.st_mode)
        ):
            continue

        try:
            for current_root, directories, files in os.walk(
                root,
                topdown=True,
                followlinks=False,
                onerror=record_walk_error,
            ):
                current = Path(current_root)

                # Remove symlinked directories before os.walk descends into them.
                directories[:] = [
                    name
                    for name in directories
                    if not (current / name).is_symlink()
                ]

                # Inspect child directories and files. The root itself was
                # already inspected above.
                for name in (*directories, *files):
                    if not inspect(current / name):
                        stop_scanning = True
                        break

                if stop_scanning:
                    break

        except OSError:
            error_count += 1
            stop_scanning = True

        if stop_scanning:
            break

    if error_count or limit_reached:
        reasons = []

        if error_count:
            reasons.append(
                f"{error_count} filesystem access or traversal error(s)"
            )

        if limit_reached:
            reasons.append(
                f"the maximum entry limit of {max_entries} was reached "
                "before all requested paths could be inspected"
            )

        findings.append(
            _incomplete_finding(
                "Cron scan was incomplete because "
                + " and ".join(reasons)
                + ". Review the search paths and rerun the scan."
            )
        )

    return findings
