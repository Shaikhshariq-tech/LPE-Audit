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
    ".service",
    ".socket",
    ".timer",
    ".path",
    ".target",
    ".mount",
    ".automount",
    ".slice",
    ".scope",
)

MAX_ENTRIES = 30_000
INCOMPLETE_TITLE = "services scanner could not complete"


def scan_systemd_services(
    search_paths: list[str] | None = None,
    max_entries: int = MAX_ENTRIES,
) -> list[Finding]:
    """Find potentially unsafe systemd permissions without following links.

    Missing optional default paths are ignored. Missing explicitly supplied
    paths, filesystem traversal errors, and exhausted entry budgets are
    reported as incomplete scans.
    """
    if platform.system() != "Linux":
        return [
            Finding(
                category="services",
                title="Systemd permission scanner unavailable",
                description="This scanner is intended for Linux systems.",
                severity="INFO",
                confidence="HIGH",
                detection_reason="Unsupported operating system.",
                mitigation="Run the audit on a Linux system.",
                scanner="services",
            )
        ]

    explicit_paths = search_paths is not None
    roots = (
        tuple(search_paths)
        if explicit_paths
        else DEFAULT_SEARCH_PATHS
    )
    limit = max(1, int(max_entries))

    findings: list[Finding] = []
    inspected = 0
    seen: set[tuple[int, int]] = set()
    incomplete_reasons: list[str] = []
    limit_reached = False

    def mark_incomplete(reason: str) -> None:
        if reason not in incomplete_reasons:
            incomplete_reasons.append(reason)

    def inspect(path: Path) -> None:
        """Inspect one eligible directory or unit file."""
        nonlocal inspected, limit_reached

        try:
            metadata = path.lstat()
        except OSError as exc:
            mark_incomplete(f"Could not inspect {path} ({type(exc).__name__}).")
            return

        # Never follow symbolic links.
        if stat.S_ISLNK(metadata.st_mode):
            return

        mode = metadata.st_mode
        is_file = stat.S_ISREG(mode)
        is_dir = stat.S_ISDIR(mode)

        if not (is_file or is_dir):
            return

        if is_file and not path.name.endswith(UNIT_SUFFIXES):
            return

        identity = (metadata.st_dev, metadata.st_ino)
        if identity in seen:
            return
        seen.add(identity)

        # Only declare the limit exhausted when another eligible entry
        # actually needs to be inspected. This avoids a false warning when
        # the scan completes with exactly `limit` entries.
        if inspected >= limit:
            limit_reached = True
            return

        inspected += 1

        world_writable = bool(mode & stat.S_IWOTH)
        root_group_writable = (
            metadata.st_uid == 0 and bool(mode & stat.S_IWGRP)
        )

        # A sticky bit does not prevent creating a new entry in a writable
        # directory. Such directories can still be relevant to unit-file risk.
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

        try:
            root_metadata = root.lstat()
        except FileNotFoundError:
            if explicit_paths:
                mark_incomplete(f"Explicit search path does not exist: {root}")
            continue
        except OSError as exc:
            if explicit_paths:
                mark_incomplete(f"Could not inspect search path {root} ({type(exc).__name__}).")
            continue

        if stat.S_ISLNK(root_metadata.st_mode):
            if explicit_paths:
                mark_incomplete(
                    f"Explicit search path is a symbolic link and was not followed: {root}"
                )
            continue

        if not (
            stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_ISREG(root_metadata.st_mode)
        ):
            if explicit_paths:
                mark_incomplete(f"Explicit search path is not a regular file or directory: {root}")
            continue

        # A root directory is counted once. For a file root, inspect it
        # directly and let the normal suffix and permission rules apply.
        inspect(root)

        if limit_reached:
            break

        if not stat.S_ISDIR(root_metadata.st_mode):
            continue

        def walk_error(exc: OSError) -> None:
            mark_incomplete(f"Filesystem traversal failed ({type(exc).__name__}).")

        try:
            for current, directories, files in os.walk(
                root,
                topdown=True,
                followlinks=False,
                onerror=walk_error,
            ):
                current_path = Path(current)

                # Do not descend through symbolic-link directories.
                directories[:] = [
                    name
                    for name in directories
                    if not (current_path / name).is_symlink()
                ]

                for name in directories:
                    inspect(current_path / name)
                    if limit_reached:
                        break

                if limit_reached:
                    break

                for name in files:
                    inspect(current_path / name)
                    if limit_reached:
                        break

                if limit_reached:
                    break

        except OSError as exc:
            mark_incomplete(f"Filesystem traversal failed under {root} ({type(exc).__name__}).")

        if limit_reached:
            break

    if limit_reached:
        mark_incomplete(
            f"Maximum entry limit reached: inspection budget is {limit} entries."
        )

    if incomplete_reasons:
        findings.append(
            Finding(
                category="services",
                title=INCOMPLETE_TITLE,
                description=(
                    "The systemd permission scan could not verify complete "
                    "coverage. " + " ".join(incomplete_reasons)
                ),
                severity="INFO",
                confidence="HIGH",
                detection_reason=(
                    "One or more search paths could not be fully inspected."
                ),
                mitigation=(
                    "Review the reported errors and search paths, restore access "
                    "where appropriate, and rerun the audit."
                ),
                scanner="services",
            )
        )

    return findings
