"""
SUID/SGID security scanner.

Detection and analysis only.
This module never executes discovered binaries.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from core.finding import Finding
from core.risk_engine import RiskEngine


# Pseudo-filesystems and paths that should not be recursively traversed.
DEFAULT_IGNORED_PATHS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
}

# These names are useful for prioritization, not proof of exploitability.
INTERESTING_BINARIES = {
    "awk",
    "bash",
    "cp",
    "find",
    "nmap",
    "perl",
    "python",
    "python2",
    "python3",
    "ruby",
    "tar",
    "vim",
    "vi",
    "env",
    "less",
    "more",
    "nano",
    "sh",
}

MAX_ENTRIES = 10_000


DEFAULT_SEARCH_PATHS = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
]


def _format_permissions(mode: int) -> str:
    """Return standard symbolic permissions."""
    return stat.filemode(mode)


def _is_ignored(path: Path, ignored_paths: set[str]) -> bool:
    """Determine whether a path is inside an ignored filesystem tree."""
    path_string = str(path)

    for ignored in ignored_paths:
        if path_string == ignored or path_string.startswith(ignored + os.sep):
            return True

    return False


def _classify_file(path: Path, mode: int) -> tuple[str, str]:
    """
    Classify a discovered SUID/SGID file.

    Classification is deliberately conservative:
    the presence of SUID/SGID is not automatically called exploitable.
    """
    name = path.name.lower()

    has_suid = bool(mode & stat.S_ISUID)
    has_sgid = bool(mode & stat.S_ISGID)

    if name in INTERESTING_BINARIES:
        return (
            "potentially_interesting",
            "The binary name is commonly associated with "
            "privilege-sensitive execution paths.",
        )

    if has_suid and has_sgid:
        return (
            "suid_sgid_present",
            "Both SUID and SGID permission bits are present.",
        )

    if has_suid:
        return (
            "suid_present",
            "The SUID permission bit is present.",
        )

    return (
        "sgid_present",
        "The SGID permission bit is present.",
    )


def scan_suid_sgid(
    search_paths: list[str] | None = None,
    ignored_paths: set[str] | None = None,
    max_entries: int = MAX_ENTRIES,
) -> list[Finding]:
    """
    Discover SUID/SGID files and return normalized findings.

    The scanner:
    - operates only on Linux;
    - does not execute discovered files;
    - handles inaccessible directories;
    - never follows symbolic links;
    - avoids common pseudo-filesystems;
    - limits the number of distinct filesystem paths inspected.
    """
    if os.name != "posix" or not platform_is_linux():
        return [
            Finding(
                category="suid_sgid",
                title="SUID/SGID scan unavailable",
                description="SUID/SGID enumeration is supported only on Linux.",
                severity="INFO",
                confidence="HIGH",
                detection_reason="Current operating system is not Linux.",
                mitigation="Run LPE-Audit from a supported Linux environment.",
                scanner="suid_sgid",
            )
        ]

    paths = DEFAULT_SEARCH_PATHS if search_paths is None else search_paths
    ignored = DEFAULT_IGNORED_PATHS if ignored_paths is None else ignored_paths
    max_entries = max(1, int(max_entries))

    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()
    counted_paths: set[str] = set()
    inspected = 0
    error_count = 0
    limit_reached = False
    stop_scanning = False

    def record_walk_error(_error: OSError) -> None:
        """Record traversal errors without exposing filesystem details."""
        nonlocal error_count
        error_count += 1

    def count_entry(path: Path) -> bool:
        """Count a distinct path; return False when the budget is exhausted."""
        nonlocal inspected, limit_reached

        path_key = os.path.abspath(str(path))
        if path_key in counted_paths:
            return True

        if inspected >= max_entries:
            limit_reached = True
            return False

        counted_paths.add(path_key)
        inspected += 1
        return True

    for root_string in paths:
        if stop_scanning:
            break

        root = Path(root_string)

        if _is_ignored(root, ignored):
            continue

        try:
            root_stat = root.lstat()
        except FileNotFoundError:
            # Missing optional default roots are normal across distributions.
            if search_paths is not None:
                error_count += 1
            continue
        except OSError:
            error_count += 1
            continue

        if not count_entry(root):
            break

        # Do not follow a symlink supplied as a scan root. An explicit
        # symlink root means the requested directory tree was not inspected.
        if stat.S_ISLNK(root_stat.st_mode):
            if search_paths is not None:
                error_count += 1
            continue

        if not stat.S_ISDIR(root_stat.st_mode):
            if search_paths is not None:
                error_count += 1
            continue

        try:
            for current_root, directories, files in os.walk(
                root,
                topdown=True,
                followlinks=False,
                onerror=record_walk_error,
            ):
                current_path = Path(current_root)

                if _is_ignored(current_path, ignored):
                    directories[:] = []
                    continue

                # Filter ignored trees and symbolic-link directories before
                # descent. Symbolic links are never traversal targets.
                directories[:] = [
                    name
                    for name in directories
                    if not _is_ignored(current_path / name, ignored)
                    and not (current_path / name).is_symlink()
                ]

                # Count child directories and files against the same budget.
                # Directory entries are counted before the walk descends.
                for name in directories:
                    if not count_entry(current_path / name):
                        stop_scanning = True
                        break

                if stop_scanning:
                    break

                for name in files:
                    path = current_path / name

                    if not count_entry(path):
                        stop_scanning = True
                        break

                    try:
                        file_stat = path.lstat()
                    except OSError:
                        error_count += 1
                        continue

                    # lstat plus this check prevents symlinks and special
                    # filesystem objects from being treated as binaries.
                    if not stat.S_ISREG(file_stat.st_mode):
                        continue

                    has_suid = bool(file_stat.st_mode & stat.S_ISUID)
                    has_sgid = bool(file_stat.st_mode & stat.S_ISGID)

                    if not (has_suid or has_sgid):
                        continue

                    identity = (file_stat.st_dev, file_stat.st_ino)
                    if identity in seen:
                        continue
                    seen.add(identity)

                    classification, reason = _classify_file(
                        path,
                        file_stat.st_mode,
                    )
                    severity = (
                        "MEDIUM"
                        if classification == "potentially_interesting"
                        else "LOW"
                    )

                    finding = Finding(
                        category="suid_sgid",
                        title=f"SUID/SGID binary discovered: {path.name}",
                        description=(
                            f"A privileged permission bit was discovered on "
                            f"{path}."
                        ),
                        severity=severity,
                        confidence="HIGH",
                        affected_path=str(path),
                        owner=str(file_stat.st_uid),
                        permissions=_format_permissions(file_stat.st_mode),
                        evidence=(
                            f"mode={oct(file_stat.st_mode)}, "
                            f"permissions={_format_permissions(file_stat.st_mode)}, "
                            f"uid={file_stat.st_uid}, gid={file_stat.st_gid}"
                        ),
                        detection_reason=reason,
                        potential_impact=(
                            "A privileged executable may provide an "
                            "interesting privilege-escalation attack path "
                            "depending on its behavior and configuration."
                        ),
                        attack_path_description=(
                            "Review the binary's intended behavior, "
                            "ownership, version, and known security "
                            "properties. No exploitation is performed "
                            "by LPE-Audit."
                        ),
                        mitigation=(
                            "Remove unnecessary SUID/SGID permissions and "
                            "ensure privileged binaries are owned and "
                            "protected appropriately."
                        ),
                        references=["https://gtfobins.github.io/"],
                        scanner="suid_sgid",
                    )

                    RiskEngine.apply(finding, privileged_context=True)
                    findings.append(finding)

                if stop_scanning:
                    break

        except OSError:
            # Preserve coverage of other independent search roots.
            error_count += 1
            continue

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
            Finding(
                category="suid_sgid",
                title="suid_sgid scanner could not complete",
                description=(
                    "SUID/SGID enumeration was incomplete because "
                    + " and ".join(reasons)
                    + "."
                ),
                severity="INFO",
                confidence="HIGH",
                detection_reason=(
                    "Filesystem access errors or the configured entry limit "
                    "prevented complete SUID/SGID enumeration."
                ),
                potential_impact=(
                    "Additional SUID/SGID files may not have been detected."
                ),
                mitigation=(
                    "Review filesystem access and scan coverage, then rerun "
                    "the audit with appropriate access or a suitable entry limit."
                ),
                scanner="suid_sgid",
            )
        )

    return findings


def platform_is_linux() -> bool:
    """Return True only when the running platform is Linux."""
    try:
        import platform

        return platform.system() == "Linux"
    except Exception:
        return False