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
) -> list[Finding]:
    """
    Discover SUID/SGID files and return normalized findings.

    The scanner:
    - operates only on Linux;
    - does not execute discovered files;
    - handles inaccessible directories;
    - does not follow symlinks;
    - avoids common pseudo-filesystems.
    """
    if os.name != "posix":
        return [
            Finding(
                category="suid_sgid",
                title="SUID/SGID scan unavailable",
                description=(
                    "SUID/SGID enumeration requires a POSIX/Linux "
                    "filesystem environment."
                ),
                severity="INFO",
                confidence="HIGH",
                detection_reason="Current operating system is not POSIX/Linux.",
                mitigation="Run LPE-Audit from a Linux environment.",
                scanner="suid_sgid",
            )
        ]

    # os.geteuid() exists on normal POSIX systems.
    if hasattr(os, "geteuid") and platform_is_linux():
        pass

    paths = search_paths or DEFAULT_SEARCH_PATHS
    ignored = ignored_paths or DEFAULT_IGNORED_PATHS

    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()

    for root_string in paths:
        root = Path(root_string)

        if not root.exists() or _is_ignored(root, ignored):
            continue

        try:
            for current_root, directories, files in os.walk(
                root,
                topdown=True,
                followlinks=False,
            ):
                current_path = Path(current_root)

                if _is_ignored(current_path, ignored):
                    directories[:] = []
                    continue

                # Prevent traversal into ignored directories.
                directories[:] = [
                    directory
                    for directory in directories
                    if not _is_ignored(current_path / directory, ignored)
                ]

                for filename in files:
                    path = current_path / filename

                    try:
                        # lstat prevents following symbolic links.
                        file_stat = path.lstat()
                    except (OSError, PermissionError):
                        continue

                    if not stat.S_ISREG(file_stat.st_mode):
                        continue

                    has_suid = bool(file_stat.st_mode & stat.S_ISUID)
                    has_sgid = bool(file_stat.st_mode & stat.S_ISGID)

                    if not (has_suid or has_sgid):
                        continue

                    # Avoid duplicate findings when search paths overlap.
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
                        references=[
                            "https://gtfobins.github.io/",
                        ],
                        scanner="suid_sgid",
                    )

                    RiskEngine.apply(
                        finding,
                        privileged_context=True,
                    )

                    findings.append(finding)

        except (OSError, PermissionError):
            # An inaccessible root must not terminate the entire audit.
            continue

    return findings


def platform_is_linux() -> bool:
    """Return True only when the running platform is Linux."""
    try:
        import platform

        return platform.system() == "Linux"
    except Exception:
        return False