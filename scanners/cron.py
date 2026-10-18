"""Read-only checks for risky cron configuration permissions."""
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


def scan_cron_jobs(
    search_paths=None,
    max_entries: int = 10000,
) -> list[Finding]:
    if platform.system() != "Linux" or os.name != "posix":
        return [Finding(
            category="cron",
            title="Cron scanner unavailable",
            description="Cron permission checks require Linux.",
            severity="INFO",
            confidence="HIGH",
            detection_reason="Unsupported operating system.",
            mitigation="Run the audit on Linux.",
            scanner="cron",
        )]

    roots = [Path(p) for p in (
        DEFAULT_CRON_PATHS if search_paths is None else search_paths
    )]
    findings = []
    inspected = 0
    seen = set()

    for root in roots:
        candidates = [root]
        try:
            if root.is_dir() and not root.is_symlink():
                for current, dirs, files in os.walk(root, followlinks=False):
                    dirs[:] = [
                        name for name in dirs
                        if not (Path(current) / name).is_symlink()
                    ]
                    candidates.extend(Path(current) / name for name in files)
                    candidates.extend(Path(current) / name for name in dirs)
                    if len(candidates) >= max_entries:
                        break
        except OSError:
            continue

        for path in candidates:
            if inspected >= max_entries:
                break

            key = str(path)
            if key in seen:
                continue
            seen.add(key)

            try:
                metadata = path.lstat()
            except (OSError, PermissionError):
                continue

            inspected += 1

            # Ignore symlinks; do not follow their targets.
            if stat.S_ISLNK(metadata.st_mode):
                continue

            mode = metadata.st_mode
            is_file = stat.S_ISREG(mode)
            is_dir = stat.S_ISDIR(mode)
            if not (is_file or is_dir):
                continue

            world_writable = bool(mode & stat.S_IWOTH)
            group_writable = bool(mode & stat.S_IWGRP)

            # Sticky directories such as /tmp have special semantics and
            # are not automatically treated as writable cron configurations.
            if is_dir and mode & stat.S_ISVTX:
                continue

            risky = world_writable or (
                group_writable and metadata.st_uid == 0
            )
            if not risky:
                continue

            reasons = []
            if world_writable:
                reasons.append("world-writable")
            if group_writable and metadata.st_uid == 0:
                reasons.append("root-owned and group-writable")

            findings.append(Finding(
                category="cron",
                title="Potentially unsafe cron configuration permissions",
                description=(
                    f"The cron-related path is {' and '.join(reasons)}. "
                    "Confirm whether an untrusted user can modify it and "
                    "whether a privileged scheduled task consumes it."
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
                detection_reason="Filesystem metadata matched a writable-permission rule.",
                potential_impact=(
                    "If the path controls a privileged scheduled job, "
                    "unauthorized changes may affect commands run by that job."
                ),
                mitigation=(
                    "Restrict write permissions to trusted administrators and "
                    "review ownership and the scheduled task's execution context."
                ),
                scanner="cron",
            ))

        if inspected >= max_entries:
            findings.append(Finding(
                category="cron",
                title="Cron scan reached its entry limit",
                description=f"Inspection stopped at the configured limit of {max_entries} entries.",
                severity="INFO",
                confidence="HIGH",
                detection_reason="The safety limit prevented unbounded traversal.",
                mitigation="Review the configured search paths or raise the limit deliberately.",
                scanner="cron",
            ))
            break

    return findings
