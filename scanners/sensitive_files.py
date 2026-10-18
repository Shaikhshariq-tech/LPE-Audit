"""Read-only permission checks for selected sensitive system files."""

from __future__ import annotations

import glob
import grp
import os
import platform
import stat
from pathlib import Path

from core.finding import Finding


DEFAULT_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
]


def scan_sensitive_files(
    paths: list[str] | None = None,
    expected_uid: int = 0,
) -> list[Finding]:
    """Report unsafe metadata without reading the contents of target files."""
    if platform.system() != "Linux":
        return [Finding(
            category="sensitive_files",
            title="Sensitive-file scanner unavailable",
            description="This scanner is intended for Linux systems.",
            severity="INFO",
            risk_score=0,
            confidence="HIGH",
            detection_reason="Unsupported operating system.",
            mitigation="Run the audit on Linux.",
            scanner="sensitive_files",
        )]

    if paths is None:
        targets = list(DEFAULT_PATHS)
        targets.extend(glob.glob("/etc/ssh/ssh_host_*_key"))
    else:
        targets = list(paths)

    findings: list[Finding] = []
    seen: set[str] = set()

    for raw_path in targets[:10000]:
        path = str(raw_path)
        if path in seen:
            continue
        seen.add(path)

        try:
            metadata = os.lstat(path)
        except OSError:
            # Missing or inaccessible files are not automatically findings.
            continue

        # Never follow symlinks; only inspect regular files.
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            continue

        mode = stat.S_IMODE(metadata.st_mode)
        basename = Path(path).name
        issues: list[str] = []
        high_risk = False

        if metadata.st_uid != expected_uid:
            issues.append(
                f"unexpected owner UID {metadata.st_uid}; expected {expected_uid}"
            )

        if mode & stat.S_IWOTH:
            issues.append("file is world-writable")
            high_risk = True

        if metadata.st_uid == 0 and mode & stat.S_IWGRP:
            issues.append("root-owned file is group-writable")

        if basename in {"shadow", "gshadow"}:
            if mode & stat.S_IROTH:
                issues.append("password-related file is world-readable")
                high_risk = True
            if mode & stat.S_IRGRP:
                try:
                    group_name = grp.getgrgid(metadata.st_gid).gr_name
                except KeyError:
                    group_name = ""
                if group_name != "shadow":
                    issues.append(
                        "password-related file is readable by a group other than shadow"
                    )
                    high_risk = True

        if basename.startswith("ssh_host_") and basename.endswith("_key"):
            if mode & (stat.S_IRGRP | stat.S_IROTH):
                issues.append("SSH host private key is group- or world-readable")
                high_risk = True

        if not issues:
            continue

        severity = "HIGH" if high_risk else "MEDIUM"
        findings.append(Finding(
            category="sensitive_files",
            title=f"Potentially unsafe permissions: {path}",
            description=(
                "A sensitive system file has metadata that warrants review: "
                + "; ".join(issues)
                + "."
            ),
            severity=severity,
            risk_score=65 if severity == "HIGH" else 40,
            confidence="HIGH",
            affected_path=path,
            owner=f"uid={metadata.st_uid}, gid={metadata.st_gid}",
            permissions=f"{mode:04o}",
            evidence=(
                f"path={path}; uid={metadata.st_uid}; gid={metadata.st_gid}; "
                f"mode={mode:04o}; issues={'; '.join(issues)}"
            ),
            detection_reason=(
                "File ownership and permission bits were checked using metadata only."
            ),
            potential_impact=(
                "Inappropriate access or modification could expose sensitive "
                "configuration or weaken system security."
            ),
            attack_path_description=(
                "An unauthorized user may be able to read or modify a sensitive "
                "file, depending on the detected permissions and system context. "
                "This scanner does not attempt access or exploitation."
            ),
            mitigation=(
                "Verify the intended owner, group, and permissions against the "
                "distribution's security guidance. Apply only the minimum "
                "permissions required by the service."
            ),
            references=[
                "https://www.cisecurity.org/benchmark/ubuntu_linux",
            ],
            scanner="sensitive_files",
        ))

    return findings
