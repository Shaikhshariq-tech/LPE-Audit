"""Read-only checks for unsafe entries in the current PATH."""

from __future__ import annotations

import os
import platform
import re
import stat

from core.finding import Finding


def _is_wsl_windows_path(path: str, release: str | None = None) -> bool:
    """Heuristic for Windows drive mounts commonly exposed by WSL DrvFS."""
    kernel_release = (release if release is not None else platform.release()).lower()
    normalized = os.path.normpath(path)
    return (
        "microsoft" in kernel_release
        and re.match(r"^/mnt/[a-z](?:/|$)", normalized, re.IGNORECASE) is not None
    )


def scan_path_security(path_value: str | None = None) -> list[Finding]:
    """Report empty, relative, missing, and writable PATH components."""
    if platform.system() != "Linux":
        return [Finding(
            category="path_security",
            title="PATH security scanner unavailable",
            description="This scanner is intended for Linux systems.",
            severity="INFO",
            risk_score=5,
            confidence="HIGH",
            detection_reason="Unsupported operating system.",
            mitigation="Run the audit on Linux.",
            scanner="path_security",
        )]

    raw_path = os.environ.get("PATH", "") if path_value is None else path_value
    findings: list[Finding] = []

    def add_finding(
        title: str,
        component: str,
        reason: str,
        severity: str,
        risk_score: int,
        *,
        owner: str = "",
        permissions: str = "",
        impact: str = "",
    ) -> None:
        findings.append(Finding(
            category="path_security",
            title=title,
            description=f"PATH component {component!r}: {reason}",
            severity=severity,
            risk_score=risk_score,
            confidence="HIGH",
            affected_path=component or ".",
            owner=owner,
            permissions=permissions,
            evidence=(
                f"PATH component={component!r}; owner={owner or 'unknown'}; "
                f"permissions={permissions or 'unknown'}"
            ),
            detection_reason=reason,
            potential_impact=impact or (
                "A risky PATH entry may cause a process to resolve an "
                "unexpected executable. Actual impact depends on the process "
                "using this PATH and its privileges."
            ),
            attack_path_description=(
                "Review which processes use this PATH and who can modify the "
                "directory. This scanner does not execute programs from it."
            ),
            mitigation=(
                "Remove empty or inappropriate relative entries. Restrict "
                "directory modification according to the trust level of the "
                "processes that use this PATH."
            ),
            scanner="path_security",
        ))

    if not raw_path:
        add_finding(
            "PATH is empty", "",
            "No PATH directories were configured.",
            "LOW", 20,
        )
        return findings

    for component in dict.fromkeys(raw_path.split(os.pathsep)):
        if not component:
            add_finding(
                "Empty PATH component", "",
                "An empty component can resolve executables from the current directory.",
                "HIGH", 65,
            )
            continue

        if not os.path.isabs(component):
            add_finding(
                "Relative PATH component", component,
                "The component is relative to the process working directory.",
                "MEDIUM", 40,
            )
            continue

        try:
            metadata = os.stat(component)
        except (FileNotFoundError, NotADirectoryError):
            add_finding(
                "Missing or non-directory PATH component", component,
                "The entry does not resolve to an existing directory.",
                "LOW", 20,
            )
            continue
        except OSError as exc:
            add_finding(
                "path_security scanner could not complete", component,
                (
                    "Directory metadata could not be read; PATH audit "
                    f"coverage is incomplete ({type(exc).__name__})."
                ),
                "INFO", 5,
            )
            continue

        if not stat.S_ISDIR(metadata.st_mode):
            add_finding(
                "Missing or non-directory PATH component", component,
                "The entry exists but is not a directory.",
                "LOW", 20,
            )
            continue

        mode = stat.S_IMODE(metadata.st_mode)
        owner = f"uid={metadata.st_uid}, gid={metadata.st_gid}"
        permissions = f"{mode:04o} ({stat.filemode(metadata.st_mode)})"

        writable_by_current_user = os.access(component, os.W_OK)
        world_writable = bool(mode & stat.S_IWOTH)
        group_writable = bool(mode & stat.S_IWGRP)

        if not (writable_by_current_user or world_writable or group_writable):
            continue

        wsl_windows_path = _is_wsl_windows_path(component)
        if wsl_windows_path:
            # DrvFS-visible mode bits do not establish the effective Windows ACL.
            severity, score = "LOW", 20
            reason = (
                f"Directory appears writable in Linux metadata "
                f"(uid={metadata.st_uid}, mode={stat.filemode(metadata.st_mode)}). "
                "It appears to be on a Windows drive mounted in WSL; these mode "
                "bits alone do not establish the effective Windows ACL or prove "
                "that another user can modify the directory."
            )
        elif world_writable:
            severity, score = "HIGH", 65
            reason = (
                f"Directory is world-writable (uid={metadata.st_uid}, "
                f"mode={stat.filemode(metadata.st_mode)}). Any local user may "
                "be able to add or replace executable names, subject to other controls."
            )
        elif group_writable:
            severity, score = "MEDIUM", 40
            reason = (
                f"Directory is group-writable (uid={metadata.st_uid}, "
                f"mode={stat.filemode(metadata.st_mode)}). Review the group "
                "membership and the privileges of processes using this PATH."
            )
        else:
            severity, score = "LOW", 20
            reason = (
                f"Directory is writable by the current audit user "
                f"(uid={metadata.st_uid}, mode={stat.filemode(metadata.st_mode)}). "
                "This alone does not prove a privilege-escalation path."
            )

        add_finding(
            "Writable PATH directory",
            component,
            reason,
            severity,
            score,
            owner=owner,
            permissions=permissions,
            impact=(
                "If a higher-privileged process uses this PATH and an untrusted "
                "user can alter a searched directory, executable resolution may "
                "be unsafe. The current user's PATH alone does not establish that "
                "such a privileged process exists."
            ),
        )

    return findings
