"""Read-only kernel and distribution inventory for vulnerability triage."""

from __future__ import annotations

import platform
from pathlib import Path

from core.finding import Finding


def scan_kernel_info(
    kernel_release: str | None = None,
    os_release_path: str = "/etc/os-release",
    proc_version_path: str = "/proc/version",
) -> list[Finding]:
    """Collect kernel/OS context without claiming CVE applicability."""
    if platform.system() != "Linux":
        return [Finding(
            category="kernel",
            title="Kernel inventory scanner unavailable",
            description="This scanner is intended for Linux systems.",
            severity="INFO",
            confidence="HIGH",
            detection_reason="Unsupported operating system.",
            mitigation="Run the audit on Linux.",
            scanner="kernel",
        )]

    release = kernel_release or platform.release()
    architecture = platform.machine()
    distribution = "unknown"
    distribution_version = "unknown"
    proc_version = "unavailable"
    metadata_errors: list[str] = []

    try:
        for line in Path(os_release_path).read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            key, separator, value = line.partition("=")
            if not separator:
                continue
            value = value.strip().strip('"').strip("'")
            if key == "PRETTY_NAME":
                distribution = value
            elif key == "VERSION_ID":
                distribution_version = value
    except (FileNotFoundError, NotADirectoryError):
        pass
    except OSError as exc:
        metadata_errors.append(type(exc).__name__)

    try:
        proc_version = Path(proc_version_path).read_text(
            encoding="utf-8", errors="replace"
        ).strip()
    except (FileNotFoundError, NotADirectoryError):
        pass
    except OSError as exc:
        metadata_errors.append(type(exc).__name__)

    wsl_indicator = (
        "WSL" if "microsoft" in release.lower()
        or "microsoft" in proc_version.lower()
        else "not detected"
    )

    evidence = (
        f"kernel_release={release}; architecture={architecture}; "
        f"distribution={distribution}; distribution_version={distribution_version}; "
        f"wsl_indicator={wsl_indicator}; proc_version={proc_version[:300]}"
    )

    findings = [Finding(
        category="kernel",
        title="Kernel and operating-system inventory collected",
        description=(
            f"Detected kernel {release} ({architecture}) on "
            f"{distribution} {distribution_version}. "
            "This is inventory for vulnerability triage, not a CVE verdict."
        ),
        severity="INFO",
        confidence="HIGH",
        affected_path="/proc/version",
        evidence=evidence,
        detection_reason=(
            "Kernel release, architecture, and available OS metadata were collected."
        ),
        potential_impact=(
            "An outdated or affected kernel can expose the system to known "
            "vulnerabilities; applicability depends on vendor patches, build "
            "details, configuration, and the actual runtime environment."
        ),
        attack_path_description=(
            "Compare this inventory with authoritative advisories for the exact "
            "distribution and kernel build. Do not infer exploitability from "
            "the version string alone."
        ),
        mitigation=(
            "Check supported distribution and kernel security updates, install "
            "approved updates through the system's normal update process, and "
            "reboot when required by the administrator's maintenance policy."
        ),
        references=[
            "https://www.kernel.org/",
            "https://ubuntu.com/security/notices",
        ],
        scanner="kernel",
    )]

    if metadata_errors:
        error_types = ", ".join(sorted(set(metadata_errors)))
        findings.append(Finding(
            category="kernel",
            title="kernel scanner could not complete",
            description=(
                "One or more kernel or distribution metadata files could not "
                "be read. The inventory finding is retained, but metadata "
                "coverage may be incomplete."
            ),
            severity="INFO",
            confidence="HIGH",
            evidence=f"Metadata read error types: {error_types}",
            detection_reason=(
                "An attempted metadata read failed with an operating-system "
                "error other than a missing optional file."
            ),
            mitigation=(
                "Review metadata file accessibility and rerun the audit if "
                "complete kernel and distribution inventory is required."
            ),
            scanner="kernel",
        ))

    return findings
