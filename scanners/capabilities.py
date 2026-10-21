"""Linux file-capability enumeration. Discovered files are never executed."""

from __future__ import annotations

import platform
import shutil

from core.command_runner import CommandRunner
from core.finding import Finding
from core.risk_engine import RiskEngine
from core.scanner import Scanner


DEFAULT_SEARCH_PATHS = [
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
]

HIGH_RISK_CAPABILITIES = {
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_sys_ptrace",
    "cap_chown",
}


def _parse_capability_line(line: str) -> tuple[str, str] | None:
    """Parse a getcap result such as '/usr/bin/example cap_net_raw=ep'."""
    parts = line.strip().split(None, 1)
    if len(parts) != 2 or "=" not in parts[1]:
        return None
    return parts[0], parts[1]


class CapabilitiesScanner(Scanner):
    name = "capabilities"

    def __init__(
        self,
        search_paths: list[str] | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.search_paths = search_paths or DEFAULT_SEARCH_PATHS
        self.runner = runner or CommandRunner(default_timeout=30)

    def scan(self) -> list[Finding]:
        if platform.system().lower() != "linux":
            return [self.unavailable_finding(
                "Linux file capabilities can only be audited on Linux."
            )]

        if shutil.which("getcap") is None:
            return [self.unavailable_finding(
                "The getcap utility was not found. Install the Linux libcap tools."
            )]

        result = self.runner.run(
            ["getcap", "-r", *self.search_paths],
            timeout=30,
        )

        if result.error and not result.stdout.strip():
            return [self.unavailable_finding(
                f"Could not run getcap: {result.error}"
            )]

        findings: list[Finding] = []

        for line in result.stdout.splitlines():
            parsed = _parse_capability_line(line)
            if parsed is None:
                continue

            path, capabilities = parsed
            capability_names = {
                item.split("=", 1)[0].strip().lower()
                for item in capabilities.split()
                if "=" in item
            }
            high_risk = bool(capability_names & HIGH_RISK_CAPABILITIES)

            finding = Finding(
                category=self.name,
                title=f"File capabilities discovered: {path.rsplit('/', 1)[-1]}",
                description=f"Linux file capabilities are assigned to {path}.",
                severity="HIGH" if high_risk else "LOW",
                confidence="HIGH",
                affected_path=path,
                evidence=f"{path}: {capabilities}",
                detection_reason=(
                    "One or more capabilities can grant sensitive privileges."
                    if high_risk
                    else "The file has explicitly assigned Linux capabilities."
                ),
                potential_impact=(
                    "Depending on the capability, ownership, executable behavior, "
                    "and system configuration, this may broaden the file's privileges."
                ),
                attack_path_description=(
                    "Review whether each capability is required and whether the "
                    "binary and its configuration are appropriately protected. "
                    "LPE-Audit does not execute the file."
                ),
                mitigation=(
                    "Remove unnecessary file capabilities and retain only the "
                    "minimum privileges required by the application."
                ),
                references=["https://man7.org/linux/man-pages/man7/capabilities.7.html"],
                scanner=self.name,
            )
            RiskEngine.apply(finding, privileged_context=True)
            findings.append(finding)

        # Preserve useful findings, but explicitly report incomplete scans.
        # A timeout, execution error, missing return code, or non-zero exit
        # means the scan cannot be treated as complete.
        incomplete = (
            bool(result.error)
            or bool(getattr(result, "timed_out", False))
            or result.returncode != 0
        )
        if incomplete:
            findings.append(self._error_finding(
                "Capabilities scan was incomplete; review command status and rerun."
            ))

        return findings


def scan_capabilities(
    search_paths: list[str] | None = None,
    runner: CommandRunner | None = None,
) -> list[Finding]:
    """Public function interface used by the CLI and tests."""
    return CapabilitiesScanner(search_paths, runner).run()
