"""Read-only sudo policy enumeration."""
import os
import platform
import shutil
import subprocess

from core.finding import Finding


def scan_sudo_rules() -> list[Finding]:
    if platform.system() != "Linux" or os.name != "posix":
        return [Finding(
            category="sudo",
            title="Sudo scanner unavailable",
            description="Sudo policy enumeration requires Linux.",
            severity="INFO",
            confidence="HIGH",
            detection_reason="Unsupported operating system.",
            mitigation="Run this scanner on Linux.",
            scanner="sudo",
        )]

    sudo_path = shutil.which("sudo")
    if not sudo_path:
        return [Finding(
            category="sudo",
            title="Sudo command unavailable",
            description="The sudo executable was not found in PATH.",
            severity="INFO",
            confidence="HIGH",
            detection_reason="The required command is unavailable.",
            mitigation="Verify whether sudo is installed and how this system manages privilege delegation.",
            scanner="sudo",
        )]

    try:
        result = subprocess.run(
            [sudo_path, "-n", "-l"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except subprocess.TimeoutExpired:
        message = "Sudo policy listing timed out."
        output = ""
    except OSError as exc:
        message = f"Sudo policy listing failed: {type(exc).__name__}."
        output = ""
    else:
        message = ""
        output = (result.stdout or "") + "\n" + (result.stderr or "")

    if message:
        return [Finding(
            category="sudo",
            title="Sudo policy could not be enumerated",
            description=message,
            severity="INFO",
            confidence="HIGH",
            detection_reason="The read-only sudo listing did not complete.",
            mitigation="Review sudo availability and policy-listing permissions, then rerun.",
            scanner="sudo",
        )]

    # Do not interpret an unavailable policy listing as a vulnerability.
    if result.returncode != 0 and not output.strip():
        return [Finding(
            category="sudo",
            title="Sudo policy listing unavailable",
            description="Sudo returned no policy details; passwordless listing may not be permitted.",
            severity="INFO",
            confidence="HIGH",
            detection_reason="No usable sudo policy output was returned.",
            mitigation="Have an administrator review the effective sudo policy if necessary.",
            scanner="sudo",
        )]

    findings = []
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    policy_lines = [
        line for line in lines
        if "NOPASSWD:" in line.upper()
        or "(ALL" in line.upper()
        or "ALL=(ALL" in line.upper()
    ]

    if policy_lines:
        findings.append(Finding(
            category="sudo",
            title="Sudo policy contains potentially broad or passwordless rules",
            description=(
                "The policy listing includes rule lines worth reviewing. "
                "These lines alone do not prove a privilege-escalation vulnerability."
            ),
            severity="INFO",
            confidence="MEDIUM",
            evidence="\n".join(policy_lines[:20])[:4000],
            detection_reason=(
                "Rule text matched broad-run-as or NOPASSWD indicators."
            ),
            potential_impact=(
                "Depending on the allowed commands and configuration, "
                "the rules may grant more privilege than intended."
            ),
            mitigation=(
                "Review each rule against least-privilege requirements. "
                "Restrict command scope and avoid unnecessary NOPASSWD permissions."
            ),
            references=["https://www.sudo.ws/docs/man/sudoers.man/"],
            scanner="sudo",
        ))
    else:
        findings.append(Finding(
            category="sudo",
            title="Sudo policy listing collected",
            description=(
                "Sudo returned policy output, but no simple broad-rule "
                "indicator was detected. This is not proof that the policy is safe."
            ),
            severity="INFO",
            confidence="LOW",
            affected_path="effective sudo policy (current user)",
            evidence=output.strip()[:4000],
            detection_reason="Basic policy text checks completed.",
            mitigation="Review the complete effective sudo policy for unnecessary permissions.",
            scanner="sudo",
        ))

    return findings
