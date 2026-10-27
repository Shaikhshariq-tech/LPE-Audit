"""Read-only sudo policy enumeration."""
import os
import platform
import shutil
import subprocess

from core.finding import Finding


def _incomplete_finding(description: str) -> Finding:
    """Report incomplete sudo coverage using the shared coordinator contract."""
    return Finding(
        category="sudo",
        title="sudo scanner could not complete",
        description=description,
        severity="INFO",
        confidence="HIGH",
        detection_reason=(
            "The effective sudo policy could not be reliably enumerated."
        ),
        potential_impact=(
            "Sudo-related privilege-escalation risks may remain undetected."
        ),
        mitigation=(
            "Review sudo availability and policy-listing permissions, "
            "then rerun the audit."
        ),
        scanner="sudo",
    )


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
            mitigation=(
                "Verify whether sudo is installed and how this system "
                "manages privilege delegation."
            ),
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
        return [_incomplete_finding("Sudo policy listing timed out.")]
    except OSError as exc:
        return [_incomplete_finding(
            f"Sudo policy listing failed: {type(exc).__name__}."
        )]

    # A nonzero exit means policy enumeration was unsuccessful. Never parse
    # diagnostic output as policy evidence or claim the listing was collected.
    if result.returncode != 0:
        return [_incomplete_finding(
            "Sudo returned a nonzero exit status; effective policy "
            "coverage is incomplete."
        )]

    # Only successful stdout is considered policy output. Keep stderr out of
    # evidence so diagnostics cannot be mistaken for policy rules.
    output = result.stdout or ""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    policy_lines = [
        line for line in lines
        if "NOPASSWD:" in line.upper()
        or "(ALL" in line.upper()
        or "ALL=(ALL" in line.upper()
    ]

    if policy_lines:
        return [Finding(
            category="sudo",
            title="Sudo policy contains potentially broad or passwordless rules",
            description=(
                "The policy listing includes rule lines worth reviewing. "
                "These lines alone do not prove a privilege-escalation "
                "vulnerability."
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
                "Restrict command scope and avoid unnecessary NOPASSWD "
                "permissions."
            ),
            references=["https://www.sudo.ws/docs/man/sudoers.man/"],
            scanner="sudo",
        )]

    if not output.strip():
        return [_incomplete_finding(
            "Sudo exited successfully but returned no policy output; "
            "effective policy coverage could not be confirmed."
        )]

    return [Finding(
        category="sudo",
        title="Sudo policy listing collected",
        description=(
            "Sudo returned policy output, but no simple broad-rule "
            "indicator was detected. This is not proof that the policy "
            "is safe."
        ),
        severity="INFO",
        confidence="LOW",
        affected_path="effective sudo policy (current user)",
        evidence=output.strip()[:4000],
        detection_reason="Basic policy text checks completed.",
        mitigation=(
            "Review the complete effective sudo policy for unnecessary "
            "permissions."
        ),
        scanner="sudo",
    )]
