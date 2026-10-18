"""Conservative, read-only remediation guidance for audit findings."""

from core.finding import Finding


def recommendation_for_finding(finding: Finding) -> str:
    """Suggest defensive remediation without executing any action."""
    category = str(finding.category or "").lower()
    title = str(finding.title or "").lower()
    path = str(finding.affected_path or "").lower()
    text = f"{category} {title} {path}"

    if finding.mitigation and finding.mitigation.strip():
        return finding.mitigation.strip()

    if any(term in text for term in ("suid", "sgid")):
        return (
            "Verify that the SUID/SGID bit is required, review the executable "
            "and its ownership, and remove unnecessary privilege bits through "
            "your approved change process."
        )

    if "capabilit" in text:
        return (
            "Review whether the file capability is required. Remove excessive "
            "capabilities and restrict file ownership and write access through "
            "your approved change process."
        )

    if "sudo" in text:
        return (
            "Have an administrator review the effective sudo policy and remove "
            "unnecessary commands, broad privileges, or passwordless access."
        )

    if any(term in text for term in ("cron", "scheduled task")):
        return (
            "Review the scheduled task and every relevant parent directory. "
            "Restrict modification rights to trusted administrators and verify "
            "the task's ownership and execution context."
        )

    if any(term in text for term in ("systemd", "service", "unit file")):
        return (
            "Review the service unit, referenced scripts, and parent directories. "
            "Restrict write access to trusted administrators and verify that "
            "the service runs with only the privileges it needs."
        )

    if "path" in text:
        return (
            "Review PATH ordering and remove empty or unintended entries. "
            "Ensure executable search directories are trusted and not writable "
            "by untrusted users; account for platform-specific permissions."
        )

    if any(term in text for term in ("sensitive", "shadow", "sudoers", "ssh")):
        return (
            "Have an administrator verify the file's intended owner and access "
            "policy, then restrict permissions to the minimum required."
        )

    if "kernel" in text:
        return (
            "Compare the detected kernel and distribution versions with the "
            "vendor's security advisories. Apply supported updates through "
            "the normal patch-management process; this inventory alone does "
            "not establish that a vulnerability exists."
        )

    if any(term in text for term in ("permission", "writable")):
        return (
            "Verify the intended owner and access policy. Remove unnecessary "
            "write permissions and review parent-directory permissions before "
            "making an approved change."
        )

    return (
        "Manually validate the evidence and affected resource, then apply the "
        "least-privilege remediation appropriate to the confirmed issue."
    )
