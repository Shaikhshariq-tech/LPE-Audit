
"""Collect basic host information without modifying the system."""

import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _read_os_release() -> dict[str, str]:
    """Read Linux distribution metadata when available."""
    release_path = Path("/etc/os-release")
    data: dict[str, str] = {}

    try:
        for line in release_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            data[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass

    return data


def _linux_identity() -> dict[str, Any]:
    """Read Linux UID, GID and supplementary groups when supported."""
    result: dict[str, Any] = {
        "username": os.environ.get("USERNAME") or os.environ.get("USER", "unknown"),
        "uid": None,
        "gid": None,
        "groups": [],
        "is_root": False,
    }

    try:
        import grp
        import pwd

        uid = os.getuid()
        gid = os.getgid()
        result["uid"] = uid
        result["gid"] = gid
        result["username"] = pwd.getpwuid(uid).pw_name
        result["groups"] = [
            grp.getgrgid(group_id).gr_name
            for group_id in os.getgroups()
        ]
        result["is_root"] = uid == 0
    except (ImportError, AttributeError, OSError, KeyError):
        # Windows does not expose these Linux identity APIs.
        pass

    return result


def collect_system_info() -> dict[str, Any]:
    """Return a structured snapshot of the current environment."""
    system = platform.system()
    linux = system == "Linux"
    identity = _linux_identity()

    info: dict[str, Any] = {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "hostname": platform.node(),
        "operating_system": system,
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "kernel_release": platform.release(),
        "python_version": platform.python_version(),
        "username": identity["username"],
        "uid": identity["uid"],
        "gid": identity["gid"],
        "groups": identity["groups"],
        "is_root": identity["is_root"],
        "shell": os.environ.get("SHELL") or os.environ.get("COMSPEC", ""),
        "path": os.environ.get("PATH", ""),
        "is_linux": linux,
        "distro_id": "",
        "distro_name": "",
        "distro_version": "",
        "available_tools": {},
        "notes": [],
    }

    if linux:
        release = _read_os_release()
        info["distro_id"] = release.get("ID", "")
        info["distro_name"] = release.get("PRETTY_NAME", "")
        info["distro_version"] = release.get("VERSION_ID", "")

        for tool in ("find", "getcap", "sudo", "systemctl", "uname"):
            info["available_tools"][tool] = shutil.which(tool) is not None
    else:
        info["notes"].append(
            "This host is not Linux. Linux-specific audit checks require "
            "a Linux host or Linux environment such as WSL."
        )
        info["available_tools"] = {
            tool: shutil.which(tool) is not None
            for tool in ("find", "getcap", "sudo", "systemctl", "uname")
        }

    return info


def collect_kernel_release() -> str:
    """Return the OS-reported kernel/platform release."""
    return platform.release()