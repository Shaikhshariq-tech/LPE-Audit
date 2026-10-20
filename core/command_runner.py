"""Safe subprocess helper for explicitly selected read-only audit commands."""

from dataclasses import dataclass
import shutil
import subprocess


@dataclass
class CommandResult:
    """Structured outcome of a command execution attempt."""

    command: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """Whether the command completed successfully."""
        return self.returncode == 0 and not self.error and not self.timed_out


class CommandRunner:
    """Run argument-list commands without invoking a shell."""

    def __init__(self, default_timeout: int = 10):
        if (
            isinstance(default_timeout, bool)
            or not isinstance(default_timeout, int)
            or default_timeout < 1
        ):
            raise ValueError("default_timeout must be a positive integer")
        self.default_timeout = default_timeout

    @staticmethod
    def _text(value) -> str:
        """Normalize optional text or bytes returned by subprocess."""
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def run(
        self,
        command: list[str],
        timeout: int | None = None,
    ) -> CommandResult:
        """Run one command and return errors as data rather than raising them."""
        if not isinstance(command, list) or not command:
            return CommandResult(
                [], None, error="Command must be a non-empty list"
            )

        safe_command = command.copy()

        if not all(isinstance(arg, str) for arg in safe_command):
            return CommandResult(
                [], None, error="All command arguments must be strings"
            )

        executable = safe_command[0]
        if executable != "getcap":
            return CommandResult(
                safe_command,
                None,
                error="Executable is not permitted by the read-only audit policy",
            )

        if (
            len(safe_command) < 3
            or safe_command[1] != "-r"
            or any(
                not arg
                or arg != arg.strip()
                or arg.startswith("-")
                for arg in safe_command[2:]
            )
        ):
            return CommandResult(
                safe_command,
                None,
                error="Only getcap -r PATH... is permitted",
            )

        effective_timeout = (
            self.default_timeout if timeout is None else timeout
        )
        if (
            isinstance(effective_timeout, bool)
            or not isinstance(effective_timeout, int)
            or effective_timeout < 1
        ):
            return CommandResult(
                safe_command,
                None,
                error="timeout must be a positive integer",
            )

        try:
            executable_path = shutil.which(executable)
        except OSError as exc:
            return CommandResult(
                safe_command,
                None,
                error=f"Unable to locate command: {exc}",
            )

        if executable_path is None:
            return CommandResult(
                safe_command,
                None,
                error=f"Command not found: {executable}",
            )

        try:
            completed = subprocess.run(
                safe_command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
                errors="replace",
            )
            return CommandResult(
                command=safe_command,
                returncode=completed.returncode,
                stdout=self._text(completed.stdout),
                stderr=self._text(completed.stderr),
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command=safe_command,
                returncode=None,
                stdout=self._text(exc.stdout),
                stderr=self._text(exc.stderr),
                error=f"Command timed out after {effective_timeout} seconds",
                timed_out=True,
            )
        except OSError as exc:
            return CommandResult(
                command=safe_command,
                returncode=None,
                error=f"Command execution failed: {exc}",
            )
