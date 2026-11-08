"""Helpers for safely rendering untrusted text in terminal-oriented output."""

from typing import Any


def escape_terminal_text(value: str) -> str:
    """Render non-printable characters as visible escape sequences.

    Printable Unicode characters are preserved. Control characters and
    other non-printable code points are represented without emitting them
    literally, preventing terminal control and line-layout manipulation.
    """
    if not isinstance(value, str):
        raise TypeError("value must be a string")

    escaped = []

    for character in value:
        if character.isprintable():
            escaped.append(character)
            continue

        codepoint = ord(character)
        if codepoint <= 0xFF:
            escaped.append(f"\\x{codepoint:02x}")
        elif codepoint <= 0xFFFF:
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(f"\\U{codepoint:08x}")

    return "".join(escaped)


def sanitize_terminal_data(value: Any) -> Any:
    """Return a recursively sanitized copy of report data.

    Dictionaries, lists, and tuples are copied. Original report structures
    and values are not modified.
    """
    if isinstance(value, str):
        return escape_terminal_text(value)

    if isinstance(value, dict):
        return {
            key: sanitize_terminal_data(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [sanitize_terminal_data(item) for item in value]

    if isinstance(value, tuple):
        return tuple(sanitize_terminal_data(item) for item in value)

    return value
