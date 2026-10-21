"""Parsing helpers for common Linux sshd and login authentication messages."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthEvent:
    """One recognized authentication event from a syslog-style log line."""

    timestamp: str
    source_ip: str
    outcome: str  # "failure" or "success"
    username: str | None
    line_number: int
    raw: str


_TIMESTAMP = re.compile(r"^(?P<stamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+")
_FAILED = re.compile(
    r"Failed\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?:(?:invalid\s+user)\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\w:.%-]+)", re.I
)
_ACCEPTED = re.compile(
    r"Accepted\s+(?:password|publickey|keyboard-interactive/pam)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[\w:.%-]+)", re.I
)
_PAM_FAILURE = re.compile(r"authentication failure;.*?\brhost=(?P<ip>[\w:.%-]+).*?\buser=(?P<user>\S*)", re.I)


def parse_line(line: str, line_number: int = 1) -> AuthEvent | None:
    """Parse a recognized sshd authentication line; return None if unrecognized."""
    timestamp_match = _TIMESTAMP.match(line)
    if not timestamp_match:
        return None
    for pattern, outcome in ((_FAILED, "failure"), (_ACCEPTED, "success"), (_PAM_FAILURE, "failure")):
        match = pattern.search(line)
        if match:
            username = match.groupdict().get("user") or None
            return AuthEvent(timestamp_match.group("stamp"), match.group("ip"), outcome, username, line_number, line.rstrip("\n"))
    return None


def parse_lines(lines: list[str]) -> list[AuthEvent]:
    """Parse lines in file order, preserving original line numbers."""
    events = []
    for number, line in enumerate(lines, start=1):
        event = parse_line(line, number)
        if event is not None:
            events.append(event)
    return events
