"""Detection and summary logic for parsed authentication events."""

from __future__ import annotations

from collections import Counter, defaultdict

from .parser import AuthEvent


def analyze(events: list[AuthEvent], threshold: int = 3) -> dict:
    """Summarize sources and flag repeated failures and later successful logins.

    A source is considered repeated when it has at least ``threshold`` failures.
    A success is suspicious when that same IP has already reached the threshold
    earlier in the input file. Input order is used because syslog timestamps
    omit the year and can be ambiguous around year boundaries.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    counts: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    repeated: dict[str, list[AuthEvent]] = defaultdict(list)
    suspicious_successes: list[AuthEvent] = []
    for event in events:
        counts[event.source_ip] += 1
        if event.outcome == "failure":
            failures[event.source_ip] += 1
            if failures[event.source_ip] == threshold:
                repeated[event.source_ip].append(event)
        elif failures[event.source_ip] >= threshold:
            suspicious_successes.append(event)
    return {
        "threshold": threshold,
        "source_counts": dict(counts.most_common()),
        "failure_counts": dict(failures.most_common()),
        "repeated_failure_sources": {ip: len([e for e in events if e.source_ip == ip and e.outcome == "failure"])
                                     for ip in repeated},
        "suspicious_successes": suspicious_successes,
    }
