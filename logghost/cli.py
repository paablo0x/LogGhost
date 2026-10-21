"""Command-line interface for LogGhost."""

from __future__ import annotations

import argparse
from pathlib import Path

from .analyzer import analyze
from .parser import parse_lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logghost",
        description="Spot repeated failed SSH/login attempts in Linux authentication logs.",
    )
    parser.add_argument("logfile", type=Path, help="path to an auth.log or secure log file")
    parser.add_argument("--threshold", type=int, default=3,
                        help="failures from one IP needed to flag it (default: 3)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.threshold < 1:
        build_parser().error("--threshold must be at least 1")
    try:
        with args.logfile.open("r", encoding="utf-8", errors="replace") as file:
            events = parse_lines(file.readlines())
    except OSError as error:
        print(f"logghost: cannot read {args.logfile}: {error}")
        return 2

    report = analyze(events, args.threshold)
    print(f"LogGhost report for {args.logfile}")
    print(f"Recognized authentication events: {len(events)}")
    print("\nSource IP event counts:")
    if report["source_counts"]:
        for ip, count in report["source_counts"].items():
            print(f"  {ip}: {count}")
    else:
        print("  (none found)")
    print(f"\nRepeated failed attempts (threshold: {args.threshold}):")
    if report["repeated_failure_sources"]:
        for ip, count in report["repeated_failure_sources"].items():
            print(f"  {ip}: {count} failed attempts")
    else:
        print("  (none found)")
    print("\nSuccessful logins after repeated failures:")
    if report["suspicious_successes"]:
        for event in report["suspicious_successes"]:
            print(f"  {event.timestamp} | {event.source_ip} | user={event.username or 'unknown'} | line {event.line_number}")
    else:
        print("  (none found)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
