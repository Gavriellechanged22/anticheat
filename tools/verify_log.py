#!/usr/bin/env python3
"""Verify the integrity of anticheat JSON Lines logs.

Every emitted line ends with the integrity suffix

    ,"chain":"<64 hex characters>"}

and the value is defined as

    chain[0] = seed                                  (from log_segment_opened)
    chain[i] = SHA256(chain[i-1] || body[i])

where ``body[i]`` is the exact bytes of the line before the integrity suffix.
A verifier can therefore detect any edited, reordered, removed or appended
line without trusting the agent that produced the file.

Usage:
    verify_log.py events.jsonl [events.jsonl.1 ...]
    verify_log.py --self-test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

CHAIN_MARKER = b',"chain":"'
CHAIN_HEX_LENGTH = 64
SEGMENT_EVENT = "log_segment_opened"


@dataclass
class Report:
    lines: int = 0
    segments: int = 0
    events: dict[str, int] = field(default_factory=dict)
    severities: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _split_line(raw: bytes) -> tuple[bytes, str]:
    """Return the hashed body and the recorded chain value of one log line."""
    position = raw.rfind(CHAIN_MARKER)
    if position < 0:
        raise ValueError("missing chain suffix")

    body = raw[:position]
    suffix = raw[position + len(CHAIN_MARKER) :]
    if len(suffix) != CHAIN_HEX_LENGTH + 2 or not suffix.endswith(b'"}'):
        raise ValueError("malformed chain suffix")

    chain = suffix[:CHAIN_HEX_LENGTH].decode("ascii")
    int(chain, 16)  # raises ValueError when the digest is not hexadecimal
    return body, chain


def verify_streams(streams: Iterable[tuple[str, bytes]]) -> Report:
    report = Report()
    chain: bytes | None = None
    expected_sequence: int | None = None

    for name, blob in streams:
        for number, raw in enumerate(blob.split(b"\n"), start=1):
            if not raw.strip():
                continue

            location = f"{name}:{number}"
            report.lines += 1

            try:
                body, recorded = _split_line(raw)
            except ValueError as error:
                report.problems.append(f"{location}: {error}")
                continue

            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                report.problems.append(f"{location}: not valid JSON ({error})")
                continue

            event = document.get("event", "<missing>")
            report.events[event] = report.events.get(event, 0) + 1
            severity = document.get("severity", "<missing>")
            report.severities[severity] = report.severities.get(severity, 0) + 1

            sequence = document.get("seq")
            if not isinstance(sequence, int):
                report.problems.append(f"{location}: missing numeric seq")
            elif expected_sequence is not None and sequence != expected_sequence:
                report.problems.append(
                    f"{location}: seq gap, expected {expected_sequence} got {sequence}"
                )
                expected_sequence = sequence
            if isinstance(sequence, int):
                expected_sequence = sequence + 1

            if event == SEGMENT_EVENT:
                seed = document.get("details", {}).get("chain_seed")
                if isinstance(seed, str):
                    report.segments += 1
                    try:
                        chain = bytes.fromhex(seed)
                    except ValueError:
                        report.problems.append(f"{location}: malformed chain_seed")
                        chain = None

            if chain is None:
                report.problems.append(
                    f"{location}: no chain seed established yet, cannot verify"
                )
                continue

            computed = hashlib.sha256(chain + body).hexdigest()
            if computed != recorded:
                report.problems.append(
                    f"{location}: chain mismatch (event={event}, seq={sequence})"
                )
            chain = bytes.fromhex(computed)

    if report.lines == 0:
        report.problems.append("no log lines found")
    return report


def verify_files(paths: Sequence[Path]) -> Report:
    streams = []
    for path in paths:
        try:
            streams.append((path.name, path.read_bytes()))
        except OSError as error:
            report = Report()
            report.problems.append(f"{path}: {error}")
            return report
    return verify_streams(streams)


def _build_synthetic_log(corrupt: bool = False) -> bytes:
    seed = hashlib.sha256(b"self-test").digest()
    bodies = [
        '{"seq":1,"timestamp":"2026-01-01T00:00:00.000Z","severity":"info",'
        '"event":"log_segment_opened","pid":0,"details":{"chain_seed":"%s"}'
        % seed.hex(),
        '{"seq":2,"timestamp":"2026-01-01T00:00:01.000Z","severity":"high",'
        '"event":"suspicious_executable_region","pid":42,"details":{"reason":"x"}',
        '{"seq":3,"timestamp":"2026-01-01T00:00:02.000Z","severity":"info",'
        '"event":"scan_completed","pid":42,"details":{"scan_id":1}',
    ]

    chain = seed
    lines = []
    for body in bodies:
        encoded = body.encode("utf-8")
        chain = hashlib.sha256(chain + encoded).digest()
        lines.append(encoded + CHAIN_MARKER + chain.hex().encode("ascii") + b'"}')

    if corrupt:
        lines[1] = lines[1].replace(b'"pid":42', b'"pid":43')
    return b"\n".join(lines) + b"\n"


def _self_test() -> int:
    good = verify_streams([("synthetic", _build_synthetic_log())])
    if not good.ok:
        print("self-test FAILED: clean log rejected", file=sys.stderr)
        for problem in good.problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    if good.lines != 3 or good.segments != 1:
        print(f"self-test FAILED: unexpected counts {good}", file=sys.stderr)
        return 1

    tampered = verify_streams([("synthetic", _build_synthetic_log(corrupt=True))])
    if tampered.ok:
        print("self-test FAILED: tampered log accepted", file=sys.stderr)
        return 1

    dropped = _build_synthetic_log().split(b"\n")
    removed = verify_streams([("synthetic", b"\n".join([dropped[0], dropped[2]]))])
    if removed.ok:
        print("self-test FAILED: truncated log accepted", file=sys.stderr)
        return 1

    print("self-test passed: clean log accepted, edited and truncated logs rejected")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", type=Path, help="log files, oldest first")
    parser.add_argument("--self-test", action="store_true", help="validate this tool")
    parser.add_argument("--quiet", action="store_true", help="only print problems")
    arguments = parser.parse_args(argv)

    if arguments.self_test:
        return _self_test()
    if not arguments.paths:
        parser.error("provide at least one log file or --self-test")

    report = verify_files(arguments.paths)

    if not arguments.quiet:
        print(f"lines:    {report.lines}")
        print(f"segments: {report.segments}")
        if report.events:
            print("events:")
            for name, count in sorted(report.events.items(), key=lambda item: -item[1]):
                print(f"  {count:6d}  {name}")
        if report.severities:
            ordered = ["high", "medium", "low", "info"]
            summary = "  ".join(
                f"{level}={report.severities[level]}"
                for level in ordered
                if level in report.severities
            )
            print(f"severity: {summary}")

    if report.ok:
        print("integrity: OK")
        return 0

    print(f"integrity: FAILED ({len(report.problems)} problem(s))", file=sys.stderr)
    for problem in report.problems[:50]:
        print(f"  {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
