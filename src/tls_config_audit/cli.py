"""Command-line interface for tls-config-audit."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from typing import Sequence, TextIO

from . import __version__
from .audit import Finding, Severity, audit_file

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tls-config-audit",
        description="Audit nginx and Apache TLS configuration for weak settings.",
    )
    parser.add_argument("paths", nargs="+", metavar="FILE", help="configuration file(s) to audit")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    parser.add_argument(
        "--fail-on",
        default="high",
        metavar="SEVERITY",
        help="exit with code 1 when a finding reaches this severity: low, medium, high, critical (default: high)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _summary(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(str(f.severity) for f in findings)
    return {str(s): counts[str(s)] for s in sorted(Severity, reverse=True) if counts[str(s)]}


def _write_text(out: TextIO, path: str, findings: list[Finding]) -> None:
    if not findings:
        out.write(f"{path}: no findings\n")
        return
    out.write(f"{path}: {len(findings)} finding(s)\n\n")
    for f in findings:
        where = f"line {f.line}" if f.line else "file"
        out.write(f"  [{f.rule_id}] {str(f.severity).upper():<8} {f.message} ({where})\n")
        out.write(f"  {' ' * len(f.rule_id)}   -> {f.remediation}\n\n")
    parts = ", ".join(f"{n} {sev}" for sev, n in _summary(findings).items())
    out.write(f"Summary: {parts}\n")


def main(argv: Sequence[str] | None = None, out: TextIO = sys.stdout, err: TextIO = sys.stderr) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        threshold = Severity.parse(args.fail_on)
    except ValueError as exc:
        parser.error(str(exc))

    results: dict[str, list[Finding]] = {}
    for path in args.paths:
        try:
            results[path] = audit_file(path)
        except (OSError, UnicodeDecodeError) as exc:
            err.write(f"error: cannot read {path}: {exc}\n")
            return EXIT_ERROR

    if args.format == "json":
        payload = [
            {"file": path, "summary": _summary(fs), "findings": [f.to_dict() for f in fs]}
            for path, fs in results.items()
        ]
        json.dump(payload, out, indent=2)
        out.write("\n")
    else:
        for i, (path, fs) in enumerate(results.items()):
            if i:
                out.write("\n")
            _write_text(out, path, fs)

    worst = max((f.severity for fs in results.values() for f in fs), default=0)
    return EXIT_FINDINGS if worst >= threshold else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
