"""reizan-ansigate CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reizan_ansigate.formatting import escaped
from reizan_ansigate.models import ScanResult, Verdict, merge_verdicts
from reizan_ansigate.scanner import scan_bytes, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="reizan-ansigate")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a file, directory, or stdin for hidden agent injection")
    scan.add_argument("target", help="path to scan, or '-' for stdin")
    scan.add_argument("--json", action="store_true", dest="as_json", help="emit JSON")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        raise AssertionError(f"unknown command: {args.command}")

    if args.target == "-":
        results = [scan_bytes(sys.stdin.buffer.read(), path="<stdin>")]
    else:
        results = scan_path(Path(args.target))

    overall = merge_verdicts([result.verdict for result in results])
    if args.as_json:
        print(json.dumps(_json_report(overall, results), indent=2, sort_keys=True))
    else:
        print(_text_report(overall, results))

    if overall == Verdict.POISONED:
        return 2
    if overall == Verdict.SUSPICIOUS:
        return 1
    return 0


def _json_report(overall: Verdict, results: list[ScanResult]) -> dict[str, object]:
    return {
        "verdict": overall.value,
        "results": [result.to_json() for result in results],
    }


def _text_report(overall: Verdict, results: list[ScanResult]) -> str:
    lines = [f"{overall.value} {len(results)} target(s)"]
    for result in results:
        lines.append(f"{result.verdict.value} {result.path} ({result.bytes_scanned} bytes)")
        for finding in result.findings:
            detail = f" {finding.detail}" if finding.detail else ""
            lines.append(
                f"  - {finding.verdict.value} {finding.kind} "
                f"bytes {finding.byte_offset}:{finding.byte_end}{detail}"
            )
            if finding.hidden_span:
                lines.append(f"    hidden: {escaped(finding.hidden_span)}")
            if finding.diff:
                lines.append(f"    diff: {finding.diff}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
