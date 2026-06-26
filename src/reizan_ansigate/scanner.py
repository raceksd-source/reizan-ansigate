"""Scanner orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from reizan_ansigate.ansi import HiddenSpan, render_terminal
from reizan_ansigate.formatting import context, escaped
from reizan_ansigate.models import Finding, ScanResult, Verdict, merge_verdicts
from reizan_ansigate.normalization import (
    confusable_replacement,
    find_injection_matches,
    has_injection_text,
    invisible_unicode_kind,
    normalize_for_detection,
)

DEFAULT_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
}


@dataclass(frozen=True)
class StrippedText:
    text: str
    starts: list[int]
    ends: list[int]


def scan_path(path: Path | str) -> list[ScanResult]:
    target = Path(path)
    if target.is_dir():
        return [scan_file(file_path) for file_path in _iter_files(target)]
    return [scan_file(target)]


def scan_file(path: Path) -> ScanResult:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return _io_error_result(str(path), exc)
    return scan_bytes(data, path=str(path))


def scan_bytes(data: bytes, path: str = "<stdin>") -> ScanResult:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        finding = Finding(
            path=path,
            kind="decode_error",
            verdict=Verdict.SUSPICIOUS,
            byte_offset=exc.start,
            byte_end=exc.end,
            raw=data[max(0, exc.start - 12) : min(len(data), exc.end + 12)].hex(),
            detail=str(exc),
        )
        return ScanResult(path=path, verdict=Verdict.SUSPICIOUS, findings=[finding], bytes_scanned=len(data))

    starts, ends = _char_offsets(text)
    rendered = render_terminal(text, starts, ends, path)
    findings = list(rendered.findings)

    findings.extend(_unicode_findings(text, starts, ends, path))
    findings.extend(_hidden_instruction_findings(text, rendered.rendered, rendered.hidden_spans, path))
    findings.extend(_raw_rendered_instruction_findings(text, starts, ends, rendered.rendered, rendered.hidden_spans, path))

    verdict = merge_verdicts([finding.verdict for finding in findings])
    return ScanResult(
        path=path,
        verdict=verdict,
        findings=findings,
        bytes_scanned=len(data),
        rendered=rendered.rendered,
    )


def _iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = sorted(dirname for dirname in dirs if dirname not in DEFAULT_SKIP_DIRS)
        for filename in sorted(filenames):
            file_path = Path(current_root) / filename
            if file_path.is_file():
                files.append(file_path)
    return files


def _io_error_result(path: str, exc: OSError) -> ScanResult:
    finding = Finding(
        path=path,
        kind="io_error",
        verdict=Verdict.SUSPICIOUS,
        byte_offset=0,
        byte_end=0,
        detail=str(exc),
    )
    return ScanResult(path=path, verdict=Verdict.SUSPICIOUS, findings=[finding])


def _char_offsets(text: str) -> tuple[list[int], list[int]]:
    starts: list[int] = []
    ends: list[int] = []
    offset = 0
    for char in text:
        starts.append(offset)
        offset += len(char.encode("utf-8"))
        ends.append(offset)
    return starts, ends


def _unicode_findings(text: str, starts: list[int], ends: list[int], path: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, char in enumerate(text):
        invisible_kind = invisible_unicode_kind(char)
        if invisible_kind is not None:
            findings.append(
                Finding(
                    path=path,
                    kind=invisible_kind,
                    verdict=Verdict.SUSPICIOUS,
                    byte_offset=starts[index],
                    byte_end=ends[index],
                    hidden_span=char,
                    raw=escaped(char),
                    detail=f"U+{ord(char):04X} {invisible_kind.replace('_', ' ')}",
                )
            )
        replacement = confusable_replacement(char)
        if replacement is not None:
            findings.append(
                Finding(
                    path=path,
                    kind="homoglyph",
                    verdict=Verdict.SUSPICIOUS,
                    byte_offset=starts[index],
                    byte_end=ends[index],
                    hidden_span=char,
                    raw=escaped(char),
                    rendered=char,
                    detail=f"U+{ord(char):04X} folds to {replacement!r} during detection normalization",
                )
            )
    return findings


def _hidden_instruction_findings(
    raw_text: str,
    rendered_text: str,
    hidden_spans: list[HiddenSpan],
    path: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for span in hidden_spans:
        matches = find_injection_matches(span.text)
        if not matches:
            continue
        raw_context = context(raw_text, _byte_to_char_index(raw_text, span.start), _byte_to_char_index(raw_text, span.end))
        labels = ", ".join(sorted({match.label for match in matches}))
        findings.append(
            Finding(
                path=path,
                kind="hidden_instruction",
                verdict=Verdict.POISONED,
                byte_offset=span.start,
                byte_end=span.end,
                hidden_span=span.text,
                raw=escaped(raw_context),
                rendered=escaped(rendered_text),
                diff=_diff_summary(span.text, rendered_text),
                detail=f"{span.reason}: deterministic matches {labels}",
            )
        )
    return findings


def _raw_rendered_instruction_findings(
    raw_text: str,
    starts: list[int],
    ends: list[int],
    rendered_text: str,
    hidden_spans: list[HiddenSpan],
    path: str,
) -> list[Finding]:
    if not hidden_spans:
        return []
    if has_injection_text(rendered_text):
        return []

    stripped = _strip_ansi_for_detection(raw_text, starts, ends)
    matches = find_injection_matches(stripped.text, stripped.starts, stripped.ends)
    findings: list[Finding] = []
    existing_poison_ranges = {(span.start, span.end) for span in hidden_spans if has_injection_text(span.text)}
    for match in matches:
        if any(start <= match.byte_offset <= end for start, end in existing_poison_ranges):
            continue
        if normalize_for_detection(match.matched_text) in normalize_for_detection(rendered_text):
            continue
        raw_start_char = _byte_to_char_index(raw_text, match.byte_offset)
        raw_end_char = _byte_to_char_index(raw_text, match.byte_end)
        hidden_text = raw_text[raw_start_char:raw_end_char]
        findings.append(
            Finding(
                path=path,
                kind="hidden_instruction",
                verdict=Verdict.POISONED,
                byte_offset=match.byte_offset,
                byte_end=match.byte_end,
                hidden_span=hidden_text,
                raw=escaped(context(raw_text, raw_start_char, raw_end_char)),
                rendered=escaped(rendered_text),
                diff=_diff_summary(hidden_text, rendered_text),
                detail=f"rendered-vs-raw differential: deterministic match {match.label}",
            )
        )
    return findings


def _strip_ansi_for_detection(text: str, starts: list[int], ends: list[int]) -> StrippedText:
    output: list[str] = []
    output_starts: list[int] = []
    output_ends: list[int] = []
    index = 0
    while index < len(text):
        if text[index] != "\x1b":
            output.append(text[index])
            output_starts.append(starts[index])
            output_ends.append(ends[index])
            index += 1
            continue
        next_index = _ansi_sequence_end(text, index)
        if next_index <= index:
            next_index = index + 1
        index = next_index
    return StrippedText("".join(output), output_starts, output_ends)


def _ansi_sequence_end(text: str, index: int) -> int:
    if index + 1 >= len(text):
        return index + 1
    if text[index + 1] == "[":
        cursor = index + 2
        while cursor < len(text) and not ("\x40" <= text[cursor] <= "\x7e"):
            cursor += 1
        return min(len(text), cursor + 1)
    if text[index + 1] == "]":
        cursor = index + 2
        while cursor < len(text):
            if text[cursor] == "\x07":
                return cursor + 1
            if text[cursor] == "\x1b" and cursor + 1 < len(text) and text[cursor + 1] == "\\":
                return cursor + 2
            cursor += 1
        return len(text)
    return min(len(text), index + 2)


def _byte_to_char_index(text: str, byte_offset: int) -> int:
    current = 0
    for index, char in enumerate(text):
        if current >= byte_offset:
            return index
        current += len(char.encode("utf-8"))
    return len(text)


def _diff_summary(hidden_text: str, rendered_text: str) -> str:
    return f"raw_hidden={escaped(hidden_text)} rendered={escaped(rendered_text)}"
