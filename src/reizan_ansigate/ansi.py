"""Minimal terminal renderer for hidden-byte differential detection."""

from __future__ import annotations

from dataclasses import dataclass
import re

from reizan_ansigate.formatting import escaped
from reizan_ansigate.models import Finding, Verdict
from reizan_ansigate.normalization import invisible_unicode_kind

CSI_CURSOR_FINALS = {"A", "B", "C", "D", "E", "F", "G", "H", "f"}
CSI_ERASE_FINALS = {"J", "K"}


@dataclass(frozen=True)
class Cell:
    char: str
    start: int
    end: int


@dataclass(frozen=True)
class HiddenSpan:
    reason: str
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class RenderResult:
    rendered: str
    hidden_spans: list[HiddenSpan]
    findings: list[Finding]


class TerminalRenderer:
    def __init__(self, text: str, starts: list[int], ends: list[int], path: str) -> None:
        self.text = text
        self.starts = starts
        self.ends = ends
        self.path = path
        self.lines: list[list[Cell | None]] = [[]]
        self.row = 0
        self.col = 0
        self.hidden_spans: list[HiddenSpan] = []
        self.findings: list[Finding] = []
        self.fg: tuple[str, int | tuple[int, int, int]] | None = None
        self.bg: tuple[str, int | tuple[int, int, int]] | None = None
        self.conceal = False

    def render(self) -> RenderResult:
        index = 0
        while index < len(self.text):
            char = self.text[index]
            if char == "\x1b":
                index = self._consume_escape(index)
                continue
            if char == "\r":
                if index + 1 < len(self.text) and self.text[index + 1] == "\n":
                    self._newline()
                    index += 2
                    continue
                self._finding(
                    "carriage_return",
                    Verdict.SUSPICIOUS,
                    self.starts[index],
                    self.ends[index],
                    raw=char,
                    detail="standalone carriage return can overwrite terminal-visible text",
                )
                self.col = 0
                index += 1
                continue
            if char == "\n":
                self._newline()
                index += 1
                continue
            if char == "\b":
                self._finding(
                    "backspace",
                    Verdict.SUSPICIOUS,
                    self.starts[index],
                    self.ends[index],
                    raw=char,
                    detail="backspace can overwrite terminal-visible text",
                )
                self.col = max(0, self.col - 1)
                index += 1
                continue
            invisible_kind = invisible_unicode_kind(char)
            if invisible_kind is not None:
                self.hidden_spans.append(
                    HiddenSpan(invisible_kind, self.starts[index], self.ends[index], char)
                )
                index += 1
                continue
            if ord(char) < 0x20 and char != "\t":
                self._finding(
                    "control_character",
                    Verdict.SUSPICIOUS,
                    self.starts[index],
                    self.ends[index],
                    raw=char,
                    detail=f"C0 control U+{ord(char):04X}",
                )
                index += 1
                continue
            self._put_char(char, self.starts[index], self.ends[index])
            index += 1

        return RenderResult(self._rendered_text(), _coalesce_hidden(self.hidden_spans), self.findings)

    def _current_line(self) -> list[Cell | None]:
        while self.row >= len(self.lines):
            self.lines.append([])
        return self.lines[self.row]

    def _newline(self) -> None:
        self.row += 1
        self.col = 0
        while self.row >= len(self.lines):
            self.lines.append([])

    def _put_char(self, char: str, start: int, end: int) -> None:
        line = self._current_line()
        while len(line) < self.col:
            line.append(None)

        if self._style_hidden():
            if self.col < len(line) and line[self.col] is not None:
                self._hide_cells([line[self.col]], "ansi_sgr_hidden_overwrite")
            if self.col == len(line):
                line.append(None)
            else:
                line[self.col] = None
            self.hidden_spans.append(HiddenSpan("ansi_sgr_hidden", start, end, char))
            self.col += 1
            return

        if self.col < len(line) and line[self.col] is not None:
            self._hide_cells([line[self.col]], "overwrite")

        cell = Cell(char, start, end)
        if self.col == len(line):
            line.append(cell)
        else:
            line[self.col] = cell
        self.col += 1

    def _hide_cells(self, cells: list[Cell | None], reason: str) -> None:
        visible_cells = [cell for cell in cells if cell is not None]
        if not visible_cells:
            return
        start = min(cell.start for cell in visible_cells)
        end = max(cell.end for cell in visible_cells)
        text = "".join(cell.char for cell in sorted(visible_cells, key=lambda cell: cell.start))
        self.hidden_spans.append(HiddenSpan(reason, start, end, text))

    def _consume_escape(self, index: int) -> int:
        if index + 1 >= len(self.text):
            self._parse_error(index, len(self.text), "trailing ESC byte")
            return len(self.text)

        next_char = self.text[index + 1]
        if next_char == "[":
            return self._consume_csi(index)
        if next_char == "]":
            return self._consume_osc(index)

        end_index = min(index + 2, len(self.text))
        self._finding(
            "ansi_escape",
            Verdict.SUSPICIOUS,
            self.starts[index],
            self.ends[end_index - 1],
            raw=self.text[index:end_index],
            detail="non-CSI ANSI escape sequence",
        )
        return end_index

    def _consume_csi(self, index: int) -> int:
        cursor = index + 2
        while cursor < len(self.text) and not ("\x40" <= self.text[cursor] <= "\x7e"):
            cursor += 1
        if cursor >= len(self.text):
            self._parse_error(index, len(self.text), "unterminated CSI sequence")
            return len(self.text)

        sequence = self.text[index : cursor + 1]
        final = self.text[cursor]
        params = sequence[2:-1]
        start = self.starts[index]
        end = self.ends[cursor]

        verdict = Verdict.CLEAN
        kind = "ansi_escape"
        detail = f"CSI {final}"
        if final in CSI_ERASE_FINALS:
            verdict = Verdict.SUSPICIOUS
            kind = "ansi_erase"
            detail = f"CSI {final} erase operation can hide prior bytes"
        elif final in CSI_CURSOR_FINALS:
            verdict = Verdict.SUSPICIOUS
            kind = "ansi_cursor"
            detail = f"CSI {final} cursor movement can overwrite prior bytes"

        self._finding(kind, verdict, start, end, raw=sequence, detail=detail)
        numbers = _parse_csi_numbers(params)
        if final == "m":
            self._handle_sgr(numbers)
            if self._style_hidden():
                self._finding(
                    "ansi_sgr_hidden",
                    Verdict.SUSPICIOUS,
                    start,
                    end,
                    raw=sequence,
                    detail="SGR style conceals text or sets matching foreground/background colors",
                )
        elif final == "K":
            self._handle_erase_line(numbers)
        elif final == "J":
            self._handle_erase_display(numbers)
        elif final in CSI_CURSOR_FINALS:
            self._handle_cursor(final, numbers)
        return cursor + 1

    def _consume_osc(self, index: int) -> int:
        cursor = index + 2
        terminator_end: int | None = None
        while cursor < len(self.text):
            if self.text[cursor] == "\x07":
                terminator_end = cursor + 1
                break
            if self.text[cursor] == "\x1b" and cursor + 1 < len(self.text) and self.text[cursor + 1] == "\\":
                terminator_end = cursor + 2
                break
            cursor += 1
        if terminator_end is None:
            self._parse_error(index, len(self.text), "unterminated OSC sequence")
            return len(self.text)

        sequence = self.text[index:terminator_end]
        content_start = index + 2
        content_end = terminator_end - 1
        if self.text[terminator_end - 1] == "\\":
            content_end = terminator_end - 2
        content = self.text[content_start:content_end]
        if content:
            self.hidden_spans.append(
                HiddenSpan("ansi_osc", self.starts[content_start], self.ends[content_end - 1], content)
            )
        self._finding(
            "ansi_osc",
            Verdict.SUSPICIOUS,
            self.starts[index],
            self.ends[terminator_end - 1],
            raw=sequence,
            detail="OSC sequence is invisible in normal terminal output",
        )
        return terminator_end

    def _handle_sgr(self, params: list[int]) -> None:
        if not params:
            params = [0]
        index = 0
        while index < len(params):
            code = params[index]
            if code == 0:
                self.fg = None
                self.bg = None
                self.conceal = False
            elif code == 8:
                self.conceal = True
            elif code == 28:
                self.conceal = False
            elif code == 39:
                self.fg = None
            elif code == 49:
                self.bg = None
            elif 30 <= code <= 37:
                self.fg = ("ansi", code - 30)
            elif 90 <= code <= 97:
                self.fg = ("ansi", code - 90 + 8)
            elif 40 <= code <= 47:
                self.bg = ("ansi", code - 40)
            elif 100 <= code <= 107:
                self.bg = ("ansi", code - 100 + 8)
            elif code in (38, 48):
                parsed = _parse_extended_color(params, index)
                if parsed is not None:
                    color, consumed = parsed
                    if code == 38:
                        self.fg = color
                    else:
                        self.bg = color
                    index += consumed
            index += 1

    def _handle_erase_line(self, params: list[int]) -> None:
        mode = params[0] if params else 0
        line = self._current_line()
        if mode == 2:
            self._hide_cells(line, "ansi_erase_line")
            for index in range(len(line)):
                line[index] = None
            return
        if mode == 1:
            cells = line[: min(self.col + 1, len(line))]
            self._hide_cells(cells, "ansi_erase_line")
            for index in range(min(self.col + 1, len(line))):
                line[index] = None
            return
        cells = line[self.col :]
        self._hide_cells(cells, "ansi_erase_line")
        for index in range(self.col, len(line)):
            line[index] = None

    def _handle_erase_display(self, params: list[int]) -> None:
        mode = params[0] if params else 0
        if mode != 2:
            return
        for line in self.lines:
            self._hide_cells(line, "ansi_erase_display")
        self.lines = [[]]
        self.row = 0
        self.col = 0

    def _handle_cursor(self, final: str, params: list[int]) -> None:
        amount = params[0] if params and params[0] > 0 else 1
        if final == "A":
            self.row = max(0, self.row - amount)
        elif final in {"B", "E"}:
            self.row += amount
            while self.row >= len(self.lines):
                self.lines.append([])
            if final == "E":
                self.col = 0
        elif final == "C":
            self.col += amount
        elif final in {"D", "F"}:
            self.col = max(0, self.col - amount)
            if final == "F":
                self.row = max(0, self.row - amount)
        elif final == "G":
            self.col = max(0, amount - 1)
        elif final in {"H", "f"}:
            row = params[0] if len(params) >= 1 and params[0] > 0 else 1
            col = params[1] if len(params) >= 2 and params[1] > 0 else 1
            self.row = row - 1
            self.col = col - 1
            while self.row >= len(self.lines):
                self.lines.append([])

    def _style_hidden(self) -> bool:
        return self.conceal or (self.fg is not None and self.fg == self.bg)

    def _rendered_text(self) -> str:
        rendered_lines = []
        for line in self.lines:
            rendered_lines.append("".join(cell.char if cell is not None else " " for cell in line).rstrip(" "))
        return "\n".join(rendered_lines).rstrip("\n")

    def _parse_error(self, start_index: int, end_index: int, detail: str) -> None:
        end_index = max(start_index + 1, min(end_index, len(self.text)))
        self._finding(
            "parse_error",
            Verdict.SUSPICIOUS,
            self.starts[start_index],
            self.ends[end_index - 1],
            raw=self.text[start_index:end_index],
            detail=detail,
        )

    def _finding(
        self,
        kind: str,
        verdict: Verdict,
        start: int,
        end: int,
        *,
        raw: str = "",
        detail: str = "",
    ) -> None:
        self.findings.append(
            Finding(
                path=self.path,
                kind=kind,
                verdict=verdict,
                byte_offset=start,
                byte_end=end,
                raw=escaped(raw),
                detail=detail,
            )
        )


def render_terminal(text: str, starts: list[int], ends: list[int], path: str) -> RenderResult:
    return TerminalRenderer(text, starts, ends, path).render()


def _parse_csi_numbers(params: str) -> list[int]:
    if not params:
        return []
    cleaned = re.sub(r"[?=><]", "", params).replace(":", ";")
    numbers: list[int] = []
    for part in cleaned.split(";"):
        if part == "":
            numbers.append(0)
            continue
        try:
            numbers.append(int(part))
        except ValueError:
            numbers.append(0)
    return numbers


def _parse_extended_color(
    params: list[int],
    index: int,
) -> tuple[tuple[str, int | tuple[int, int, int]], int] | None:
    if index + 2 < len(params) and params[index + 1] == 5:
        return ("8bit", params[index + 2]), 2
    if index + 4 < len(params) and params[index + 1] == 2:
        rgb = (params[index + 2], params[index + 3], params[index + 4])
        return ("rgb", rgb), 4
    return None


def _coalesce_hidden(spans: list[HiddenSpan]) -> list[HiddenSpan]:
    if not spans:
        return []
    ordered = sorted(spans, key=lambda span: (span.start, span.end, span.reason))
    coalesced = [ordered[0]]
    for span in ordered[1:]:
        current = coalesced[-1]
        if span.reason == current.reason and span.start <= current.end:
            coalesced[-1] = HiddenSpan(
                current.reason,
                current.start,
                max(current.end, span.end),
                current.text + span.text,
            )
        else:
            coalesced.append(span)
    return coalesced
