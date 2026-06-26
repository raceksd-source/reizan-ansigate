"""NFKC plus translate normalization for deterministic detection."""

from __future__ import annotations

from dataclasses import dataclass
import re
from collections.abc import Sequence
import unicodedata

ZERO_WIDTH_CHARS = {
    ord("\u200b"): None,
    ord("\u200c"): None,
    ord("\u200d"): None,
    ord("\ufeff"): None,
}

BIDI_CHARS = {codepoint: None for codepoint in range(0x202A, 0x202F)}
BIDI_CHARS.update({codepoint: None for codepoint in range(0x2066, 0x206A)})

TAG_CHARS = {codepoint: None for codepoint in range(0xE0000, 0xE0080)}

HYPHEN_CHARS = {
    ord("\u2010"): "-",
    ord("\u2011"): "-",
    ord("\u2012"): "-",
    ord("\u2013"): "-",
    ord("\u2014"): "-",
    ord("\u2015"): "-",
    ord("\u2043"): "-",
    ord("\u2212"): "-",
}

CONFUSABLE_CHARS = {
    ord("А"): "A",
    ord("В"): "B",
    ord("Е"): "E",
    ord("К"): "K",
    ord("М"): "M",
    ord("Н"): "H",
    ord("О"): "O",
    ord("Р"): "P",
    ord("С"): "C",
    ord("Т"): "T",
    ord("Х"): "X",
    ord("а"): "a",
    ord("е"): "e",
    ord("о"): "o",
    ord("р"): "p",
    ord("с"): "c",
    ord("у"): "y",
    ord("х"): "x",
    ord("І"): "I",
    ord("і"): "i",
    ord("Ј"): "J",
    ord("ј"): "j",
    ord("Ѕ"): "S",
    ord("ѕ"): "s",
    ord("Α"): "A",
    ord("Β"): "B",
    ord("Ε"): "E",
    ord("Ζ"): "Z",
    ord("Η"): "H",
    ord("Ι"): "I",
    ord("Κ"): "K",
    ord("Μ"): "M",
    ord("Ν"): "N",
    ord("Ο"): "O",
    ord("Ρ"): "P",
    ord("Τ"): "T",
    ord("Υ"): "Y",
    ord("Χ"): "X",
    ord("α"): "a",
    ord("β"): "b",
    ord("γ"): "y",
    ord("δ"): "d",
    ord("ε"): "e",
    ord("ι"): "i",
    ord("κ"): "k",
    ord("ν"): "v",
    ord("ο"): "o",
    ord("ρ"): "p",
    ord("τ"): "t",
    ord("υ"): "u",
    ord("χ"): "x",
}

DETECTION_TRANSLATE = (
    ZERO_WIDTH_CHARS
    | BIDI_CHARS
    | TAG_CHARS
    | HYPHEN_CHARS
    | CONFUSABLE_CHARS
)


@dataclass(frozen=True)
class NormalizedText:
    text: str
    start_offsets: list[int]
    end_offsets: list[int]


@dataclass(frozen=True)
class InjectionMatch:
    label: str
    matched_text: str
    start: int
    end: int
    byte_offset: int
    byte_end: int


INSTRUCTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "override_prior_instructions",
        re.compile(
            r"\b(disregard|ignore|forget|override|bypass)\s+"
            r"(all\s+)?(previous|prior|above|earlier)\s+"
            r"(instructions|directives|rules|prompts)\b"
        ),
    ),
    (
        "delete_tests_or_code",
        re.compile(r"\b(delete|remove|wipe)\s+(all\s+)?([\w.-]+\s+)?(tests?|test\s+files|source|code)\b"),
    ),
    (
        "agent_directive",
        re.compile(
            r"\b(if\s+you\s+are\s+(an?\s+)?(ai|coding)\s+agent|ai\s+agent|coding\s+agent)\b"
            r".{0,120}\b(must|should|shall|do\s+not|don't|ignore|delete|remove)\b"
        ),
    ),
    (
        "prompt_extraction",
        re.compile(r"\b(reveal|print|dump|show)\s+(the\s+)?(system|developer)\s+(prompt|instructions|message)\b"),
    ),
    (
        "secret_exfiltration",
        re.compile(r"\b(exfiltrate|steal|leak|upload|send)\b.{0,80}\b(secret|token|key|credential|password)s?\b"),
    ),
    (
        "shell_execution",
        re.compile(r"\b(run|execute)\s+.{0,40}\b(rm\s+-rf|curl|wget|bash|sh|powershell|pwsh)\b"),
    ),
)


def normalize_for_detection(text: str) -> str:
    return normalize_with_offsets(text).text


def normalize_with_offsets(
    text: str,
    start_offsets: Sequence[int] | None = None,
    end_offsets: Sequence[int] | None = None,
) -> NormalizedText:
    normalized_chars: list[str] = []
    normalized_starts: list[int] = []
    normalized_ends: list[int] = []

    for index, char in enumerate(text):
        start = start_offsets[index] if start_offsets is not None else index
        end = end_offsets[index] if end_offsets is not None else start + len(char.encode("utf-8"))
        for folded in unicodedata.normalize("NFKC", char):
            replacement = DETECTION_TRANSLATE.get(ord(folded), folded)
            if replacement is None:
                continue
            if isinstance(replacement, int):
                replacement = chr(replacement)
            for output_char in replacement:
                normalized_chars.append(output_char.casefold())
                normalized_starts.append(start)
                normalized_ends.append(end)

    return NormalizedText("".join(normalized_chars), normalized_starts, normalized_ends)


def find_injection_matches(
    text: str,
    start_offsets: Sequence[int] | None = None,
    end_offsets: Sequence[int] | None = None,
) -> list[InjectionMatch]:
    normalized = normalize_with_offsets(text, start_offsets, end_offsets)
    matches: list[InjectionMatch] = []
    for label, pattern in INSTRUCTION_PATTERNS:
        for match in pattern.finditer(normalized.text):
            if match.start() >= len(normalized.start_offsets):
                continue
            end_index = max(match.end() - 1, match.start())
            byte_offset = normalized.start_offsets[match.start()]
            byte_end = normalized.end_offsets[end_index]
            matches.append(
                InjectionMatch(
                    label=label,
                    matched_text=match.group(0),
                    start=match.start(),
                    end=match.end(),
                    byte_offset=byte_offset,
                    byte_end=byte_end,
                )
            )
    return matches


def has_injection_text(text: str) -> bool:
    return bool(find_injection_matches(text))


def invisible_unicode_kind(char: str) -> str | None:
    codepoint = ord(char)
    if codepoint in ZERO_WIDTH_CHARS:
        return "zero_width"
    if 0x202A <= codepoint <= 0x202E or 0x2066 <= codepoint <= 0x2069:
        return "bidi_control"
    if 0xE0000 <= codepoint <= 0xE007F:
        return "unicode_tag"
    return None


def confusable_replacement(char: str) -> str | None:
    replacement = CONFUSABLE_CHARS.get(ord(char))
    if replacement is None:
        return None
    if isinstance(replacement, int):
        return chr(replacement)
    return replacement
