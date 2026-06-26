"""Stable text formatting helpers for reports."""

from __future__ import annotations


def escaped(text: str, limit: int = 180) -> str:
    rendered = text.encode("unicode_escape").decode("ascii")
    if len(rendered) <= limit:
        return rendered
    return rendered[: limit - 3] + "..."


def context(text: str, start: int, end: int, radius: int = 80) -> str:
    prefix_start = max(0, start - radius)
    suffix_end = min(len(text), end + radius)
    return text[prefix_start:suffix_end]
