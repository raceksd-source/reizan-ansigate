"""Public result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    POISONED = "POISONED"


VERDICT_RANK = {
    Verdict.CLEAN: 0,
    Verdict.SUSPICIOUS: 1,
    Verdict.POISONED: 2,
}


def merge_verdicts(verdicts: list[Verdict]) -> Verdict:
    if not verdicts:
        return Verdict.CLEAN
    return max(verdicts, key=lambda verdict: VERDICT_RANK[verdict])


@dataclass(frozen=True)
class Finding:
    path: str
    kind: str
    verdict: Verdict
    byte_offset: int
    byte_end: int
    hidden_span: str = ""
    raw: str = ""
    rendered: str = ""
    diff: str = ""
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "verdict": self.verdict.value,
            "byte_offset": self.byte_offset,
            "byte_end": self.byte_end,
            "hidden_span": self.hidden_span,
            "raw": self.raw,
            "rendered": self.rendered,
            "diff": self.diff,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ScanResult:
    path: str
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    bytes_scanned: int = 0
    rendered: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "verdict": self.verdict.value,
            "bytes_scanned": self.bytes_scanned,
            "findings": [finding.to_json() for finding in self.findings],
        }
