from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class ScanResult:
    score: int
    reasons: list[str]
    domains_found: list[str]
    text_snippet: str

    @property
    def is_scam(self) -> bool:
        return self.score > 0
