from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class HighRiskRule:
    pattern_text: str
    weight: int
    label: str
    flags: int
    pattern: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class ScamRuleSet:
    blocked_domains: frozenset[str]
    blocked_words: tuple[str, ...]
    high_risk_rules: tuple[HighRiskRule, ...]
