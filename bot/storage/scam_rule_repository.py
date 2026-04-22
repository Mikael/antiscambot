from __future__ import annotations

import asyncio
import re
from typing import Any

from motor.motor_asyncio import AsyncIOMotorCollection

from bot.models.scam_rule_set import HighRiskRule, ScamRuleSet


class ScamRuleRepository:
    def __init__(
        self,
        collection: AsyncIOMotorCollection,
        *,
        refresh_interval_seconds: int = 30,
    ) -> None:
        self._collection = collection
        self._refresh_interval_seconds = max(5, refresh_interval_seconds)
        self._lock = asyncio.Lock()
        self._rules = ScamRuleSet(
            blocked_domains=frozenset(),
            blocked_words=tuple(),
            high_risk_rules=tuple(),
        )
        self._refresh_task: asyncio.Task[None] | None = None

    @property
    def rules(self) -> ScamRuleSet:
        return self._rules

    async def start(self) -> None:
        await self.refresh_now()
        self._refresh_task = asyncio.create_task(self._refresh_loop(), name="scam-rules-refresh")

    async def close(self) -> None:
        if self._refresh_task is None:
            return

        self._refresh_task.cancel()
        try:
            await self._refresh_task
        except asyncio.CancelledError:
            pass
        self._refresh_task = None

    async def refresh_now(self) -> None:
        async with self._lock:
            docs = await self._collection.find({}, {"_id": 0}).to_list(length=None)
            self._rules = self._build_rule_set(docs)

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(self._refresh_interval_seconds)
            try:
                await self.refresh_now()
            except Exception:
                continue

    def _build_rule_set(self, docs: list[dict[str, Any]]) -> ScamRuleSet:
        blocked_domains: set[str] = set()
        blocked_words: set[str] = set()
        high_risk_rules: list[HighRiskRule] = []

        for doc in docs:
            kind = str(doc.get("kind", "")).strip().lower()
            if kind == "blocked_domain":
                value = str(doc.get("value", "")).strip().lower()
                if value:
                    blocked_domains.add(value)
                continue

            if kind == "blocked_word":
                value = str(doc.get("value", "")).strip().lower()
                if value:
                    blocked_words.add(value)
                continue

            if kind == "high_risk_pattern":
                pattern_text = str(doc.get("pattern", "")).strip()
                label = str(doc.get("label", "")).strip() or "pattern"
                weight = int(doc.get("weight", 1))
                flags = int(doc.get("flags", re.IGNORECASE))
                if not pattern_text:
                    continue
                try:
                    compiled = re.compile(pattern_text, flags)
                except re.error:
                    continue
                high_risk_rules.append(
                    HighRiskRule(
                        pattern_text=pattern_text,
                        weight=max(1, weight),
                        label=label,
                        flags=flags,
                        pattern=compiled,
                    )
                )

        return ScamRuleSet(
            blocked_domains=frozenset(blocked_domains),
            blocked_words=tuple(sorted(blocked_words)),
            high_risk_rules=tuple(high_risk_rules),
        )
