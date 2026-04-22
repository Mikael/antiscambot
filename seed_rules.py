from __future__ import annotations

import asyncio
import re
from motor.motor_asyncio import AsyncIOMotorClient

from bot.core.settings import load_settings


def _sanitize_error_message(message: str) -> str:
    return re.sub(r"mongodb(?:\+srv)?://[^\s\"']+", "mongodb://<redacted>", message, flags=re.IGNORECASE)


DEFAULT_BLOCKED_DOMAINS = [
    "bugamb.at",
    "orbivon.com",
    "hefovex.com",
    "votetesla.com",
]

DEFAULT_BLOCKED_WORDS = [
    "bugamb",
    "mrbeast",
    "elon musk",
    "promo code",
    "activate code for bonus",
    "reward received",
    "withdrawal success",
    "receive usdt",
    "5400 usdt",
    "2500 bonus",
    "receive your $2,500 bonus",
    "receive your $2500 bonus",
    "crypto casino",
    "how to claim your reward",
    "this post will be deleted one hour after publication",
    "limited time",
    "giving away",
    "gift",
]

DEFAULT_HIGH_RISK_PATTERNS = [
    {
        "pattern": r"\\b(?:bugamb\\.at|orbivon\\.com|hefovex\\.com|votetesla\\.com)\\b",
        "weight": 6,
        "label": "blocked_domain",
        "flags": re.IGNORECASE,
    },
    {
        "pattern": r"\\b(?:mr\\s*beast|elon\\s*musk)\\b.*\\b(usdt|btc|bitcoin|wallet|withdraw|bonus|promo\\s*code|crypto\\s*casino)\\b",
        "weight": 5,
        "label": "celebrity_crypto_combo",
        "flags": re.IGNORECASE | re.DOTALL,
    },
    {
        "pattern": r"\\b(withdrawal\\s*success|reward\\s*received|successfully\\s*received|claim\\s*your\\s*reward)\\b",
        "weight": 3,
        "label": "fake_proof_phrase",
        "flags": re.IGNORECASE,
    },
    {
        "pattern": r"\\b(5[, ]?400|2[, ]?500)\\s*(usdt|\\$)?\\b",
        "weight": 2,
        "label": "magic_amount",
        "flags": re.IGNORECASE,
    },
    {
        "pattern": r"\\b(promo\\s*code|activate\\s*code\\s*for\\s*bonus)\\b",
        "weight": 2,
        "label": "promo_bonus_text",
        "flags": re.IGNORECASE,
    },
    {
        "pattern": r"\\b(enter\\s+the\\s+special\\s+promo\\s+code\\s*:\\s*gift|go\\s+to\\s+(?:orbivon\\.com|hefovex\\.com|votetesla\\.com)|receive\\s+your\\s+\\$?2[, ]?500\\s+bonus)\\b",
        "weight": 4,
        "label": "elon_campaign_phrase",
        "flags": re.IGNORECASE,
    },
]


async def seed_rules() -> None:
    settings = load_settings()
    client = AsyncIOMotorClient(settings.mongodb_uri)

    try:
        database = client[settings.mongodb_database]
        collection = database[settings.scam_rules_collection]
        docs = []

        docs.extend({"kind": "blocked_domain", "value": value} for value in DEFAULT_BLOCKED_DOMAINS)
        docs.extend({"kind": "blocked_word", "value": value} for value in DEFAULT_BLOCKED_WORDS)
        docs.extend(
            {
                "kind": "high_risk_pattern",
                "pattern": item["pattern"],
                "weight": item["weight"],
                "label": item["label"],
                "flags": item["flags"],
            }
            for item in DEFAULT_HIGH_RISK_PATTERNS
        )

        for doc in docs:
            if doc["kind"] == "high_risk_pattern":
                query = {
                    "kind": doc["kind"],
                    "pattern": doc["pattern"],
                    "label": doc["label"],
                }
            else:
                query = {
                    "kind": doc["kind"],
                    "value": doc["value"],
                }

            await collection.update_one(query, {"$setOnInsert": doc}, upsert=True)

        print(
            f"Seed completed: {len(docs)} rules ensured in {settings.mongodb_database}.{settings.scam_rules_collection}."
        )
    finally:
        client.close()


if __name__ == "__main__":
    try:
        asyncio.run(seed_rules())
    except Exception as exc:
        print(f"Seed failed: {_sanitize_error_message(str(exc))}")
        raise SystemExit(1) from None
