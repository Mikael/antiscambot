"""Ad-hoc sanity check for core-phrase scoring. Delete when done."""
from bot.services.image_scan_service import (
    CORE_SCAM_PHRASES,
    CORE_SCAM_TOKENS,
    URGENCY_PATTERNS,
)
import re


def normalize(t: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9\s]", " ", t.lower())).strip()


def score_text(text: str):
    lowered = text.lower()
    normalized = normalize(text)
    score = 0
    reasons = []

    phrase_hits = [p for p in CORE_SCAM_PHRASES if p in lowered or p in normalized]
    if phrase_hits:
        if len(phrase_hits) >= 2:
            score += min(8, len(phrase_hits) * 2)
            reasons.append(f"core_phrases({len(phrase_hits)}):{','.join(phrase_hits[:3])}")
        else:
            score += 1
            reasons.append(f"core_phrase_single:{phrase_hits[0]}")

    tokens = set(normalized.split())
    token_hits = sorted(tokens & CORE_SCAM_TOKENS)
    if len(token_hits) >= 2:
        score += min(6, len(token_hits))
        reasons.append(f"core_tokens({len(token_hits)}):{','.join(token_hits[:5])}")

    urg = sum(w for pat, w in URGENCY_PATTERNS if pat.search(lowered))
    if urg >= 4:
        score += min(5, urg)
        reasons.append(f"urgency_patterns:{urg}")

    weighted = score
    core_phrase_hits_count = 0
    for r in reasons:
        if r.startswith("core_phrases("):
            n = int(r.split("(")[1].split(")")[0])
            core_phrase_hits_count = max(core_phrase_hits_count, n)
    weighted += core_phrase_hits_count * 2
    return score, weighted, reasons


tests = {
    "patreon_tier_page": (
        "Your membership Tier 5 per month As a thank you reward, you will "
        "be able to redeem 3 Items of your choice and a Special Present "
        "which contains 10 coupons 3 coins unlimited ToyBattles crown head "
        "accessory 5 battery packs 1000 1x super glue and 1x Upgrade Reset"
    ),
    "patreon_support_chat": (
        "Please note that canceling and re-subscribing to previous donation "
        "will not work. Patreon does not allow this. The last confirmed "
        "paid donation is from April 5th. What happens (very likely) is "
        "that your money will be removed from your account only on the "
        "next amount."
    ),
    "real_crypto_scam": (
        "Congratulations you are the lucky winner! Claim your reward now. "
        "Withdraw your funds in USDT. Limited time offer, claim your bonus "
        "before it expires. Hurry up, last chance!"
    ),
    "nitro_scam": (
        "Free Nitro! Your friend just gifted you Discord Nitro! Claim your "
        "prize now at discord-nitro.xyz"
    ),
    "giveaway_scam": (
        "You have won our celebration promotion. Congratulations you are "
        "selected. Claim your prize and free bonus. Act now! Limited time."
    ),
}

for name, text in tests.items():
    raw, weighted, reasons = score_text(text)
    print(f"{name}")
    print(f"  raw_score      = {raw}")
    print(f"  weighted_score = {weighted}")
    print(f"  reasons        = {reasons}")
    print()
