from __future__ import annotations

import argparse
import asyncio
import os
import re
import shutil
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from time import perf_counter
from pathlib import Path

from motor.motor_asyncio import AsyncIOMotorClient
from PIL import Image, ImageEnhance, ImageFilter, ImageOps
import pytesseract

from bot.core.settings import load_settings

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}
DOMAIN_RE = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.IGNORECASE)
TOKEN_RE = re.compile(r"[a-z0-9$]{3,}", re.IGNORECASE)

SAFE_DOMAINS = {
    "discord.com",
    "discord.gg",
    "youtube.com",
    "youtu.be",
    "twitter.com",
    "x.com",
    "instagram.com",
    "facebook.com",
    "tiktok.com",
    "google.com",
    "telegram.org",
}

CRYPTO_ANCHORS = {
    "btc",
    "bitcoin",
    "usdt",
    "crypto",
    "wallet",
    "withdraw",
    "bonus",
    "promo",
    "gift",
    "claim",
    "reward",
    "code",
}

SUSPICIOUS_PHRASES = {
    "promo code",
    "activate code",
    "reward received",
    "withdrawal success",
    "claim your reward",
    "receive usdt",
    "limited time",
    "giving away",
    "crypto casino",
}


def iter_images(folder: Path):
    for p in folder.rglob("*"):
        if p.is_file() and p.suffix.lower() in IMAGE_EXTENSIONS:
            yield p


def preprocess(img: Image.Image) -> Image.Image:
    gray = ImageOps.grayscale(img)
    contrast = ImageEnhance.Contrast(gray).enhance(1.8)
    sharp = contrast.filter(ImageFilter.SHARPEN)
    w, h = sharp.size
    if w < 1280:
        scale = 1280 / max(1, w)
        sharp = sharp.resize((int(w * scale), int(h * scale)))
    return sharp


def find_tesseract(custom_path: str | None) -> str | None:
    candidates: list[Path] = []

    if custom_path:
        candidates.append(Path(os.path.expandvars(custom_path)).expanduser())

    from_path = shutil.which("tesseract")
    if from_path:
        candidates.append(Path(from_path))

    env_cmd = os.environ.get("TESSERACT_CMD", "").strip()
    if env_cmd:
        candidates.append(Path(os.path.expandvars(env_cmd)).expanduser())

    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if local_app_data:
            candidates.append(Path(local_app_data) / "Programs" / "Tesseract-OCR" / "tesseract.exe")

        candidates.extend(
            [
                Path(r"C:\Program Files\Tesseract-OCR\tesseract.exe"),
                Path(r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe"),
            ]
        )
    else:
        candidates.extend(
            [
                Path("/usr/bin/tesseract"),
                Path("/usr/local/bin/tesseract"),
                Path("/opt/homebrew/bin/tesseract"),
                Path("/snap/bin/tesseract"),
            ]
        )

    seen: set[str] = set()
    for c in candidates:
        normalized = str(c)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)

        if not (c.exists() and c.is_file()):
            continue
        if not _is_tesseract_usable(c):
            continue

        return str(c)
    return None


def _is_tesseract_usable(candidate: Path) -> bool:
    try:
        completed = subprocess.run(
            [str(candidate), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=6,
        )
    except Exception:
        return False

    if completed.returncode != 0:
        return False

    output = (completed.stdout or b"") + (completed.stderr or b"")
    return b"tesseract" in output.lower()


def extract_text(path: Path) -> str:
    try:
        img = Image.open(path)
        processed = preprocess(img)
        return pytesseract.image_to_string(processed, lang="eng", config="--oem 1 --psm 6") or ""
    except Exception:
        return ""


def normalize_domain(domain: str) -> str:
    return domain.lower().strip(". ")


def looks_suspicious_domain(domain: str) -> bool:
    if domain in SAFE_DOMAINS:
        return False
    tld = domain.rsplit(".", 1)[-1]
    if tld in {"com", "net", "org", "io", "gg", "tv"}:
        return True
    return len(tld) >= 2


def find_candidate_words(text: str) -> set[str]:
    lowered = text.lower()
    tokens = set(TOKEN_RE.findall(lowered))

    has_crypto_context = any(anchor in lowered for anchor in CRYPTO_ANCHORS)
    if not has_crypto_context:
        return set()

    selected: set[str] = set()
    for phrase in SUSPICIOUS_PHRASES:
        if phrase in lowered:
            selected.add(phrase)

    for token in tokens:
        if token in CRYPTO_ANCHORS:
            continue
        if token.isdigit():
            continue
        if len(token) < 4:
            continue
        if token in {"discord", "server", "channel", "message", "today", "people", "claim"}:
            continue
        if any(ch.isdigit() for ch in token):
            continue
        if token in {"bonus", "reward", "promo", "withdrawal", "crypto", "bitcoin", "wallet"}:
            selected.add(token)
    return selected


def _print_live_summary(
    *,
    processed: int,
    total: int,
    elapsed_seconds: float,
    last_file: Path,
    new_domains: set[str],
    new_words: set[str],
    domain_counter: Counter[str],
    word_counter: Counter[str],
) -> None:
    rate = processed / elapsed_seconds if elapsed_seconds > 0 else 0.0
    top_domains = [f"{d}({domain_counter[d]})" for d, _ in domain_counter.most_common(5)]
    top_words = [f"{w}({word_counter[w]})" for w, _ in word_counter.most_common(5)]

    print("-" * 72)
    print(f"[{processed}/{total}] {last_file.name} | {rate:.2f} img/s")
    if new_domains:
        print(f"  new domains: {', '.join(sorted(new_domains))}")
    if new_words:
        print(f"  new words: {', '.join(sorted(new_words))}")
    print(f"  unique suspicious domains so far: {len(domain_counter)}")
    print(f"  unique suspicious words so far: {len(word_counter)}")
    print(f"  top domains: {', '.join(top_domains) if top_domains else 'none'}")
    print(f"  top words: {', '.join(top_words) if top_words else 'none'}")


def _analyze_image(path: Path) -> tuple[Path, set[str], set[str], bool]:
    text = extract_text(path)
    if not text:
        return path, set(), set(), False

    domains = {
        normalize_domain(m.group(1))
        for m in DOMAIN_RE.finditer(text)
        if looks_suspicious_domain(normalize_domain(m.group(1)))
    }
    words = find_candidate_words(text)
    return path, domains, words, True


async def seed_candidates(folder: Path, apply: bool, min_domain_count: int, min_word_count: int, workers: int) -> int:
    settings = load_settings()
    tesseract = find_tesseract(settings.tesseract_cmd)
    if not tesseract:
        print("Tesseract not found. Install or set ocr.tesseract_cmd in config.ini")
        return 2

    pytesseract.pytesseract.tesseract_cmd = tesseract

    images = list(iter_images(folder))
    if not images:
        print(f"No images found in {folder}")
        return 0

    domain_counter: Counter[str] = Counter()
    word_counter: Counter[str] = Counter()
    seen_domains: set[str] = set()
    seen_words: set[str] = set()

    started = perf_counter()
    total = len(images)

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [loop.run_in_executor(pool, _analyze_image, image_path) for image_path in images]

        processed = 0
        for done in asyncio.as_completed(futures):
            image_path, domains, words, has_text = await done
            processed += 1

            new_domains: set[str] = set()
            new_words: set[str] = set()

            if has_text:
                for domain in domains:
                    domain_counter[domain] += 1
                    if domain not in seen_domains:
                        seen_domains.add(domain)
                        new_domains.add(domain)

                for word in words:
                    word_counter[word] += 1
                    if word not in seen_words:
                        seen_words.add(word)
                        new_words.add(word)

            _print_live_summary(
                processed=processed,
                total=total,
                elapsed_seconds=perf_counter() - started,
                last_file=image_path,
                new_domains=new_domains,
                new_words=new_words,
                domain_counter=domain_counter,
                word_counter=word_counter,
            )

    candidate_domains = sorted([d for d, c in domain_counter.items() if c >= min_domain_count])
    candidate_words = sorted([w for w, c in word_counter.items() if c >= min_word_count])

    print(f"Scanned {len(images)} images")
    print(f"Candidate domains ({len(candidate_domains)}): {', '.join(candidate_domains) if candidate_domains else 'none'}")
    print(f"Candidate words ({len(candidate_words)}): {', '.join(candidate_words) if candidate_words else 'none'}")

    if not apply:
        print("Dry run only. Re-run with --apply to write candidates to MongoDB.")
        return 0

    client = AsyncIOMotorClient(settings.mongodb_uri)
    inserted = 0
    try:
        collection = client[settings.mongodb_database][settings.scam_rules_collection]

        for domain in candidate_domains:
            result = await collection.update_one(
                {"kind": "blocked_domain", "value": domain},
                {"$setOnInsert": {"kind": "blocked_domain", "value": domain}},
                upsert=True,
            )
            if result.upserted_id is not None:
                inserted += 1

        for word in candidate_words:
            result = await collection.update_one(
                {"kind": "blocked_word", "value": word},
                {"$setOnInsert": {"kind": "blocked_word", "value": word}},
                upsert=True,
            )
            if result.upserted_id is not None:
                inserted += 1

        print(f"Inserted {inserted} new safe candidates into {settings.mongodb_database}.{settings.scam_rules_collection}")
        return 0
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Mine conservative scam rule candidates from pics folder")
    parser.add_argument("--folder", default="pics", help="Folder containing scam examples (default: pics)")
    parser.add_argument("--apply", action="store_true", help="Write candidates to MongoDB (default: dry-run)")
    parser.add_argument("--min-domain-count", type=int, default=2, help="Minimum sightings before domain can be added")
    parser.add_argument("--min-word-count", type=int, default=4, help="Minimum sightings before word can be added")
    parser.add_argument("--workers", type=int, default=max(2, os.cpu_count() or 4), help="Parallel OCR workers")
    args = parser.parse_args()

    return asyncio.run(
        seed_candidates(
            folder=Path(args.folder),
            apply=args.apply,
            min_domain_count=max(1, args.min_domain_count),
            min_word_count=max(1, args.min_word_count),
            workers=max(1, args.workers),
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
