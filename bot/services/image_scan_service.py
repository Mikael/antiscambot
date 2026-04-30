from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import subprocess
import time
import unicodedata
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter, ImageOps
import pytesseract

from bot.services.scam_rules import ScanResult
from bot.storage.scam_rule_repository import ScamRuleRepository

LOGGER = logging.getLogger(__name__)


DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)

WALLET_PATTERNS = {
    "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "bitcoin": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "bitcoin_bech32": re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,39}\b"),
    "solana": re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b"),
    "tron": re.compile(r"\bT[A-Za-z1-9]{33}\b"),
    "ripple": re.compile(r"\br[A-Za-z0-9]{24,34}\b"),
    "cardano": re.compile(r"\baddr1[A-Za-z0-9]{38,100}\b"),
}

URL_PATTERNS = {
    "bitly": re.compile(r"bit\.ly/\S+", re.IGNORECASE),
    "tinyurl": re.compile(r"tinyurl\.com/\S+", re.IGNORECASE),
    "shortlink": re.compile(r"(?:short|rb\.gy|is\.gd|buff\.ly)/\S+", re.IGNORECASE),
}

LEETSPEAK_MAP = str.maketrans(
    {
        "0": "o", "1": "i", "2": "z", "3": "e", "4": "a", "5": "s",
        "6": "g", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a",
        "!": "i", "+": "t", "|": "i", "(": "c", ")": "c", "<": "c",
        ">": "c", "#": "h",
    }
)

# NOTE: entries here MUST be multi-word phrases. Bare English words like
# "reward", "prize", "winner", "celebration", "congratulation(s)" are far
# too generic -- they appear in Patreon tier descriptions, game event
# screenshots, birthday messages, etc. Such words belong in
# CORE_SCAM_TOKENS below, where a 2+ token threshold protects against
# false positives on benign single-word occurrences.
CORE_SCAM_PHRASES: Tuple[str, ...] = (
    "withdrawal success", "receive usdt", "select crypto to withdraw",
    "crypto to withdraw", "claim your reward", "activate code",
    "reward received", "wallet connect", "crypto bonus", "bonus code",
    "promo code", "limited time", "million users",
    "celebration promotion", "you are the lucky", "prize credited",
    "withdraw your funds", "free bonus",
    "users celebration", "claim your prize", "you have won",
    "congratulations you", "reward is waiting",
)

CORE_SCAM_TOKENS: frozenset = frozenset(
    {
        "withdraw", "withdrawal", "receive", "reward", "bonus", "claim",
        "promo", "usdt", "trx", "crypto", "wallet", "tether",
        "congratulations", "prize", "winner", "credited", "balance",
        "funds", "promotion",
    }
)

FINANCIAL_PATTERNS: Tuple[Tuple[re.Pattern, int], ...] = (
    (re.compile(r"\$\d+(?:,\d+)*(?:\.\d+)?"), 1),
    (re.compile(r"\d+(?:,\d+)*\s*(?:usd|eur|gbp|btc|eth)", re.IGNORECASE), 1),
    (re.compile(r"(?:\d+(?:\.\d+)?)\s*(?:million|billion|thousand)", re.IGNORECASE), 1),
)

URGENCY_PATTERNS: Tuple[Tuple[re.Pattern, int], ...] = (
    (re.compile(r"limited\s+time", re.IGNORECASE), 2),
    (re.compile(r"only\s+\d+\s+(?:left|remaining|spots?)", re.IGNORECASE), 2),
    (re.compile(r"last\s+chance", re.IGNORECASE), 2),
    (re.compile(r"expires?\s+(?:soon|today|in)", re.IGNORECASE), 2),
    (re.compile(r"ending\s+soon", re.IGNORECASE), 2),
    (re.compile(r"(?:act\s+now|don[\'\u2019]t\s+miss|claim\s+now|hurry\s+(?:up|now))", re.IGNORECASE), 2),
    (re.compile(r"final\s+(?:day|chance|warning)|time\s+running\s+out", re.IGNORECASE), 2),
)


EARLY_EXIT_SCORE = 8

DEFAULT_MAX_DIM = 1600

MIN_DIM = 50


@dataclass(slots=True)
class OCRResult:
    text: str
    confidence: float
    method: str


@dataclass
class EnhancedScanResult(ScanResult):
    confidence_score: float = 0.0
    matched_patterns: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    ocr_methods_used: List[str] = field(default_factory=list)


class ImageScanService:
    """Fast, thread-parallel OCR-based scam image scanner.

    Design goals (multi-server):
      * Non-blocking: all CPU work goes to a shared thread pool.
      * Bounded concurrency: a semaphore prevents thread-pool thrash when
        many guilds post images at once.
      * Fast path first: cheap preprocess + single tesseract call; only
        escalate to stronger variants if the fast pass is inconclusive.
      * Content-hash cache + pHash near-dup cache: identical/very similar
        images posted across servers hit instantly.
    """

    def __init__(
        self,
        *,
        tesseract_cmd: Optional[str],
        rule_repository: ScamRuleRepository,
        workers: Optional[int] = None,
        cache_ttl_seconds: int = 900,
        cache_max_items: int = 4096,
        aggressive_mode: bool = False,
        max_image_dimension: int = DEFAULT_MAX_DIM,
        ocr_concurrency: Optional[int] = None,
    ) -> None:
        self._tesseract_cmd = self._find_tesseract(tesseract_cmd)
        self._rule_repository = rule_repository
        self._aggressive_mode = aggressive_mode
        self._max_dim = max(400, int(max_image_dimension))


        cpu = os.cpu_count() or 4
        pool_size = workers if workers and workers > 0 else max(4, cpu * 2)
        self._pool = ThreadPoolExecutor(
            max_workers=pool_size, thread_name_prefix="ocr"
        )


        sem_size = ocr_concurrency if ocr_concurrency and ocr_concurrency > 0 else cpu
        self._ocr_semaphore = asyncio.Semaphore(sem_size)

        self._cache: "OrderedDict[str, tuple[float, ScanResult]]" = OrderedDict()
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache_max_items = cache_max_items


        self._phash_cache: "OrderedDict[int, tuple[float, ScanResult]]" = OrderedDict()

        self._stats: Dict[str, Any] = {
            "total_scans": 0,
            "cache_hits": 0,
            "phash_hits": 0,
            "cache_misses": 0,
            "ocr_failures": 0,
            "avg_processing_time": 0.0,
            "early_exits": 0,
        }

        self._high_risk_rules: List[Tuple[re.Pattern, int, str]] = []
        if hasattr(self._rule_repository, "high_risk_rules"):
            self._high_risk_rules = [
                (rule.pattern, rule.weight, rule.label)
                for rule in self._rule_repository.high_risk_rules
            ]


    @property
    def tesseract_available(self) -> bool:
        return self._tesseract_cmd is not None

    @property
    def stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    async def scan_bytes(self, payload: bytes) -> ScanResult:
        """Scan a single image. Safe to call from many coroutines at once."""
        start = time.perf_counter()
        self._stats["total_scans"] += 1

        cache_key = hashlib.sha256(payload).hexdigest()
        cached = self._cache_get(cache_key)
        if cached is not None:
            self._stats["cache_hits"] += 1
            return cached

        self._stats["cache_misses"] += 1

        if not self._tesseract_cmd:
            return ScanResult(
                score=0, reasons=["ocr_unavailable"],
                domains_found=[], text_snippet="",
            )

        loop = asyncio.get_running_loop()
        async with self._ocr_semaphore:
            result = await loop.run_in_executor(
                self._pool, self._scan_bytes_sync, payload
            )

        elapsed_ms = (time.perf_counter() - start) * 1000
        self._stats["avg_processing_time"] = (
            self._stats["avg_processing_time"] * 0.95 + elapsed_ms * 0.05
        )
        if isinstance(result, EnhancedScanResult):
            result.processing_time_ms = elapsed_ms

        self._cache_put(cache_key, result)
        return result

    async def scan_many(self, payloads: Sequence[bytes]) -> List[ScanResult]:
        """Scan several images concurrently. Preserves order."""
        if not payloads:
            return []
        return await asyncio.gather(*(self.scan_bytes(p) for p in payloads))

    def clear_cache(self) -> None:
        self._cache.clear()
        self._phash_cache.clear()
        LOGGER.info("Image scan cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        return {
            "size": len(self._cache),
            "phash_size": len(self._phash_cache),
            "max_size": self._cache_max_items,
            "ttl_seconds": self._cache_ttl_seconds,
        }


    def _scan_bytes_sync(self, payload: bytes) -> ScanResult:
        try:
            img = Image.open(BytesIO(payload))
            img.load()
        except Image.UnidentifiedImageError:
            return ScanResult(
                score=0, reasons=["invalid_image_format"],
                domains_found=[], text_snippet="",
            )
        except Exception as exc:
            return ScanResult(
                score=0, reasons=[f"image_open_error:{exc.__class__.__name__}"],
                domains_found=[], text_snippet="",
            )

        w, h = img.size
        if w < MIN_DIM or h < MIN_DIM:
            return ScanResult(
                score=0, reasons=["image_too_small"],
                domains_found=[], text_snippet="",
            )

        img = self._prepare(img)

        phash = self._phash(img)
        hit = self._phash_get(phash)
        if hit is not None:
            self._stats["phash_hits"] += 1
            return hit


        results: List[OCRResult] = []

        fast_img = self._preprocess(img, "fast")
        fast_text = self._run_tesseract(fast_img, psm=6, oem=1)
        if fast_text:
            results.append(OCRResult(fast_text, 0.7, "fast_psm6"))

        verdict = self._analyze(results)
        if verdict.score >= EARLY_EXIT_SCORE:
            self._stats["early_exits"] += 1
            self._phash_put(phash, verdict)
            return verdict


        variant_jobs = [
            ("contrast_psm11", self._preprocess(img, "high_contrast"), 11, 3),
            ("upscaled_psm4", self._preprocess(img, "upscaled"), 4, 1),
            ("single_line_psm7", self._preprocess(img, "high_contrast"), 7, 3),
        ]
        if self._aggressive_mode:
            variant_jobs.append(
                ("aggressive_psm3", self._preprocess(img, "aggressive"), 3, 1)
            )

        futures = [
            self._pool.submit(self._run_tesseract, pre_img, psm, oem)
            for _, pre_img, psm, oem in variant_jobs
        ]
        for (method, _pre, _psm, _oem), fut in zip(variant_jobs, futures):
            try:
                text = fut.result(timeout=15)
            except Exception as exc:
                LOGGER.debug("OCR variant %s failed: %s", method, exc)
                continue
            if text:
                results.append(OCRResult(text, 0.8, method))

        if not results:
            self._stats["ocr_failures"] += 1
            verdict = ScanResult(
                score=0, reasons=["ocr_no_text"],
                domains_found=[], text_snippet="",
            )
        else:
            verdict = self._analyze(results)

        self._phash_put(phash, verdict)
        return verdict


    def _prepare(self, img: Image.Image) -> Image.Image:
        """Normalize + downscale. Runs once per image."""
        try:
            if getattr(img, "is_animated", False):
                img.seek(0)
        except Exception:
            pass

        if img.mode not in ("L", "RGB"):
            if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                rgba = img.convert("RGBA")
                bg = Image.new("RGB", rgba.size, (255, 255, 255))
                bg.paste(rgba, mask=rgba.split()[-1])
                img = bg
            else:
                img = img.convert("RGB")

        w, h = img.size
        longest = max(w, h)
        if longest > self._max_dim:
            scale = self._max_dim / longest
            img = img.resize(
                (max(1, int(w * scale)), max(1, int(h * scale))),
                Image.Resampling.LANCZOS,
            )
        return img

    def _preprocess(self, img: Image.Image, method: str) -> Image.Image:
        if method == "fast":
            gray = ImageOps.grayscale(img)
            arr = np.asarray(gray, dtype=np.uint8)
            if float(arr.mean()) > 200.0:
                gray = ImageOps.invert(gray)
            return ImageEnhance.Contrast(gray).enhance(1.6)

        if method == "high_contrast":
            gray = ImageOps.grayscale(img)
            if gray.size[0] < 800:
                scale = 1200 / max(gray.size[0], 1)
                gray = gray.resize(
                    (int(gray.size[0] * scale), int(gray.size[1] * scale)),
                    Image.Resampling.LANCZOS,
                )
            sharp = ImageEnhance.Contrast(gray).enhance(2.2).filter(ImageFilter.SHARPEN)
            return sharp.point(lambda px: 255 if px > 160 else 0)

        if method == "upscaled":
            gray = ImageOps.grayscale(img)
            if gray.size[0] < 1400:
                scale = 1800 / max(gray.size[0], 1)
                gray = gray.resize(
                    (int(gray.size[0] * scale), int(gray.size[1] * scale)),
                    Image.Resampling.LANCZOS,
                )
            denoised = gray.filter(ImageFilter.MedianFilter(size=3))
            sharp = ImageEnhance.Contrast(denoised).enhance(1.8).filter(ImageFilter.SHARPEN)
            return sharp.point(lambda px: 255 if px > 150 else 0)

        if method == "aggressive":
            gray = ImageOps.grayscale(img)
            scale = 2400 / max(gray.size[0], 1)
            gray = gray.resize(
                (int(gray.size[0] * scale), int(gray.size[1] * scale)),
                Image.Resampling.LANCZOS,
            )
            gray = gray.filter(ImageFilter.MedianFilter(size=2))
            boosted = ImageEnhance.Brightness(
                ImageEnhance.Contrast(gray).enhance(2.5)
            ).enhance(1.2).filter(ImageFilter.SHARPEN)
            return boosted.point(lambda px: 255 if px > 130 else 0)

        return ImageOps.grayscale(img)


    def _run_tesseract(self, img: Image.Image, psm: int, oem: int) -> str:
        try:
            config = f"--oem {oem} --psm {psm}"
            text = pytesseract.image_to_string(img, lang="eng", config=config)
        except Exception as exc:
            LOGGER.debug("Tesseract psm=%s failed: %s", psm, exc)
            return ""
        return text.strip() if text else ""


    def _analyze(self, ocr_results: List[OCRResult]) -> EnhancedScanResult:
        merged = self._merge(ocr_results)
        return self._score_text(merged, ocr_results)

    def _merge(self, results: List[OCRResult]) -> str:
        if not results:
            return ""
        lines: List[str] = []
        seen: Set[str] = set()
        for r in results:
            for line in r.text.split("\n"):
                line = line.strip()
                if len(line) > 3 and line not in seen:
                    seen.add(line)
                    lines.append(line)
        best = max(results, key=lambda x: x.confidence).text
        combined = "\n".join(lines)
        if len(combined) > len(best) * 1.5:
            return f"{best}\n{combined}"
        return best if len(best) > len(combined) else combined

    def _score_text(self, text: str, ocr_results: List[OCRResult]) -> EnhancedScanResult:
        score = 0
        reasons: List[str] = []
        matched: List[str] = []

        lowered = text.lower()
        normalized = self._normalize(text)

        domains = sorted({self._normalize_domain(m.group(1)) for m in DOMAIN_RE.finditer(text)})
        rules = self._rule_repository.rules
        flagged = [d for d in domains if d in rules.blocked_domains]
        if flagged:
            score += 6
            reasons.append(f"blocked_domain:{','.join(flagged)}")
            matched.extend(f"blocked_domain:{d}" for d in flagged)

        hit_words = sorted(
            {w for w in rules.blocked_words if self._contains_phrase(lowered, normalized, w)}
        )
        if hit_words:
            score += min(9, len(hit_words) * 3)
            reasons.append(f"blocked_words({len(hit_words)}):{','.join(hit_words[:5])}")
            matched.extend(hit_words[:3])

        phrase_hits = [p for p in CORE_SCAM_PHRASES if self._contains_phrase(lowered, normalized, p)]
        if phrase_hits:
            # A single core-phrase hit used to be enough to heavily boost
            # the score (min 2, +2 more via core_phrase_hits*2 in the
            # handler -> 4) which cleared aggressive thresholds on its
            # own. Require 2+ distinct phrase hits for the full boost,
            # and give only a small weight for a solitary hit so benign
            # screenshots don't auto-flag.
            if len(phrase_hits) >= 2:
                score += min(8, len(phrase_hits) * 2)
                reasons.append(f"core_phrases({len(phrase_hits)}):{','.join(phrase_hits[:3])}")
                matched.extend(phrase_hits[:3])
            else:
                score += 1
                reasons.append(f"core_phrase_single:{phrase_hits[0]}")

        tokens = set(normalized.split())
        token_hits = sorted(tokens & CORE_SCAM_TOKENS)
        if len(token_hits) >= 2:
            score += min(6, len(token_hits))
            reasons.append(f"core_tokens({len(token_hits)}):{','.join(token_hits[:5])}")

        wallet_hits = [name for name, pat in WALLET_PATTERNS.items() if pat.search(text)]
        if wallet_hits:
            score += 3 * len(wallet_hits) + 2
            for name in wallet_hits:
                reasons.append(f"wallet_address:{name}")
                matched.append(f"crypto_wallet_{name}")
            reasons.append("wallet_address_like")

        for name, pat in URL_PATTERNS.items():
            if pat.search(text):
                score += 4
                reasons.append(f"url_shortener:{name}")
                matched.append(f"shortened_url_{name}")

        fin = sum(w for pat, w in FINANCIAL_PATTERNS if pat.search(text))
        if fin >= 2:
            score += min(4, fin)
            reasons.append(f"financial_indicators:{fin}")

        urg = sum(w for pat, w in URGENCY_PATTERNS if pat.search(lowered))
        if urg >= 4:
            score += min(5, urg)
            reasons.append(f"urgency_patterns:{urg}")
            matched.append("urgency_indicators")

        for pat, weight, label in self._high_risk_rules:
            if pat.search(text) or pat.search(normalized):
                score += weight
                reasons.append(label)
                matched.append(label)

        promo_hits = sum(1 for ind in rules.blocked_words if ind in lowered)
        if promo_hits >= 3:
            score += 4
            reasons.append(f"promotion_scam:{promo_hits}")

        score = min(score, 25)

        return EnhancedScanResult(
            score=score,
            reasons=reasons,
            domains_found=domains,
            text_snippet=self._snippet(normalized),
            confidence_score=min(score / 15.0, 1.0),
            matched_patterns=matched[:10],
            processing_time_ms=0.0,
            ocr_methods_used=[r.method for r in ocr_results],
        )


    @staticmethod
    def _snippet(text: str, max_len: int = 300) -> str:
        if not text:
            return ""
        one = re.sub(r"\s+", " ", text).strip()
        return one if len(one) <= max_len else one[: max_len - 3] + "..."

    @staticmethod
    def _normalize(text: str) -> str:
        lowered = unicodedata.normalize("NFKD", text.lower())
        lowered = lowered.encode("ascii", "ignore").decode("ascii")
        lowered = lowered.translate(LEETSPEAK_MAP)
        lowered = re.sub(r"[^a-z0-9\s]", " ", lowered)
        lowered = re.sub(r"\s+", " ", lowered).strip()
        lowered = lowered.replace("rn", "m").replace("cl", "d").replace("vv", "w")
        return lowered

    @staticmethod
    def _contains_phrase(raw: str, normalized: str, phrase: str) -> bool:
        p = phrase.lower().strip()
        if not p:
            return False
        if p in raw:
            return True
        pn = re.sub(r"\s+", " ", p.translate(LEETSPEAK_MAP))
        return pn in normalized

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        return domain.lower().strip(". ")


    @staticmethod
    def _phash(img: Image.Image) -> int:
        """64-bit average-hash of an 8x8 grayscale thumbnail.

        Not cryptographic; used purely for near-duplicate lookup so the
        same scam reposted across servers hits the cache instantly.
        """
        thumb = img.convert("L").resize((8, 8), Image.Resampling.BILINEAR)
        arr = np.asarray(thumb, dtype=np.uint8).flatten()
        avg = int(arr.mean())
        bits = 0
        for i, px in enumerate(arr):
            if int(px) > avg:
                bits |= 1 << i
        return bits

    def _phash_get(self, h: int) -> Optional[ScanResult]:
        now = time.time()
        item = self._phash_cache.get(h)
        if item and now - item[0] <= self._cache_ttl_seconds:
            self._phash_cache.move_to_end(h)
            return item[1]
        for key in list(self._phash_cache.keys())[-64:]:
            ts, res = self._phash_cache[key]
            if now - ts > self._cache_ttl_seconds:
                continue
            if bin(key ^ h).count("1") <= 5:
                return res
        return None

    def _phash_put(self, h: int, result: ScanResult) -> None:
        self._phash_cache[h] = (time.time(), result)
        self._phash_cache.move_to_end(h)
        while len(self._phash_cache) > self._cache_max_items:
            self._phash_cache.popitem(last=False)


    def _cache_get(self, key: str) -> Optional[ScanResult]:
        item = self._cache.get(key)
        if item is None:
            return None
        ts, result = item
        if time.time() - ts > self._cache_ttl_seconds:
            self._cache.pop(key, None)
            return None
        self._cache.move_to_end(key)
        return result

    def _cache_put(self, key: str, result: ScanResult) -> None:
        self._cache[key] = (time.time(), result)
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_max_items:
            self._cache.popitem(last=False)


    def _find_tesseract(self, custom_path: Optional[str]) -> Optional[str]:
        candidates: List[Path] = []

        if custom_path:
            candidates.append(Path(os.path.expandvars(custom_path)).expanduser())

        from_path = shutil.which("tesseract")
        if from_path:
            candidates.append(Path(from_path))

        env_cmd = os.environ.get("TESSERACT_CMD", "").strip()
        if env_cmd:
            candidates.append(Path(os.path.expandvars(env_cmd)).expanduser())

        if os.name == "nt":
            pf = os.environ.get("ProgramFiles", r"C:\Program Files")
            pf86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
            candidates.extend(
                [
                    Path(pf) / "Tesseract-OCR" / "tesseract.exe",
                    Path(pf86) / "Tesseract-OCR" / "tesseract.exe",
                    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Tesseract-OCR" / "tesseract.exe",
                    Path(r"C:\Tesseract-OCR\tesseract.exe"),
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

        seen: Set[str] = set()
        for cand in candidates:
            s = str(cand)
            if not s or s in seen:
                continue
            seen.add(s)
            if not (cand.exists() and cand.is_file()):
                continue
            if not self._is_tesseract_usable(cand):
                continue
            pytesseract.pytesseract.tesseract_cmd = s
            LOGGER.info("Tesseract found: %s", s)
            return s

        LOGGER.warning("Tesseract OCR not found. Image scanning disabled.")
        return None

    @staticmethod
    def _is_tesseract_usable(candidate: Path) -> bool:
        try:
            completed = subprocess.run(
                [str(candidate), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            return False
        if completed.returncode != 0:
            return False
        out = (completed.stdout or b"") + (completed.stderr or b"")
        return b"tesseract" in out.lower()
