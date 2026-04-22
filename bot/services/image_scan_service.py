from __future__ import annotations

import asyncio
import re
import shutil
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from pathlib import Path

from PIL import Image, ImageEnhance, ImageFilter, ImageOps
import pytesseract

from bot.services.scam_rules import ScanResult
from bot.storage.scam_rule_repository import ScamRuleRepository

DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)


class ImageScanService:
    def __init__(
        self,
        *,
        tesseract_cmd: str | None,
        rule_repository: ScamRuleRepository,
        workers: int | None = None,
    ) -> None:
        self._tesseract_cmd = self._find_tesseract(tesseract_cmd)
        self._rule_repository = rule_repository
        self._pool = ThreadPoolExecutor(max_workers=workers)

    @property
    def tesseract_available(self) -> bool:
        return self._tesseract_cmd is not None

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    async def scan_bytes(self, payload: bytes) -> ScanResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._pool, self._scan_bytes_sync, payload)

    def _scan_bytes_sync(self, payload: bytes) -> ScanResult:
        if not self._tesseract_cmd:
            return ScanResult(score=0, reasons=["ocr_unavailable"], domains_found=[], text_snippet="")

        try:
            img = Image.open(BytesIO(payload))
            processed = self._preprocess(img)
            text = pytesseract.image_to_string(
                processed,
                lang="eng",
                config="--oem 1 --psm 6",
            )
        except Exception as exc:
            return ScanResult(score=0, reasons=[f"ocr_error:{exc.__class__.__name__}"], domains_found=[], text_snippet="")

        return self._analyze_text(text or "")

    def _preprocess(self, img: Image.Image) -> Image.Image:
        gray = ImageOps.grayscale(img)
        contrast = ImageEnhance.Contrast(gray).enhance(1.8)
        sharp = contrast.filter(ImageFilter.SHARPEN)

        w, h = sharp.size
        if w < 1280:
            scale = 1280 / max(1, w)
            sharp = sharp.resize((int(w * scale), int(h * scale)))
        return sharp

    def _analyze_text(self, text: str) -> ScanResult:
        score = 0
        reasons: list[str] = []
        lowered = text.lower()
        rules = self._rule_repository.rules

        domains = sorted({self._normalize_domain(m.group(1)) for m in DOMAIN_RE.finditer(text)})
        flagged_domains = [d for d in domains if d in rules.blocked_domains]
        if flagged_domains:
            score += 6
            reasons.append(f"blocked_domain:{','.join(flagged_domains)}")

        matched_words = [w for w in rules.blocked_words if w in lowered]
        if matched_words:
            score += 3
            reasons.append(f"blocked_words:{','.join(matched_words)}")

        for high_risk_rule in rules.high_risk_rules:
            if high_risk_rule.pattern.search(text):
                score += high_risk_rule.weight
                reasons.append(high_risk_rule.label)

        return ScanResult(
            score=score,
            reasons=reasons,
            domains_found=domains,
            text_snippet=self._make_snippet(text),
        )

    def _make_snippet(self, text: str, max_len: int = 220) -> str:
        one_line = re.sub(r"\\s+", " ", text).strip()
        return one_line[:max_len] + ("..." if len(one_line) > max_len else "")

    def _find_tesseract(self, custom_path: str | None) -> str | None:
        candidates = []
        if custom_path:
            candidates.append(Path(custom_path))

        from_path = shutil.which("tesseract")
        if from_path:
            candidates.append(Path(from_path))

        candidates.extend(
            [
                Path(r"C:\\Program Files\\Tesseract-OCR\\tesseract.exe"),
                Path(r"C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe"),
                Path(r"C:\\Users\\Mikael\\AppData\\Local\\Programs\\Tesseract-OCR\\tesseract.exe"),
            ]
        )

        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                pytesseract.pytesseract.tesseract_cmd = str(candidate)
                return str(candidate)
        return None

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        return domain.lower().strip(". ")
