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
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from functools import lru_cache, wraps

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter, ImageOps
import pytesseract

from bot.services.scam_rules import ScanResult
from bot.storage.scam_rule_repository import ScamRuleRepository

# Setup logging
LOGGER = logging.getLogger(__name__)

# Enhanced regex patterns
DOMAIN_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b",
    re.IGNORECASE,
)

# Crypto wallet patterns (enhanced)
WALLET_PATTERNS = {
    'ethereum': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
    'bitcoin': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    'bitcoin_bech32': re.compile(r'\bbc1[a-zA-HJ-NP-Z0-9]{25,39}\b'),
    'solana': re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'),
    'tron': re.compile(r'\bT[A-Za-z1-9]{33}\b'),
    'ripple': re.compile(r'\br[A-Za-z0-9]{24,34}\b'),
    'cardano': re.compile(r'\baddr1[A-Za-z0-9]{38,100}\b'),
}

# URL/shortlink patterns
URL_PATTERNS = {
    'bitly': re.compile(r'bit\.ly/\S+', re.IGNORECASE),
    'tinyurl': re.compile(r'tinyurl\.com/\S+', re.IGNORECASE),
    'shortlink': re.compile(r'(?:short|rb\.gy|is\.gd|buff\.ly)/\S+', re.IGNORECASE),
}

# Enhanced leetspeak map
LEETSPEAK_MAP = str.maketrans({
    '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's', '6': 'g',
    '7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a', '!': 'i', '+': 't',
    '|': 'i', '(': 'c', ')': 'c', '<': 'c', '>': 'c', '#': 'h',
})

# Expanded core scam phrases
CORE_SCAM_PHRASES = (
    "withdrawal success", "receive usdt", "select crypto to withdraw",
    "crypto to withdraw", "claim your reward", "activate code",
    "reward received", "wallet connect", "crypto bonus", "bonus code",
    "congratulations", "promo code", "limited time", "million users",
    "celebration promotion", "you are the lucky", "prize credited",
    "withdraw your funds", "account balance", "free bonus",
)

# Expanded core scam tokens
CORE_SCAM_TOKENS = {
    "withdraw", "withdrawal", "receive", "reward", "bonus", "claim",
    "promo", "usdt", "trx", "crypto", "wallet", "tether", "congratulations",
    "prize", "winner", "credited", "balance", "funds", "promotion",
}

# Financial patterns
FINANCIAL_PATTERNS = [
    (re.compile(r'\$\d+(?:,\d+)*(?:\.\d+)?'), 1),  # Dollar amounts
    (re.compile(r'\d+(?:,\d+)*\s*(?:usd|eur|gbp|btc|eth)'), 1),  # Crypto amounts
    (re.compile(r'(?:\d+(?:\.\d+)?)\s*(?:million|billion|thousand)'), 1),
]

# Urgency patterns (high confidence indicators)
URGENCY_PATTERNS = [
    (re.compile(r'(?:limited|only|expires?|ending\s+soon|last\s+chance)'), 2),
    (re.compile(r'(?:act\s+now|don[\'’]t\s+miss|claim\s+now|hurry)'), 2),
    (re.compile(r'(?:final\s+(?:day|chance|warning)|time\s+running\s+out)'), 2),
]


@dataclass
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
    """Enhanced image scanning service with advanced OCR and detection"""
    
    def __init__(
        self,
        *,
        tesseract_cmd: str | None,
        rule_repository: ScamRuleRepository,
        workers: int | None = None,
        use_process_pool: bool = False,
        cache_ttl_seconds: int = 900,
        cache_max_items: int = 2000,
        enable_ml_fallback: bool = False,
        aggressive_mode: bool = False,
    ) -> None:
        self._tesseract_cmd = self._find_tesseract(tesseract_cmd)
        self._rule_repository = rule_repository
        self._aggressive_mode = aggressive_mode
        
        # Use ProcessPoolExecutor for CPU-intensive operations if requested
        if use_process_pool:
            self._pool = ProcessPoolExecutor(max_workers=workers)
        else:
            self._pool = ThreadPoolExecutor(max_workers=workers or os.cpu_count())
            
        self._cache: OrderedDict[str, tuple[float, ScanResult]] = OrderedDict()
        self._cache_ttl_seconds = cache_ttl_seconds
        self._cache_max_items = cache_max_items
        self._enable_ml_fallback = enable_ml_fallback
        
        # Statistics for monitoring
        self._stats = {
            'total_scans': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'ocr_failures': 0,
            'avg_processing_time': 0.0,
        }
        
        # Compile regex patterns once for performance
        self._compiled_patterns = self._compile_patterns()
        
    def _compile_patterns(self) -> Dict[str, Any]:
        """Compile all regex patterns for performance"""
        patterns = {
            'wallet': WALLET_PATTERNS,
            'url': URL_PATTERNS,
            'financial': FINANCIAL_PATTERNS,
            'urgency': URGENCY_PATTERNS,
        }
        
        # Add high-risk rules from repository
        if hasattr(self._rule_repository, 'high_risk_rules'):
            patterns['high_risk'] = [
                (rule.pattern, rule.weight, rule.label)
                for rule in self._rule_repository.high_risk_rules
            ]
            
        return patterns
        
    @property
    def tesseract_available(self) -> bool:
        return self._tesseract_cmd is not None
        
    @property
    def stats(self) -> Dict[str, Any]:
        """Return scanning statistics"""
        return self._stats.copy()
        
    def shutdown(self) -> None:
        """Clean shutdown of thread/process pool"""
        self._pool.shutdown(wait=False, cancel_futures=True)
        
    async def scan_bytes(self, payload: bytes) -> ScanResult:
        """Main entry point for scanning image bytes"""
        start_time = time.perf_counter()
        self._stats['total_scans'] += 1
        
        # Check cache
        cache_key = hashlib.sha256(payload).hexdigest()  # Use SHA256 for better collision resistance
        cached = self._cache_get(cache_key)
        if cached is not None:
            self._stats['cache_hits'] += 1
            return cached
            
        self._stats['cache_misses'] += 1
        
        # Perform scan
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(self._pool, self._scan_bytes_sync, payload)
        
        # Update stats
        processing_time = (time.perf_counter() - start_time) * 1000
        self._stats['avg_processing_time'] = (
            self._stats['avg_processing_time'] * 0.95 + processing_time * 0.05
        )
        
        # Cache result
        self._cache_put(cache_key, result)
        return result
        
    def _scan_bytes_sync(self, payload: bytes) -> ScanResult:
        """Synchronous scanning implementation"""
        if not self._tesseract_cmd:
            return ScanResult(
                score=0,
                reasons=["ocr_unavailable"],
                domains_found=[],
                text_snippet=""
            )
            
        try:
            # Open and validate image
            img = Image.open(BytesIO(payload))
            
            # Quick check for image size (skip tiny images)
            if img.size[0] < 50 or img.size[1] < 50:
                return ScanResult(
                    score=0,
                    reasons=["image_too_small"],
                    domains_found=[],
                    text_snippet=""
                )
                
            # Perform OCR with multiple methods
            ocr_results = self._perform_enhanced_ocr(img)
            
            if not ocr_results:
                self._stats['ocr_failures'] += 1
                return ScanResult(
                    score=0,
                    reasons=["ocr_no_text"],
                    domains_found=[],
                    text_snippet=""
                )
                
            # Merge results from different OCR methods
            merged_text = self._merge_ocr_results(ocr_results)
            
            # Analyze text with enhanced detection
            return self._analyze_text_enhanced(merged_text, ocr_results)
            
        except Image.UnidentifiedImageError:
            return ScanResult(
                score=0,
                reasons=["invalid_image_format"],
                domains_found=[],
                text_snippet=""
            )
        except Exception as exc:
            return ScanResult(
                score=0,
                reasons=[f"ocr_error:{exc.__class__.__name__}"],
                domains_found=[],
                text_snippet=""
            )
            
    def _perform_enhanced_ocr(self, img: Image.Image) -> List[OCRResult]:
        """Perform OCR with multiple preprocessing strategies"""
        results = []
        
        # Strategy 1: Standard preprocessing (PSM 6 - block text)
        processed1 = self._preprocess_image(img, method='standard')
        text1 = self._run_tesseract(processed1, psm=6, oem=1)
        if text1:
            results.append(OCRResult(text=text1, confidence=0.7, method='standard_psm6'))
            
        # Strategy 2: High contrast + threshold (PSM 11 - sparse text)
        processed2 = self._preprocess_image(img, method='high_contrast')
        text2 = self._run_tesseract(processed2, psm=11, oem=1)
        if text2:
            results.append(OCRResult(text=text2, confidence=0.75, method='contrast_psm11'))
            
        # Strategy 3: Upscaled + denoised (PSM 4 - single column)
        processed3 = self._preprocess_image(img, method='upscaled')
        text3 = self._run_tesseract(processed3, psm=4, oem=1)
        if text3:
            results.append(OCRResult(text=text3, confidence=0.8, method='upscaled_psm4'))
            
        # Strategy 4: Adaptive thresholding for complex backgrounds (skip if scipy not available)
        try:
            processed4 = self._preprocess_image(img, method='adaptive')
            text4 = self._run_tesseract(processed4, psm=6, oem=3)  # OEM 3 = default + LSTM
            if text4:
                results.append(OCRResult(text=text4, confidence=0.85, method='adaptive_psm6'))
        except Exception as e:
            LOGGER.debug(f"Adaptive preprocessing failed: {e}")
            
        # Strategy 5: Aggressive preprocessing for low-quality images
        if self._aggressive_mode:
            processed5 = self._preprocess_image(img, method='aggressive')
            text5 = self._run_tesseract(processed5, psm=3, oem=1)  # PSM 3 = fully automatic
            if text5:
                results.append(OCRResult(text=text5, confidence=0.6, method='aggressive_psm3'))
                
        return results
        
    def _preprocess_image(self, img: Image.Image, method: str) -> Image.Image:
        """Apply different preprocessing strategies"""
        
        # Convert to RGB if necessary
        if img.mode not in ('L', 'RGB'):
            img = img.convert('RGB')
            
        if method == 'standard':
            # Basic preprocessing
            gray = ImageOps.grayscale(img)
            contrast = ImageEnhance.Contrast(gray).enhance(1.6)
            return contrast.filter(ImageFilter.SHARPEN)
            
        elif method == 'high_contrast':
            # High contrast with threshold
            gray = ImageOps.grayscale(img)
            
            # Resize if too small
            if gray.size[0] < 800:
                scale = 1200 / max(gray.size[0], 1)
                gray = gray.resize((int(gray.size[0] * scale), int(gray.size[1] * scale)), Image.Resampling.LANCZOS)
                
            # Enhance contrast
            contrast = ImageEnhance.Contrast(gray).enhance(2.2)
            sharpened = contrast.filter(ImageFilter.SHARPEN)
            
            # Apply threshold
            return sharpened.point(lambda px: 255 if px > 160 else 0)
            
        elif method == 'upscaled':
            # Upscale for better OCR on small text
            gray = ImageOps.grayscale(img)
            
            # Significant upscaling
            if gray.size[0] < 1400:
                scale = 1800 / max(gray.size[0], 1)
                gray = gray.resize((int(gray.size[0] * scale), int(gray.size[1] * scale)), Image.Resampling.LANCZOS)
                
            # Denoise
            denoised = gray.filter(ImageFilter.MedianFilter(size=3))
            contrast = ImageEnhance.Contrast(denoised).enhance(1.8)
            sharpened = contrast.filter(ImageFilter.SHARPEN)
            
            return sharpened.point(lambda px: 255 if px > 150 else 0)
            
        elif method == 'adaptive':
            # Adaptive thresholding using numpy (no scipy dependency)
            gray = ImageOps.grayscale(img)
            img_array = np.array(gray, dtype=np.float32)
            
            # Simple Gaussian blur using numpy
            from scipy import ndimage  # type: ignore
            try:
                blurred = ndimage.gaussian_filter(img_array, sigma=1)
            except ImportError:
                # Fallback to PIL's GaussianBlur if scipy not available
                from PIL import ImageFilter
                blurred_img = gray.filter(ImageFilter.GaussianBlur(radius=1))
                blurred = np.array(blurred_img, dtype=np.float32)
            
            # Adaptive threshold
            threshold = np.mean(blurred) * 0.8
            binary = (blurred > threshold).astype(np.uint8) * 255
            
            return Image.fromarray(binary)
            
        elif method == 'aggressive':
            # Aggressive preprocessing for very poor quality images
            gray = ImageOps.grayscale(img)
            
            # Extreme upscaling
            scale = 2400 / max(gray.size[0], 1)
            gray = gray.resize((int(gray.size[0] * scale), int(gray.size[1] * scale)), Image.Resampling.LANCZOS)
            
            # Multiple enhancements
            for _ in range(2):
                gray = gray.filter(ImageFilter.MedianFilter(size=2))
                
            contrast = ImageEnhance.Contrast(gray).enhance(2.5)
            brightness = ImageEnhance.Brightness(contrast).enhance(1.2)
            sharpened = brightness.filter(ImageFilter.SHARPEN)
            
            # Aggressive threshold
            return sharpened.point(lambda px: 255 if px > 130 else 0)
            
        return ImageOps.grayscale(img)
        
    def _run_tesseract(self, img: Image.Image, psm: int, oem: int) -> str:
        """Run Tesseract OCR with specific parameters"""
        try:
            whitelist_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789$.,!?@#$%^&*()-=+[]{};:'\"<>/\\|`~ "
            config = f"--oem {oem} --psm {psm} -c tessedit_char_whitelist=\"{whitelist_chars}\""
            text = pytesseract.image_to_string(img, lang='eng', config=config)
            return text.strip() if text else ""
        except Exception:
            return ""
            
    def _merge_ocr_results(self, results: List[OCRResult]) -> str:
        """Intelligently merge results from multiple OCR methods"""
        if not results:
            return ""
            
        # Collect all unique lines
        all_lines = []
        seen_lines = set()
        
        for result in results:
            lines = result.text.split('\n')
            for line in lines:
                line = line.strip()
                if line and len(line) > 3 and line not in seen_lines:
                    seen_lines.add(line)
                    all_lines.append(line)
                    
        # Also add the full text from highest confidence result
        best_result = max(results, key=lambda x: x.confidence)
        full_text = best_result.text
        
        # Combine
        combined = '\n'.join(all_lines)
        
        # If combined is significantly different from best, include both
        if len(combined) > len(full_text) * 1.5:
            return f"{full_text}\n{combined}"
            
        return full_text if len(full_text) > len(combined) else combined
        
    def _analyze_text_enhanced(self, text: str, ocr_results: List[OCRResult]) -> ScanResult:
        """Enhanced text analysis with multiple detection layers"""
        score = 0
        reasons: List[str] = []
        matched_patterns: List[str] = []
        
        lowered = text.lower()
        normalized = self._normalize_ocr_text(text)
        
        # 1. Domain detection
        domains = sorted({self._normalize_domain(m.group(1)) for m in DOMAIN_RE.finditer(text)})
        rules = self._rule_repository.rules
        
        flagged_domains = [d for d in domains if d in rules.blocked_domains]
        if flagged_domains:
            score += 6
            reasons.append(f"blocked_domain:{','.join(flagged_domains)}")
            matched_patterns.extend([f"blocked_domain:{d}" for d in flagged_domains])
            
        # 2. Blocked words detection
        matched_words = sorted({w for w in rules.blocked_words if self._contains_phrase(lowered, normalized, w)})
        if matched_words:
            matched_word_score = min(9, len(matched_words) * 3)
            score += matched_word_score
            reasons.append(f"blocked_words({len(matched_words)}):{','.join(matched_words[:5])}")
            matched_patterns.extend(matched_words[:3])
            
        # 3. Core scam phrases
        core_phrase_hits = [phrase for phrase in CORE_SCAM_PHRASES if self._contains_phrase(lowered, normalized, phrase)]
        if core_phrase_hits:
            phrase_score = min(8, len(core_phrase_hits) * 2)
            score += phrase_score
            reasons.append(f"core_phrases({len(core_phrase_hits)}):{','.join(core_phrase_hits[:3])}")
            matched_patterns.extend(core_phrase_hits[:3])
            
        # 4. Core scam tokens
        normalized_tokens = set(normalized.split())
        core_token_hits = sorted({token for token in CORE_SCAM_TOKENS if token in normalized_tokens})
        if len(core_token_hits) >= 2:
            token_score = min(6, len(core_token_hits))
            score += token_score
            reasons.append(f"core_tokens({len(core_token_hits)}):{','.join(core_token_hits[:5])}")
            
        # 5. Wallet address detection (enhanced)
        wallet_matches = []
        for wallet_type, pattern in WALLET_PATTERNS.items():
            if pattern.search(text):
                wallet_matches.append(wallet_type)
                score += 3
                reasons.append(f"wallet_address:{wallet_type}")
                matched_patterns.append(f"crypto_wallet_{wallet_type}")
                
        if wallet_matches:
            score += 2  # Bonus for any wallet
            reasons.append("wallet_address_like")
            
        # 6. URL shortener detection (high risk)
        for shortener_name, pattern in URL_PATTERNS.items():
            if pattern.search(text):
                score += 4
                reasons.append(f"url_shortener:{shortener_name}")
                matched_patterns.append(f"shortened_url_{shortener_name}")
                
        # 7. Financial patterns
        financial_score = 0
        for pattern, weight in FINANCIAL_PATTERNS:
            if pattern.search(text):
                financial_score += weight
        if financial_score >= 2:
            score += min(4, financial_score)
            reasons.append(f"financial_indicators:{financial_score}")
            
        # 8. Urgency patterns (high confidence for scams)
        urgency_score = 0
        for pattern, weight in URGENCY_PATTERNS:
            if pattern.search(lowered):
                urgency_score += weight
        if urgency_score >= 2:
            score += min(5, urgency_score)
            reasons.append(f"urgency_patterns:{urgency_score}")
            matched_patterns.append("urgency_indicators")
            
        # 9. High-risk rules from repository
        for pattern, weight, label in self._compiled_patterns.get('high_risk', []):
            if pattern.search(text) or pattern.search(normalized):
                score += weight
                reasons.append(label)
                matched_patterns.append(label)
                
        # 10. Special detection for promotion/celebration scams
        promo_indicators = [
            "congratulation", "reward", "prize", "winner", "celebration",
            "million users", "promo code", "bonus code", "limited time"
        ]
        promo_hits = sum(1 for ind in promo_indicators if ind in lowered)
        if promo_hits >= 3:
            score += 4
            reasons.append(f"promotion_scam:{promo_hits}")
            
        # 11. Boost score if multiple OCR methods detected text (increases confidence)
        if len(ocr_results) >= 3:
            score += 1
            reasons.append("multi_method_ocr_confirmation")
            
        # Cap score at reasonable maximum
        score = min(score, 25)
        
        # Create enhanced result
        return EnhancedScanResult(
            score=score,
            reasons=reasons,
            domains_found=domains,
            text_snippet=self._make_snippet(normalized),
            confidence_score=min(score / 15, 1.0),  # Normalize to 0-1
            matched_patterns=matched_patterns[:10],  # Keep top 10
            processing_time_ms=0,  # Will be set by caller
            ocr_methods_used=[r.method for r in ocr_results],
        )
        
    def _make_snippet(self, text: str, max_len: int = 300) -> str:
        """Create a readable text snippet"""
        if not text:
            return ""
        one_line = re.sub(r"\s+", " ", text).strip()
        if len(one_line) > max_len:
            return one_line[:max_len-3] + "..."
        return one_line
        
    def _normalize_ocr_text(self, text: str) -> str:
        """Enhanced text normalization with leetspeak decoding"""
        lowered = text.lower()
        lowered = unicodedata.normalize("NFKD", lowered)
        lowered = lowered.encode("ascii", "ignore").decode("ascii")
        lowered = lowered.translate(LEETSPEAK_MAP)
        
        # Remove common OCR artifacts
        lowered = re.sub(r"[^a-z0-9\s]", " ", lowered)
        lowered = re.sub(r"\s+", " ", lowered).strip()
        
        # Handle common OCR mistakes
        lowered = lowered.replace("rn", "m")
        lowered = lowered.replace("cl", "d")
        lowered = lowered.replace("vv", "w")
        
        return lowered
        
    @staticmethod
    def _contains_phrase(raw_text: str, normalized_text: str, phrase: str) -> bool:
        """Check if text contains a phrase (case-insensitive with normalization)"""
        phrase_l = phrase.lower().strip()
        if not phrase_l:
            return False
            
        # Direct match
        if phrase_l in raw_text:
            return True
            
        # Normalized match
        phrase_n = re.sub(r"\s+", " ", phrase_l.translate(LEETSPEAK_MAP))
        return phrase_n in normalized_text
        
    def _cache_get(self, key: str) -> ScanResult | None:
        """Get item from cache with TTL check"""
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
        """Put item in cache with LRU eviction"""
        self._cache[key] = (time.time(), result)
        self._cache.move_to_end(key)
        
        while len(self._cache) > self._cache_max_items:
            self._cache.popitem(last=False)
            
    def _find_tesseract(self, custom_path: str | None) -> str | None:
        """Enhanced Tesseract discovery with better Windows support"""
        candidates: List[Path] = []
        
        # Custom path from config
        if custom_path:
            custom_candidate = Path(os.path.expandvars(custom_path)).expanduser()
            candidates.append(custom_candidate)
            
        # From PATH
        from_path = shutil.which("tesseract")
        if from_path:
            candidates.append(Path(from_path))
            
        # Environment variable
        tessdata_prefix = os.environ.get("TESSERACT_CMD", "").strip()
        if tessdata_prefix:
            candidates.append(Path(os.path.expandvars(tessdata_prefix)).expanduser())
            
        # Windows-specific paths
        if os.name == "nt":
            # Common installation locations
            program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
            program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
            
            tesseract_paths = [
                Path(program_files) / "Tesseract-OCR" / "tesseract.exe",
                Path(program_files_x86) / "Tesseract-OCR" / "tesseract.exe",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Tesseract-OCR" / "tesseract.exe",
                Path("C:\\Tesseract-OCR\\tesseract.exe"),
            ]
            candidates.extend(tesseract_paths)
            
            # Check Windows Package Manager installations
            tesseract_paths.extend([
                Path(program_files) / "Tesseract" / "tesseract.exe",
                Path(program_files_x86) / "Tesseract" / "tesseract.exe",
            ])
        else:
            # Unix-like paths
            candidates.extend([
                Path("/usr/bin/tesseract"),
                Path("/usr/local/bin/tesseract"),
                Path("/opt/homebrew/bin/tesseract"),
                Path("/snap/bin/tesseract"),
                Path("/usr/pkg/bin/tesseract"),  # NetBSD
                Path("/opt/local/bin/tesseract"),  # MacPorts
            ])
            
        # Test each candidate
        seen: Set[str] = set()
        for candidate in candidates:
            normalized = str(candidate)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            
            if not (candidate.exists() and candidate.is_file()):
                continue
                
            if not self._is_tesseract_usable(candidate):
                continue
                
            # Set the path for pytesseract
            pytesseract.pytesseract.tesseract_cmd = str(candidate)
            
            # Log successful discovery
            try:
                version_output = subprocess.check_output([str(candidate), "--version"], text=True, timeout=5)
                version_match = re.search(r"tesseract\s+(\d+(?:\.\d+)+)", version_output, re.IGNORECASE)
                if version_match:
                    LOGGER.info(f"Tesseract found: {candidate} (version {version_match.group(1)})")
                else:
                    LOGGER.info(f"Tesseract found: {candidate}")
            except Exception:
                LOGGER.info(f"Tesseract found: {candidate}")
                
            return str(candidate)
            
        LOGGER.warning("Tesseract OCR not found. Install Tesseract to enable image scanning.")
        return None
        
    @staticmethod
    def _is_tesseract_usable(candidate: Path) -> bool:
        """Verify Tesseract is functional"""
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
            
        output = (completed.stdout or b"") + (completed.stderr or b"")
        return b"tesseract" in output.lower()
        
    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize domain name"""
        return domain.lower().strip(". ")
        
    def clear_cache(self) -> None:
        """Clear the scan cache"""
        self._cache.clear()
        LOGGER.info("Image scan cache cleared")
        
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            'size': len(self._cache),
            'max_size': self._cache_max_items,
            'ttl_seconds': self._cache_ttl_seconds,
        }