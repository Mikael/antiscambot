from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class BotConfig:
    # Bot Core
    discord_token: str
    command_prefix: str = "!"
    debug_mode: bool = False
    
    # Database
    mongodb_uri: str = "mongodb://localhost:27017"
    database_name: str = "antiscambot"
    
    # OCR / Image Scanning
    tesseract_cmd: Optional[str] = None
    ocr_workers: int = 4
    use_process_pool: bool = True
    cache_ttl_seconds: int = 900
    cache_max_items: int = 2000
    enable_ml_fallback: bool = True
    aggressive_ocr_mode: bool = False
    
    # Logging
    log_level: str = "INFO"
    
    # Railway specific
    port: int = 8080
    public_url: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> BotConfig:
        """Load configuration from environment variables (Railway compatible)"""
        return cls(
            discord_token=os.environ.get("DISCORD_TOKEN", ""),
            command_prefix=os.environ.get("COMMAND_PREFIX", "!"),
            debug_mode=os.environ.get("DEBUG_MODE", "false").lower() == "true",
            mongodb_uri=os.environ.get("MONGODB_URI", "mongodb://localhost:27017"),
            database_name=os.environ.get("DATABASE_NAME", "antiscambot"),
            tesseract_cmd=os.environ.get("TESSERACT_CMD"),
            ocr_workers=int(os.environ.get("OCR_WORKERS", "4")),
            use_process_pool=os.environ.get("USE_PROCESS_POOL", "true").lower() == "true",
            cache_ttl_seconds=int(os.environ.get("CACHE_TTL_SECONDS", "900")),
            cache_max_items=int(os.environ.get("CACHE_MAX_ITEMS", "2000")),
            enable_ml_fallback=os.environ.get("ENABLE_ML_FALLBACK", "true").lower() == "true",
            aggressive_ocr_mode=os.environ.get("AGGRESSIVE_OCR_MODE", "false").lower() == "true",
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
            port=int(os.environ.get("PORT", "8080")),
            public_url=os.environ.get("RAILWAY_PUBLIC_DOMAIN") or os.environ.get("PUBLIC_URL"),
        )
    
    def validate(self) -> list[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        if not self.discord_token:
            errors.append("DISCORD_TOKEN environment variable is required")
        
        if self.ocr_workers < 1:
            errors.append("OCR_WORKERS must be at least 1")
            
        return errors
