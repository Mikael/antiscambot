from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Settings:
    discord_token: str
    tesseract_cmd: str | None
    scam_threshold: int
    ocr_workers: int | None
    mongodb_uri: str
    mongodb_database: str
    guild_config_collection: str
    scam_rules_collection: str
    rule_refresh_interval_seconds: int


def load_settings(config_path: str = "config.ini") -> Settings:
    path = Path(config_path)
    if not path.exists() or not path.is_file():
        raise ValueError(f"Missing config file: {config_path}")

    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")

    token = parser.get("discord", "token", fallback="").strip()
    if not token:
        raise ValueError("Missing discord.token in config.ini")

    mongodb_uri = parser.get("mongodb", "uri", fallback="").strip()
    mongodb_database = parser.get("mongodb", "database", fallback="").strip()
    guild_config_collection = parser.get("mongodb", "guild_config_collection", fallback="guild_config").strip()
    scam_rules_collection = parser.get("mongodb", "scam_rules_collection", fallback="scam_rules").strip()

    if not mongodb_uri:
        raise ValueError("Missing mongodb.uri in config.ini")
    if not mongodb_database:
        raise ValueError("Missing mongodb.database in config.ini")

    threshold = parser.getint("moderation", "scam_threshold", fallback=5)

    tesseract_cmd = parser.get("ocr", "tesseract_cmd", fallback="").strip() or None
    workers_raw = parser.get("ocr", "workers", fallback="").strip()

    return Settings(
        discord_token=token,
        tesseract_cmd=tesseract_cmd,
        scam_threshold=max(1, threshold),
        ocr_workers=int(workers_raw) if workers_raw else None,
        mongodb_uri=mongodb_uri,
        mongodb_database=mongodb_database,
        guild_config_collection=guild_config_collection,
        scam_rules_collection=scam_rules_collection,
        rule_refresh_interval_seconds=max(5, parser.getint("moderation", "rule_refresh_interval_seconds", fallback=30)),
    )
