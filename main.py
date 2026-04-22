from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime

import discord
from discord.ext import commands
from motor.motor_asyncio import AsyncIOMotorClient

from bot.core.settings import load_settings
from bot.events.guild_lifecycle import GuildLifecycleEventHandler
from bot.events.message_create import MessageCreateEventHandler
from bot.handlers.help_command_handler import HelpCommandHandler
from bot.handlers.message_moderation_handler import MessageModerationHandler
from bot.handlers.setup_command_handler import SetupCommandHandler
from bot.services.image_scan_service import ImageScanService
from bot.storage.guild_config_store import GuildConfigStore
from bot.storage.scam_rule_repository import ScamRuleRepository


def _sanitize_error_message(message: str) -> str:
    return re.sub(r"mongodb(?:\+srv)?://[^\s\"']+", "mongodb://<redacted>", message, flags=re.IGNORECASE)


class AntiScamBot(commands.AutoShardedBot):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.guilds = True
        intents.guild_messages = True
        intents.message_content = True

        super().__init__(command_prefix="!", intents=intents, shard_count=None)

        self.settings = load_settings()
        self.mongo_client = AsyncIOMotorClient(self.settings.mongodb_uri)
        database = self.mongo_client[self.settings.mongodb_database]
        guild_collection = database[self.settings.guild_config_collection]
        rule_collection = database[self.settings.scam_rules_collection]
        self.config_store = GuildConfigStore(guild_collection)
        self.rule_repository = ScamRuleRepository(
            rule_collection,
            refresh_interval_seconds=self.settings.rule_refresh_interval_seconds,
        )
        self.image_scanner = ImageScanService(
            tesseract_cmd=self.settings.tesseract_cmd,
            rule_repository=self.rule_repository,
            workers=self.settings.ocr_workers,
        )
        self._message_handler: MessageCreateEventHandler | None = None
        self._guild_handler: GuildLifecycleEventHandler | None = None

    async def setup_hook(self) -> None:
        await self.config_store.load()
        await self.rule_repository.start()

        if self.user is None:
            await asyncio.sleep(0)

        moderation = MessageModerationHandler(
            bot_user_id=(self.user.id if self.user else 0),
            config_store=self.config_store,
            image_scanner=self.image_scanner,
            threshold=self.settings.scam_threshold,
            owner_report_webhook_url=self.settings.owner_report_webhook_url,
        )

        self._message_handler = MessageCreateEventHandler(moderation)
        self._guild_handler = GuildLifecycleEventHandler(self.config_store)

        setup_handler = SetupCommandHandler(self.config_store)
        help_handler = HelpCommandHandler()
        self.tree.add_command(setup_handler.build_setup())
        self.tree.add_command(setup_handler.build_settings())
        self.tree.add_command(help_handler.build())
        await self.tree.sync()

    async def on_ready(self) -> None:
        guild_count = len(self.guilds)
        user_tag = str(self.user) if self.user else "unknown-user"
        shard_total = self.shard_count or 1
        logging.info("AntiScamBot online | user=%s | guilds=%s | shards=%s", user_tag, guild_count, shard_total)

    async def on_guild_join(self, guild: discord.Guild) -> None:
        if self._guild_handler is None:
            return
        await self._guild_handler.on_guild_join(guild)

    async def on_message(self, message: discord.Message) -> None:
        if self._message_handler is None:
            return
        await self._message_handler.on_message(message)

    async def close(self) -> None:
        self.image_scanner.shutdown()
        await self.rule_repository.close()
        self.mongo_client.close()
        await super().close()


class FancyLogFormatter(logging.Formatter):
    LEVEL_STYLES = {
        logging.DEBUG: "DBG",
        logging.INFO: "INF",
        logging.WARNING: "WRN",
        logging.ERROR: "ERR",
        logging.CRITICAL: "CRT",
    }

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now().strftime("%H:%M:%S")
        level = self.LEVEL_STYLES.get(record.levelno, "LOG")
        name = record.name.rsplit(".", 1)[-1]
        message = record.getMessage()
        return f"[{ts}] [{level}] {name}: {message}"


def configure_logging() -> None:
    formatter = FancyLogFormatter()

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers.clear()

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    root.addHandler(stream)

    logging.getLogger("discord").setLevel(logging.WARNING)
    logging.getLogger("discord.gateway").setLevel(logging.WARNING)
    logging.getLogger("discord.client").setLevel(logging.WARNING)


def main() -> None:
    configure_logging()
    try:
        bot = AntiScamBot()
        bot.run(bot.settings.discord_token)
    except Exception as exc:
        logging.error("Startup failure: %s", _sanitize_error_message(str(exc)))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
