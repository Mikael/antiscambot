from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta

import discord

from bot.services.image_scan_service import ImageScanService
from bot.storage.guild_config_store import GuildConfigStore


@dataclass(slots=True)
class ModerateResult:
    deleted: bool
    reason: str


class MessageModerationHandler:
    def __init__(
        self,
        *,
        bot_user_id: int,
        config_store: GuildConfigStore,
        image_scanner: ImageScanService,
        threshold: int,
        owner_report_webhook_url: str | None,
    ) -> None:
        self._bot_user_id = bot_user_id
        self._config_store = config_store
        self._image_scanner = image_scanner
        self._threshold = threshold
        self._owner_report_webhook_url = owner_report_webhook_url
        self._download_limit = 6 * 1024 * 1024

    async def handle(self, message: discord.Message) -> ModerateResult:
        if message.author.bot:
            return ModerateResult(False, "ignored_bot")

        if message.guild is None:
            return ModerateResult(False, "ignored_dm")

        if message.author.id == self._bot_user_id:
            return ModerateResult(False, "ignored_self")

        guild_config = await self._config_store.get(message.guild.id)
        if not guild_config.is_guild_setup:
            return ModerateResult(False, "guild_not_setup")

        attachments = [a for a in message.attachments if self._is_image(a)]
        if not attachments:
            return ModerateResult(False, "no_image")

        if not self._image_scanner.tesseract_available:
            return ModerateResult(False, "ocr_unavailable")

        scans = await asyncio.gather(*(self._scan_attachment(a) for a in attachments), return_exceptions=True)

        for result in scans:
            if isinstance(result, Exception):
                continue
            if result.score >= self._threshold:
                deleted = await self._apply_delete(message, guild_config.auto_delete)
                timeout_applied = await self._apply_timeout(message, guild_config.timeout_enabled, guild_config.timeout_minutes)
                await self._notify_channel(message, result, guild_config, deleted, timeout_applied)
                await self._report_to_owner_webhook(message, result, guild_config, deleted, timeout_applied)
                await self._dm_user_warning(message, guild_config.dm_user_warning_enabled)
                return ModerateResult(deleted, f"scam_score_{result.score}")

        return ModerateResult(False, "clean")

    async def _scan_attachment(self, attachment: discord.Attachment):
        content = await attachment.read(use_cached=True)
        if len(content) > self._download_limit:
            content = content[: self._download_limit]
        return await self._image_scanner.scan_bytes(content)

    def _is_image(self, attachment: discord.Attachment) -> bool:
        if attachment.content_type and attachment.content_type.startswith("image/"):
            return True
        filename = attachment.filename.lower()
        return filename.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"))

    async def _apply_delete(self, message: discord.Message, enabled: bool) -> bool:
        if not enabled:
            return False
        try:
            await message.delete()
            return True
        except (discord.Forbidden, discord.NotFound):
            return False

    async def _apply_timeout(self, message: discord.Message, enabled: bool, minutes: int) -> bool:
        if not enabled:
            return False
        if not isinstance(message.author, discord.Member):
            return False
        try:
            await message.author.timeout(
                timedelta(minutes=max(1, minutes)),
                reason="Possible crypto scam image detected",
            )
            return True
        except (discord.Forbidden, discord.HTTPException):
            return False

    async def _notify_channel(self, message: discord.Message, result, guild_config, deleted: bool, timeout_applied: bool) -> None:
        if not guild_config.alert_enabled:
            return

        channel = None
        if guild_config.alert_channel_id:
            channel = message.guild.get_channel(guild_config.alert_channel_id)
            if channel is None:
                try:
                    channel = await message.guild.fetch_channel(guild_config.alert_channel_id)
                except (discord.Forbidden, discord.HTTPException, discord.NotFound):
                    channel = None

        if channel is None:
            return

        reasons = ", ".join(result.reasons) if result.reasons else "none"
        details = (
            f"Scam image detected from {message.author.mention}. "
            f"score={result.score}, deleted={deleted}, timeout={timeout_applied}, reasons={reasons}"
        )
        try:
            await channel.send(details)
        except discord.Forbidden:
            return

    async def _report_to_owner_webhook(self, message: discord.Message, result, guild_config, deleted: bool, timeout_applied: bool) -> None:
        if not guild_config.report_to_owner_enabled:
            return
        if not self._owner_report_webhook_url:
            return

        reasons = ", ".join(result.reasons) if result.reasons else "none"
        attachments = "\n".join(a.url for a in message.attachments if self._is_image(a))

        embed = discord.Embed(
            title="Scam Report Submission",
            color=discord.Color.orange(),
            description="A guild enabled owner reporting for a detected scam image.",
        )
        embed.add_field(name="Guild", value=f"{message.guild.name} (`{message.guild.id}`)", inline=False)
        embed.add_field(name="User", value=f"{message.author} (`{message.author.id}`)", inline=False)
        embed.add_field(name="Channel", value=f"{message.channel.mention} (`{message.channel.id}`)", inline=False)
        embed.add_field(name="Score", value=str(result.score), inline=True)
        embed.add_field(name="Deleted", value=str(deleted), inline=True)
        embed.add_field(name="Timeout", value=str(timeout_applied), inline=True)
        embed.add_field(name="Reasons", value=reasons[:1024], inline=False)
        if attachments:
            embed.add_field(name="Image URLs", value=attachments[:1024], inline=False)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                webhook = discord.Webhook.from_url(self._owner_report_webhook_url, session=session)
                await webhook.send(embed=embed, username="AntiScam Reporter")
        except Exception:
            return

    async def _dm_user_warning(self, message: discord.Message, enabled: bool) -> None:
        if not enabled:
            return
        if not isinstance(message.author, discord.Member):
            return

        text = (
            "Your recent image was flagged as a possible crypto scam and was handled by server moderation. "
            "If your account might be compromised, change your Discord password immediately, "
            "enable 2FA, and review authorized apps/devices."
        )
        try:
            await message.author.send(text)
        except discord.Forbidden:
            return
