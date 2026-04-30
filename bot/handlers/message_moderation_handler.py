from __future__ import annotations

import asyncio
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Set, Tuple, Optional
from functools import lru_cache

import discord
from discord import Forbidden, NotFound, HTTPException

from bot.services.image_scan_service import ImageScanService
from bot.storage.guild_config_store import GuildConfigStore


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ModerateResult:
    deleted: bool
    reason: str
    score: int = 0
    action_taken: str = "none"


@dataclass
class UserInfractionTracker:
    """Track user infractions for progressive discipline"""
    infraction_count: int = 0
    first_offense: Optional[datetime] = None
    last_offense: Optional[datetime] = None
    total_score: int = 0

    def add_infraction(self, score: int) -> None:
        now = datetime.utcnow()
        if self.first_offense is None:
            self.first_offense = now
        self.last_offense = now
        self.infraction_count += 1
        self.total_score += score


class MessageModerationHandler:

    PROGRESSIVE_TIMEOUTS = {
        1: 5,
        2: 30,
        3: 120,
        4: 1440,
        5: 10080,
    }


    USER_ACTION_COOLDOWN = 60

    def __init__(
        self,
        *,
        bot_user_id: int,
        config_store: GuildConfigStore,
        image_scanner: ImageScanService,
        threshold: int,
        owner_report_webhook_url: str | None,
        aggressive_mode: bool = False,
        cache_size: int = 1000,
    ) -> None:
        self._bot_user_id = bot_user_id
        self._config_store = config_store
        self._image_scanner = image_scanner
        self._threshold = threshold
        self._owner_report_webhook_url = owner_report_webhook_url
        self._aggressive_mode = aggressive_mode


        self._processed_messages: Set[int] = set()
        self._user_last_action: Dict[int, datetime] = {}


        self._user_infractions: Dict[Tuple[int, int], UserInfractionTracker] = defaultdict(
            lambda: UserInfractionTracker()
        )


        self._scan_cache: Dict[str, Tuple[int, list, datetime]] = {}
        self._cache_size = cache_size
        self._cache_ttl = timedelta(minutes=10)


        self._scam_indicators = self._build_scam_indicators()

    def _build_scam_indicators(self) -> dict:
        """Build comprehensive scam detection patterns.

        IMPORTANT: every pattern here must be specific enough that it
        does not match ordinary English or unrelated UI text. Bare words
        like "reward", "bonus", "limited", "support" show up constantly
        on legitimate screenshots (Patreon tiers, receipts, game UI),
        so they are always paired with scam-specific context.
        """
        return {
            "urgent_actions": [
                r"(?i)\blimited\s+time\b",
                r"(?i)\bonly\s+\d+\s+(?:left|remaining|spots?|seats?|slots?)\b",
                r"(?i)\blast\s+chance\b",
                r"(?i)\bexpires?\s+(?:soon|today|in\s+\d)\b",
                r"(?i)\bending\s+soon\b",
                r"(?i)\bact\s+now\b",
                r"(?i)\bdon['\u2019]t\s+miss\s+out\b",
                r"(?i)\bclaim\s+(?:now|your\s+(?:reward|prize|bonus))\b",
                r"(?i)\bhurry\s+up\b",
                r"(?i)\bfinal\s+(?:day|chance|warning|hours?)\b",
                r"(?i)\btime\s+(?:is\s+)?running\s+out\b",
            ],
            "financial_rewards": [
                # Bare "$32" is not a scam signal on its own; require it
                # to be paired with reward/free/claim context.
                r"(?i)\b(?:claim|get|receive|win|earn)\s+(?:your\s+)?"
                r"(?:free\s+)?(?:reward|prize|bonus|gift|giveaway)\b",
                r"(?i)\bfree\s+(?:reward|prize|bonus|gift|giveaway|cash|money)\b",
                r"(?i)\bcash\s+out\b",
                r"(?i)\bwithdraw\s+(?:your\s+)?(?:funds?|money|balance|usdt|crypto)\b",
                r"(?i)\bcredited\s+to\s+your\s+(?:account|balance|wallet)\b",
                r"(?i)\bdeposited\s+to\s+your\s+(?:account|balance|wallet)\b",
                r"(?i)\badded\s+to\s+(?:your\s+)?balance\b",
            ],
            "authority_spoofing": [
                r"(?i)\bdiscord\s+(?:staff|team|admin|moderator|support)\b",
                r"(?i)\b(?:official|verified)\s+(?:discord|steam|epic|riot)\b",
                r"(?i)\b(?:steam|riot|epic)\s+support\b",
            ],
            "compromise_signals": [
                r"(?i)\baccount\s+(?:has\s+been\s+)?(?:compromised|hacked|stolen|suspended)\b",
                r"(?i)\bverify\s+(?:your\s+)?(?:identity|account|login)\b",
                r"(?i)\bsecure\s+your\s+account\b",
                r"(?i)\bunusual\s+(?:login|activity|sign[- ]in)\b",
            ],
            "crypto_scam": [
                # Generic crypto words alone are NOT a scam signal -- require
                # them paired with promo/free/reward/claim/airdrop context.
                r"(?i)\bfree\s+(?:crypto|bitcoin|ethereum|usdt|btc|eth)\b",
                r"(?i)\bclaim\s+(?:your\s+)?(?:crypto|usdt|btc|eth|airdrop|tokens?)\b",
                r"(?i)\b(?:airdrop|presale|ico|token\s+sale)\b",
                r"(?i)\bconnect\s+(?:your\s+)?wallet\b",
                r"0x[a-fA-F0-9]{40}",  # ETH address
                r"bc1[a-zA-HJ-NP-Z0-9]{25,39}",  # BTC bech32
                # BTC legacy patterns are too permissive (they false-match
                # random base58-looking OCR noise), so they were removed.
                # Use WALLET_PATTERNS in image_scan_service for those.
            ],
            "social_engineering": [
                r"(?i)\b(?:a\s+)?friend\s+(?:just\s+)?(?:sent|gifted)\s+you\b",
                r"(?i)\bsomeone\s+(?:just\s+)?gifted\s+you\b",
                r"(?i)\btag\s+a\s+friend\s+to\b",
                r"(?i)\bdm\s+me\s+(?:on|at|for)\b",
            ],
        }

    async def handle(self, message: discord.Message) -> ModerateResult:
        """Main entry point with improved detection and progressive discipline"""


        if skip_result := await self._early_checks(message):
            return skip_result

        guild_config = await self._config_store.get(message.guild.id)
        if not guild_config.is_guild_setup:
            return ModerateResult(False, "guild_not_setup")


        if message.id in self._processed_messages:
            return ModerateResult(False, "already_processed")
        self._processed_messages.add(message.id)


        if len(self._processed_messages) > 1000:
            self._processed_messages.clear()


        image_attachments = [a for a in message.attachments if self._is_image(a)]
        if not image_attachments:
            return ModerateResult(False, "no_image_attachments" if message.attachments else "no_attachment")


        if not self._image_scanner.tesseract_available:
            LOGGER.warning("OCR unavailable for message %s", message.id)
            return ModerateResult(False, "ocr_unavailable")


        scans = await self._scan_attachments_with_retry(message, image_attachments)


        for scan_result in scans:
            if scan_result is None:
                continue


            is_scam, confidence_score = self._calculate_confidence(scan_result)

            if not is_scam:
                LOGGER.debug(
                    "Message %s not flagged: score=%s reasons=%s",
                    message.id, scan_result.score, scan_result.reasons
                )
                continue


            return await self._apply_moderation_actions(
                message, scan_result, guild_config, confidence_score
            )

        LOGGER.debug("Message %s clean after scanning %d images", message.id, len(image_attachments))
        return ModerateResult(False, "clean")

    async def _early_checks(self, message: discord.Message) -> Optional[ModerateResult]:
        """Perform early checks to filter out messages"""
        if message.author.bot:
            return ModerateResult(False, "ignored_bot")
        if message.guild is None:
            return ModerateResult(False, "ignored_dm")
        if message.author.id == self._bot_user_id:
            return ModerateResult(False, "ignored_self")
        return None

    def _calculate_confidence(self, scan_result) -> Tuple[bool, int]:
        """Enhanced confidence calculation with weighted scoring"""

        has_blocked_domain = any(r.startswith("blocked_domain") for r in scan_result.reasons)
        blocked_words_hits = self._extract_reason_hits(scan_result.reasons, "blocked_words")
        core_phrase_hits = self._extract_reason_hits(scan_result.reasons, "core_phrases")
        core_token_hits = self._extract_reason_hits(scan_result.reasons, "core_tokens")
        has_wallet = any(r == "wallet_address_like" for r in scan_result.reasons)


        weighted_score = scan_result.score


        if has_blocked_domain:
            weighted_score += 5


        weighted_score += core_phrase_hits * 2


        if has_wallet and core_token_hits >= 2:
            weighted_score += 3


        effective_threshold = self._threshold - 2 if self._aggressive_mode else self._threshold


        is_confident = weighted_score >= effective_threshold


        if has_blocked_domain and weighted_score >= 3:
            is_confident = True
        elif has_wallet and core_phrase_hits >= 1 and weighted_score >= 4:
            is_confident = True
        elif core_phrase_hits >= 2 and core_token_hits >= 3:
            is_confident = True
        elif blocked_words_hits >= 3:
            is_confident = True
        elif len(scan_result.reasons) >= 4 and self._has_strong_signal(scan_result.reasons):
            # Piling up many weak reasons is not enough on its own -- benign
            # text-heavy screenshots (support chats, receipts, ToS pages)
            # easily accumulate 4+ low-weight matches. Require at least one
            # high-signal category before we accept this fallback.
            is_confident = True


        if hasattr(scan_result, 'extracted_text') and scan_result.extracted_text:
            pattern_score = self._check_scam_patterns(scan_result.extracted_text)
            if pattern_score >= 3:
                is_confident = True
                weighted_score += pattern_score

        return is_confident, weighted_score

    def _check_scam_patterns(self, text: str) -> int:
        """Check text against predefined scam patterns"""
        score = 0
        text_lower = text.lower()

        for category, patterns in self._scam_indicators.items():
            category_score = 0
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    category_score += 1
            if category_score >= 2:
                score += category_score

        return min(score, 10)

    async def _scan_attachments_with_retry(self, message: discord.Message, attachments: list) -> list:
        """Scan attachments concurrently, with per-attachment caching + retry.

        Attachments are downloaded AND scanned in parallel via asyncio.gather.
        The OCR service itself also bounds CPU concurrency internally, so
        spawning many coroutines here is safe even across many guilds.
        """
        return await asyncio.gather(
            *(self._scan_single_attachment(a) for a in attachments),
            return_exceptions=False,
        )

    async def _scan_single_attachment(self, attachment: discord.Attachment):
        """Download + scan one attachment with cache and bounded retries."""
        cache_key = f"{attachment.id}_{attachment.size}"
        cached = self._scan_cache.get(cache_key)
        if cached is not None:
            score, reasons, ts = cached
            if datetime.utcnow() - ts < self._cache_ttl:
                return type("ScanResult", (), {"score": score, "reasons": reasons})()

        if attachment.size and attachment.size > 12 * 1024 * 1024:
            return None

        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                content = await attachment.read(use_cached=True)
                result = await self._image_scanner.scan_bytes(content)
                if result and hasattr(result, "score"):
                    self._update_cache(cache_key, result.score, result.reasons)
                return result
            except (HTTPException, ConnectionError, TimeoutError) as exc:
                last_exc = exc
                await asyncio.sleep(0.5 * (attempt + 1))
            except Exception as exc:
                LOGGER.warning("Unexpected scan error on %s: %s", attachment.filename, exc)
                return None

        LOGGER.error(
            "Failed to scan %s after 3 attempts: %s", attachment.filename, last_exc
        )
        return None

    def _update_cache(self, key: str, score: int, reasons: list) -> None:
        """Update scan cache with LRU eviction"""
        if len(self._scan_cache) >= self._cache_size:

            to_remove = len(self._scan_cache) - self._cache_size + 100
            for _ in range(to_remove):
                if self._scan_cache:
                    self._scan_cache.pop(next(iter(self._scan_cache)))
        self._scan_cache[key] = (score, reasons, datetime.utcnow())

    async def _apply_moderation_actions(
        self,
        message: discord.Message,
        scan_result,
        guild_config,
        score: int
    ) -> ModerateResult:
        """Apply moderation with progressive discipline"""

        user_key = (message.guild.id, message.author.id)

        tracker = self._user_infractions[user_key]
        tracker.add_infraction(score)


        timeout_minutes = self.PROGRESSIVE_TIMEOUTS.get(
            min(tracker.infraction_count, max(self.PROGRESSIVE_TIMEOUTS.keys())),
            60
        )


        LOGGER.warning(
            "SCAM DETECTED: User=%s (infraction #%d), Score=%d, Reasons=%s",
            message.author.id, tracker.infraction_count, score, scan_result.reasons
        )


        deleted = False
        timeout_applied = False


        if guild_config.auto_delete:
            deleted = await self._apply_delete(message, True)


        if guild_config.timeout_enabled:
            timeout_applied = await self._apply_timeout(
                message, True, timeout_minutes
            )


        await self._notify_channel(message, scan_result, guild_config, deleted, timeout_applied, tracker.infraction_count)
        await self._report_to_owner_webhook(message, scan_result, guild_config, deleted, timeout_applied)


        if guild_config.dm_user_warning_enabled:
            await self._dm_user_warning(message, tracker.infraction_count)


        self._user_last_action[message.author.id] = datetime.utcnow()

        action_desc = f"deleted={deleted}, timeout={timeout_minutes}m" if timeout_applied else f"deleted={deleted}"
        return ModerateResult(deleted, f"scam_score_{score}", score=score, action_taken=action_desc)

    @staticmethod
    def _extract_reason_hits(reasons: list[str], key: str) -> int:
        """Extract hit counts from reason strings with improved parsing"""
        max_hits = 0
        prefix = f"{key}("
        for reason in reasons:
            if not reason.startswith(prefix):
                continue
            try:

                start = len(prefix)
                paren_count = 1
                end = start
                while end < len(reason) and paren_count > 0:
                    if reason[end] == '(':
                        paren_count += 1
                    elif reason[end] == ')':
                        paren_count -= 1
                    end += 1
                value = int(reason[start:end-1])
            except (IndexError, ValueError):
                value = 1
            if value > max_hits:
                max_hits = value
        return max_hits

    # Reason-prefixes that indicate an actual scam signal (not just generic
    # English text or weak heuristics). If none of these show up, a scan
    # with many reasons is almost always a false positive on a text-heavy
    # screenshot.
    _STRONG_REASON_PREFIXES: tuple[str, ...] = (
        "blocked_domain",
        "blocked_words",
        "core_phrases",
        "wallet_address",
        "url_shortener",
        "promotion_scam",
    )

    @classmethod
    def _has_strong_signal(cls, reasons: list[str]) -> bool:
        """Return True if at least one reason comes from a high-signal category."""
        return any(
            reason.startswith(prefix)
            for reason in reasons
            for prefix in cls._STRONG_REASON_PREFIXES
        )

    async def _scan_attachment(self, attachment: discord.Attachment):
        """Legacy method - kept for compatibility"""
        if attachment.size and attachment.size > 12 * 1024 * 1024:
            return None
        content = await attachment.read(use_cached=True)
        return await self._image_scanner.scan_bytes(content)

    def _is_image(self, attachment: discord.Attachment) -> bool:
        """Check if attachment is an image with better MIME type handling"""
        if attachment.content_type:
            if attachment.content_type.startswith("image/"):
                return True

            if attachment.content_type in {"application/octet-stream", "binary/octet-stream"}:
                filename = attachment.filename.lower()
                return filename.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"))
        filename = attachment.filename.lower()
        return filename.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".tif", ".tiff"))

    async def _apply_delete(self, message: discord.Message, enabled: bool) -> bool:
        """Delete message with better error handling"""
        if not enabled:
            return False
        try:
            await message.delete()
            LOGGER.info("Deleted scam message %s from user %s", message.id, message.author.id)
            return True
        except Forbidden:
            LOGGER.warning("No permission to delete message %s", message.id)
            return False
        except NotFound:
            LOGGER.debug("Message %s already deleted", message.id)
            return False
        except HTTPException as e:
            LOGGER.error("Failed to delete message %s: %s", message.id, e)
            return False

    async def _apply_timeout(self, message: discord.Message, enabled: bool, minutes: int) -> bool:
        """Apply timeout with progressive duration"""
        if not enabled:
            return False
        if not isinstance(message.author, discord.Member):
            return False
        try:

            if message.author.guild_permissions.administrator:
                LOGGER.info("Skipping timeout for admin %s", message.author.id)
                return False

            duration = timedelta(minutes=max(1, min(minutes, 10080)))
            await message.author.timeout(duration, reason="Crypto scam image detected")
            LOGGER.info("Timed out user %s for %d minutes", message.author.id, minutes)
            return True
        except Forbidden:
            LOGGER.warning("No permission to timeout user %s", message.author.id)
            return False
        except HTTPException as e:
            LOGGER.error("Failed to timeout user %s: %s", message.author.id, e)
            return False

    async def _notify_channel(
        self,
        message: discord.Message,
        result,
        guild_config,
        deleted: bool,
        timeout_applied: bool,
        infraction_count: int
    ) -> None:
        """Enhanced notification with more details"""
        if not guild_config.alert_enabled:
            return

        channel = None
        if guild_config.alert_channel_id:
            channel = message.guild.get_channel(guild_config.alert_channel_id)
            if channel is None:
                try:
                    channel = await message.guild.fetch_channel(guild_config.alert_channel_id)
                except (Forbidden, HTTPException, NotFound):
                    channel = None

        if channel is None:
            return


        if result.score >= 8:
            color = discord.Color.dark_red()
        elif result.score >= 5:
            color = discord.Color.red()
        else:
            color = discord.Color.orange()

        embed = discord.Embed(
            title="🚨 Scam Image Detected",
            description=f"**{message.author.mention}** posted a flagged image.",
            color=color,
            timestamp=datetime.utcnow()
        )


        embed.add_field(name="🎯 Confidence Score", value=f"`{result.score}/10`", inline=True)
        embed.add_field(name="⚠️ Infraction #", value=f"`{infraction_count}`", inline=True)
        embed.add_field(name="🗑️ Message Deleted", value="✅ Yes" if deleted else "❌ No", inline=True)
        embed.add_field(name="⏰ User Timed Out", value=f"✅ {timeout_applied}" if timeout_applied else "❌ No", inline=True)
        embed.add_field(name="📢 Channel", value=message.channel.mention, inline=True)
        embed.add_field(name="👤 User", value=f"{message.author} (`{message.author.id}`)", inline=False)


        if result.reasons:
            reasons_text = ", ".join(result.reasons[:5])
            if len(result.reasons) > 5:
                reasons_text += f" (+{len(result.reasons)-5} more)"
            embed.add_field(name="🔍 Detection Reasons", value=f"```{reasons_text}```", inline=False)


        image_urls = [a.url for a in message.attachments if self._is_image(a)]
        if image_urls:
            embed.set_image(url=image_urls[0])
            embed.add_field(name="📸 Image URL", value=f"[Click to view]({image_urls[0]})", inline=False)

        embed.set_footer(text=f"Message ID: {message.id} • User ID: {message.author.id}")

        try:
            await channel.send(embed=embed)
        except Forbidden:
            LOGGER.warning("Cannot send alert to channel %s", channel.id)
            return

    async def _report_to_owner_webhook(
        self,
        message: discord.Message,
        result,
        guild_config,
        deleted: bool,
        timeout_applied: bool
    ) -> None:
        """Report to owner webhook with full details"""
        if not guild_config.report_to_owner_enabled:
            return
        if not self._owner_report_webhook_url:
            return

        reasons = ", ".join(result.reasons) if result.reasons else "none"
        attachments = "\n".join(a.url for a in message.attachments if self._is_image(a))

        embed = discord.Embed(
            title="📊 Scam Report Submission",
            color=discord.Color.orange(),
            description="A guild has reported a detected scam image.",
            timestamp=datetime.utcnow()
        )

        embed.add_field(name="🏢 Guild", value=f"{message.guild.name} (`{message.guild.id}`)", inline=False)
        embed.add_field(name="👤 User", value=f"{message.author} (`{message.author.id}`)", inline=False)
        embed.add_field(name="💬 Channel", value=f"{message.channel.mention} (`{message.channel.id}`)", inline=False)
        embed.add_field(name="🎯 Score", value=f"`{result.score}/10`", inline=True)
        embed.add_field(name="🗑️ Deleted", value=str(deleted), inline=True)
        embed.add_field(name="⏰ Timeout", value=str(timeout_applied), inline=True)
        embed.add_field(name="🔍 Reasons", value=f"```{reasons[:1024]}```", inline=False)

        if attachments:
            embed.add_field(name="📸 Image URLs", value=attachments[:1024], inline=False)


        if message.content:
            embed.add_field(name="💬 Message Content", value=message.content[:1024], inline=False)

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                webhook = discord.Webhook.from_url(self._owner_report_webhook_url, session=session)
                await webhook.send(embed=embed, username="AntiScam Reporter", avatar_url=None)
        except Exception as e:
            LOGGER.error("Failed to send owner report: %s", e)

    async def _dm_user_warning(self, message: discord.Message, infraction_count: int) -> None:
        """Send DM warning with progressive messaging"""
        if not isinstance(message.author, discord.Member):
            return


        if infraction_count == 1:
            text = (
                "⚠️ **Warning**: Your recent image was flagged as a possible crypto scam. "
                "If this was a mistake, please contact server staff.\n\n"
                "If your account might be compromised, change your Discord password immediately, "
                "enable 2FA, and review authorized apps."
            )
        elif infraction_count <= 3:
            text = (
                f"⚠️ **Warning #{infraction_count}**: You have been flagged for posting suspicious content. "
                "Further violations may result in longer timeouts or a ban.\n\n"
                "**Security Recommendations:**\n"
                "• Change your Discord password\n"
                "• Enable 2-factor authentication\n"
                "• Remove unrecognized authorized apps\n"
                "• Scan your computer for malware"
            )
        else:
            text = (
                f"🚨 **FINAL WARNING** (Infraction #{infraction_count}): "
                "You have repeatedly posted scam content. The server may take further action "
                "including a permanent ban.\n\n"
                "**Immediate actions required:**\n"
                "1. Change your password immediately\n"
                "2. Check for unauthorized sessions in Discord settings\n"
                "3. Contact server staff if your account was compromised"
            )

        try:
            await message.author.send(text)
            LOGGER.debug("Sent warning DM to user %s (infraction #%d)", message.author.id, infraction_count)
        except Forbidden:
            LOGGER.debug("Cannot DM user %s (DMs disabled)", message.author.id)
        except HTTPException as e:
            LOGGER.error("Failed to DM user %s: %s", message.author.id, e)
