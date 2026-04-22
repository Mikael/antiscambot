from __future__ import annotations

import logging

import discord

from bot.storage.guild_config_store import GuildConfigStore


class GuildLifecycleEventHandler:
    def __init__(self, config_store: GuildConfigStore) -> None:
        self._config_store = config_store

    async def on_guild_join(self, guild: discord.Guild) -> None:
        await self._config_store.ensure_guild(guild.id, is_setup=False)

        owner = guild.owner
        if owner is None and guild.owner_id is not None:
            try:
                owner = await guild.fetch_member(guild.owner_id)
            except (discord.Forbidden, discord.HTTPException, discord.NotFound):
                owner = None

        if owner is None:
            logging.warning("Could not resolve guild owner for guild_id=%s", guild.id)
            await self._notify_fallback_channel(guild, None)
            return

        message = (
            f"Hi {owner.mention}, anti-scam moderation is not configured yet for **{guild.name}**. "
            "Run `/setupbot` in your server as an administrator to enable image moderation."
        )

        try:
            await owner.send(message)
        except discord.Forbidden:
            logging.info("Owner DMs closed for guild_id=%s owner_id=%s", guild.id, owner.id)
            await self._notify_fallback_channel(guild, owner.id)
            return

    async def _notify_fallback_channel(self, guild: discord.Guild, owner_id: int | None) -> None:
        target = guild.system_channel
        if target is None:
            return
        if not target.permissions_for(guild.me).send_messages:
            return

        owner_text = f"<@{owner_id}>" if owner_id else "Guild owner"
        text = (
            f"{owner_text} anti-scam moderation is not configured yet. "
            "Run `/setupbot` as an administrator to enable image moderation."
        )
        try:
            await target.send(text)
        except (discord.Forbidden, discord.HTTPException):
            return
