from __future__ import annotations

import discord

from bot.storage.guild_config_store import GuildConfigStore


class GuildLifecycleEventHandler:
    def __init__(self, config_store: GuildConfigStore) -> None:
        self._config_store = config_store

    async def on_guild_join(self, guild: discord.Guild) -> None:
        await self._config_store.ensure_guild(guild.id, is_setup=False)

        owner = guild.owner
        if owner is None:
            return

        message = (
            f"Hi {owner.mention}, anti-scam moderation is not configured yet for **{guild.name}**. "
            "Run `/setupbot` in your server as an administrator to enable image moderation."
        )

        try:
            await owner.send(message)
        except discord.Forbidden:
            return
