from __future__ import annotations

import discord

from bot.handlers.message_moderation_handler import MessageModerationHandler


class MessageCreateEventHandler:
    def __init__(self, moderation_handler: MessageModerationHandler) -> None:
        self._moderation_handler = moderation_handler

    async def on_message(self, message: discord.Message) -> None:
        await self._moderation_handler.handle(message)
