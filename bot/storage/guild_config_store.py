from __future__ import annotations

import asyncio

from motor.motor_asyncio import AsyncIOMotorCollection

from bot.models.guild_config import GuildConfig


class GuildConfigStore:
    def __init__(self, collection: AsyncIOMotorCollection) -> None:
        self._collection = collection
        self._cache: dict[int, GuildConfig] = {}
        self._lock = asyncio.Lock()

    async def load(self) -> None:
        cursor = self._collection.find({}, {"_id": 0})
        configs = await cursor.to_list(length=None)
        self._cache = {
            int(item["guild_id"]): GuildConfig.from_dict(item)
            for item in configs
            if "guild_id" in item
        }

    async def ensure_guild(self, guild_id: int, *, is_setup: bool = False) -> GuildConfig:
        config = self._cache.get(guild_id)
        if config is not None:
            return config

        async with self._lock:
            existing = self._cache.get(guild_id)
            if existing is not None:
                return existing

            default_cfg = GuildConfig(guild_id=guild_id, is_guild_setup=is_setup)
            await self._collection.update_one(
                {"guild_id": guild_id},
                {"$setOnInsert": default_cfg.to_dict()},
                upsert=True,
            )

            doc = await self._collection.find_one({"guild_id": guild_id}, {"_id": 0})
            config = GuildConfig.from_dict(doc) if doc else default_cfg
            self._cache[guild_id] = config
            return config

    async def update(self, guild_id: int, **changes) -> GuildConfig:
        async with self._lock:
            existing = self._cache.get(guild_id) or GuildConfig(guild_id=guild_id)
            data = existing.to_dict()
            data.update(changes)
            updated = GuildConfig.from_dict(data)

            await self._collection.update_one(
                {"guild_id": guild_id},
                {"$set": updated.to_dict()},
                upsert=True,
            )
            self._cache[guild_id] = updated
            return updated

    async def set_setup(self, guild_id: int, is_setup: bool) -> GuildConfig:
        return await self.update(guild_id, is_guild_setup=is_setup)

    async def get(self, guild_id: int) -> GuildConfig:
        cfg = self._cache.get(guild_id)
        if cfg is not None:
            return cfg
        return await self.ensure_guild(guild_id, is_setup=False)

    def is_setup(self, guild_id: int) -> bool:
        config = self._cache.get(guild_id)
        return bool(config and config.is_guild_setup)
