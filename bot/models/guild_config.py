from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class GuildConfig:
    guild_id: int
    is_guild_setup: bool = False
    auto_delete: bool = True
    timeout_enabled: bool = False
    timeout_minutes: int = 10
    alert_enabled: bool = False
    alert_channel_id: int | None = None
    report_to_owner_enabled: bool = False

    @classmethod
    def from_dict(cls, payload: dict) -> "GuildConfig":
        return cls(
            guild_id=int(payload["guild_id"]),
            is_guild_setup=bool(payload.get("is_guild_setup", False)),
            auto_delete=bool(payload.get("auto_delete", True)),
            timeout_enabled=bool(payload.get("timeout_enabled", False)),
            timeout_minutes=max(1, int(payload.get("timeout_minutes", 10))),
            alert_enabled=bool(payload.get("alert_enabled", False)),
            alert_channel_id=(
                int(payload["alert_channel_id"])
                if payload.get("alert_channel_id") is not None
                else None
            ),
            report_to_owner_enabled=bool(payload.get("report_to_owner_enabled", False)),
        )

    def to_dict(self) -> dict:
        return {
            "guild_id": self.guild_id,
            "is_guild_setup": self.is_guild_setup,
            "auto_delete": self.auto_delete,
            "timeout_enabled": self.timeout_enabled,
            "timeout_minutes": self.timeout_minutes,
            "alert_enabled": self.alert_enabled,
            "alert_channel_id": self.alert_channel_id,
            "report_to_owner_enabled": self.report_to_owner_enabled,
        }
