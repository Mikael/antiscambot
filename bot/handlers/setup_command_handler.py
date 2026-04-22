from __future__ import annotations

import discord
from discord import app_commands

from bot.storage.guild_config_store import GuildConfigStore


class SetupCommandHandler:
    def __init__(self, config_store: GuildConfigStore) -> None:
        self._config_store = config_store

    def build_setup(self) -> app_commands.Command:
        @app_commands.command(name="setupbot", description="Initial anti-scam setup for this server")
        @app_commands.default_permissions(administrator=True)
        @app_commands.describe(
            auto_delete="Automatically delete messages with scam images",
            timeout_enabled="Timeout users when scam image is detected",
            timeout_minutes="Timeout duration preset",
            alert_enabled="Send alerts to a channel",
            alert_channel="Channel for moderation alerts",
            report_to_owner_enabled="Submit detected scam images to owner webhook",
            dm_user_warning_enabled="DM user safety warning when scam image is detected",
        )
        @app_commands.choices(
            timeout_minutes=[
                app_commands.Choice(name="60secs", value=1),
                app_commands.Choice(name="5 mins", value=5),
                app_commands.Choice(name="10 mins", value=10),
                app_commands.Choice(name="1 hour", value=60),
                app_commands.Choice(name="1 day", value=1440),
                app_commands.Choice(name="1 week", value=10080),
            ]
        )
        async def setupbot(
            interaction: discord.Interaction,
            auto_delete: bool,
            timeout_enabled: bool,
            timeout_minutes: app_commands.Choice[int],
            alert_enabled: bool = False,
            alert_channel: discord.TextChannel | None = None,
            report_to_owner_enabled: bool = False,
            dm_user_warning_enabled: bool = False,
        ) -> None:
            if interaction.guild is None:
                await interaction.response.send_message("This command must be used in a server.", ephemeral=True)
                return

            member = interaction.user
            if not isinstance(member, discord.Member) or not member.guild_permissions.administrator:
                await interaction.response.send_message("Only administrators can run this command.", ephemeral=True)
                return

            if alert_enabled and alert_channel is None:
                await interaction.response.send_message(
                    "You enabled alerts, but no alert channel was selected.",
                    ephemeral=True,
                )
                return

            config = await self._config_store.update(
                interaction.guild.id,
                is_guild_setup=True,
                auto_delete=auto_delete,
                timeout_enabled=timeout_enabled,
                timeout_minutes=int(timeout_minutes.value),
                alert_enabled=alert_enabled,
                alert_channel_id=(alert_channel.id if alert_channel else None),
                report_to_owner_enabled=report_to_owner_enabled,
                dm_user_warning_enabled=dm_user_warning_enabled,
            )

            await interaction.response.send_message(self._format_config_message(config, created=True), ephemeral=True)

        return setupbot

    def build_settings(self) -> app_commands.Command:
        @app_commands.command(name="antiscam-settings", description="Update anti-scam moderation settings")
        @app_commands.default_permissions(administrator=True)
        @app_commands.describe(
            auto_delete="Automatically delete messages with scam images",
            timeout_enabled="Timeout users when scam image is detected",
            timeout_minutes="Timeout duration in minutes (1-40320)",
            alert_enabled="Enable or disable moderation alerts",
            alert_channel="Alert channel (set only when enabling alerts)",
            report_to_owner_enabled="Enable sending detected scam reports to owner webhook",
            dm_user_warning_enabled="Enable DM warning to users caught posting scam images",
        )
        async def antiscam_settings(
            interaction: discord.Interaction,
            auto_delete: bool | None = None,
            timeout_enabled: bool | None = None,
            timeout_minutes: app_commands.Range[int, 1, 40320] | None = None,
            alert_enabled: bool | None = None,
            alert_channel: discord.TextChannel | None = None,
            report_to_owner_enabled: bool | None = None,
            dm_user_warning_enabled: bool | None = None,
        ) -> None:
            if interaction.guild is None:
                await interaction.response.send_message("This command must be used in a server.", ephemeral=True)
                return

            member = interaction.user
            if not isinstance(member, discord.Member) or not member.guild_permissions.administrator:
                await interaction.response.send_message("Only administrators can run this command.", ephemeral=True)
                return

            current = await self._config_store.get(interaction.guild.id)
            if not current.is_guild_setup:
                await interaction.response.send_message(
                    "Bot is not set up yet. Run `/setupbot` first.",
                    ephemeral=True,
                )
                return

            changes: dict[str, object] = {}

            if auto_delete is not None:
                changes["auto_delete"] = auto_delete
            if timeout_enabled is not None:
                changes["timeout_enabled"] = timeout_enabled
            if timeout_minutes is not None:
                changes["timeout_minutes"] = int(timeout_minutes)
            if alert_enabled is not None:
                changes["alert_enabled"] = alert_enabled
                if not alert_enabled:
                    changes["alert_channel_id"] = None
            if alert_channel is not None:
                changes["alert_channel_id"] = alert_channel.id
                if alert_enabled is None:
                    changes["alert_enabled"] = True
            if report_to_owner_enabled is not None:
                changes["report_to_owner_enabled"] = report_to_owner_enabled
            if dm_user_warning_enabled is not None:
                changes["dm_user_warning_enabled"] = dm_user_warning_enabled

            if not changes:
                await interaction.response.send_message(self._format_config_message(current, created=False), ephemeral=True)
                return

            updated = await self._config_store.update(interaction.guild.id, **changes)
            await interaction.response.send_message(self._format_config_message(updated, created=False), ephemeral=True)

        return antiscam_settings

    def _format_config_message(self, config, *, created: bool) -> str:
        title = "Setup complete." if created else "Settings updated."
        alert_channel = f"<#{config.alert_channel_id}>" if config.alert_channel_id else "not set"
        return (
            f"{title}\n"
            f"- auto_delete: `{config.auto_delete}`\n"
            f"- timeout_enabled: `{config.timeout_enabled}`\n"
            f"- timeout_minutes: `{config.timeout_minutes}`\n"
            f"- alert_enabled: `{config.alert_enabled}`\n"
            f"- alert_channel: {alert_channel}\n"
            f"- report_to_owner_enabled: `{config.report_to_owner_enabled}`\n"
            f"- dm_user_warning_enabled: `{config.dm_user_warning_enabled}`"
        )
