from __future__ import annotations

import discord
from discord import app_commands


INVITE_URL = (
    "https://discord.com/oauth2/authorize"
    "?client_id=1496505335597371504"
    "&permissions=1100048574531"
    "&integration_type=0"
    "&scope=bot"
)


class InfoCommandHandler:
    def build_invite(self) -> app_commands.Command:
        @app_commands.command(name="invite", description="Get a link to invite AntiScamBot to your server")
        async def invite(interaction: discord.Interaction) -> None:
            embed = discord.Embed(
                title="Invite AntiScamBot",
                description=f"Click the link below to add AntiScamBot to your server.\n\n[Invite AntiScamBot]({INVITE_URL})",
                color=discord.Color.blurple(),
            )
            embed.set_footer(text="Thanks for helping fight scams on Discord.")
            await interaction.response.send_message(embed=embed, ephemeral=True)

        return invite

    def build_about(self) -> app_commands.Command:
        @app_commands.command(name="about", description="Learn about AntiScamBot")
        async def about(interaction: discord.Interaction) -> None:
            description = (
                "**AntiScamBot** is an automated moderation bot that protects Discord servers "
                "from crypto scam image spam. It uses OCR to read text inside images, matches "
                "them against a live-updating rule set of known scam phrases, domains, and "
                "wallet patterns, and can automatically delete offending messages, time out "
                "offenders with progressive discipline, alert moderators, and DM users a "
                "security warning.\n\n"
                "**Key features**\n"
                "- OCR-powered scam image detection\n"
                "- Live-updating scam rule set\n"
                "- Auto-delete, progressive timeouts, moderator alerts\n"
                "- Per-guild configuration via `/setupbot` and `/antiscam-settings`\n\n"
                f"[Invite AntiScamBot]({INVITE_URL})"
            )
            embed = discord.Embed(
                title="About AntiScamBot",
                description=description,
                color=discord.Color.blurple(),
            )
            embed.add_field(
                name="Get Started",
                value="Run `/setupbot` (admin only) after inviting to configure moderation.",
                inline=False,
            )
            embed.set_footer(text="AntiScamBot - keeping your community safe.")
            await interaction.response.send_message(embed=embed, ephemeral=True)

        return about
