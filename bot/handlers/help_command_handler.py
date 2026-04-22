from __future__ import annotations

import discord
from discord import app_commands


class HelpCommandHandler:
    def build(self) -> app_commands.Command:
        @app_commands.command(name="antiscam-help", description="Show admin help for anti-scam bot commands")
        @app_commands.default_permissions(administrator=True)
        async def antiscam_help(interaction: discord.Interaction) -> None:
            if interaction.guild is None:
                await interaction.response.send_message("This command must be used in a server.", ephemeral=True)
                return

            member = interaction.user
            if not isinstance(member, discord.Member) or not member.guild_permissions.administrator:
                await interaction.response.send_message("Only administrators can run this command.", ephemeral=True)
                return

            commands_list = sorted(interaction.client.tree.get_commands(), key=lambda c: c.name)

            embed = discord.Embed(
                title="AntiScamBot Admin Help",
                description="Live command reference generated from currently registered slash commands.",
                color=discord.Color.blurple(),
            )

            for cmd in commands_list:
                if not isinstance(cmd, app_commands.Command):
                    continue

                options = []
                for param in cmd.parameters:
                    required = "required" if param.required else "optional"
                    options.append(f"`{param.display_name}` ({required})")

                details = cmd.description or "No description"
                if options:
                    details += "\nOptions: " + ", ".join(options)

                embed.add_field(name=f"/{cmd.name}", value=details[:1024], inline=False)

            await interaction.response.send_message(embed=embed, ephemeral=True)

        return antiscam_help
