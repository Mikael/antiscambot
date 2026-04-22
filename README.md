# Discord Anti-Scam Bot

AntiScamBot is a multi-guild Discord moderation bot focused on detecting and handling bitcoin/crypto scam images.

## What the bot does
- Scans image attachments with OCR (Tesseract) to extract text.
- Matches extracted text against scam detection rules stored in MongoDB.
- Uses a score threshold to decide whether an image is likely a scam.
- Supports real-time rule updates from MongoDB (hot refresh) without code edits.
- Does **not** moderate images in a guild until that guild is set up.

## Guild setup flow
- When the bot joins a guild, it creates a guild config with `is_guild_setup = false`.
- The guild owner is DM'd and told to run `/setupbot`.
- Only admins can run setup/config commands.

## Per-guild moderation behavior
Admins control behavior per server:
- Auto-delete scam messages (`auto_delete`)
- Timeout offending users (`timeout_enabled`, `timeout_minutes`)
- Optional alert channel for moderation events (`alert_enabled`, `alert_channel`)

Commands:
- `/setupbot` - Initial setup and moderation options (admin only)
- `/antiscam-settings` - Update settings after setup (admin only)

## Architecture
- `main.py` - Bot startup, dependency wiring, command registration
- `bot/handlers/` - Slash command + moderation handlers
- `bot/events/` - Discord event handlers (`on_guild_join`, `on_message`)
- `bot/services/` - OCR scanning logic
- `bot/storage/` - MongoDB-backed guild config and scam rule repository
- `bot/models/` - Typed data models
- `seed_rules.py` - Seeds default scam rules into MongoDB

## Configuration
1. Copy template config:
   ```bash
   copy config.example.ini config.ini
   ```
2. Fill in `config.ini` values:
   - `discord.token`
   - `mongodb.uri`
   - `mongodb.database` (default in project: `antiscambot`)
   - optional collection names / OCR settings

Sensitive values are loaded from `config.ini` (ignored by git), not hardcoded in source.

## Install and run
1. Install Python 3.11+
2. Install Tesseract OCR and add it to PATH
3. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
4. Seed default scam rules (first run):
   ```bash
   python seed_rules.py
   ```
5. Start bot:
   ```bash
   python main.py
   ```

## Required Discord permissions
- View Channels
- Read Message History
- Manage Messages (for auto-delete)
- Moderate Members (for timeout)
- Message Content intent enabled in the Developer Portal
