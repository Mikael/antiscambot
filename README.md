# Discord Anti-Scam Bot

AntiScamBot is a multi-guild Discord moderation bot focused on detecting and handling bitcoin/crypto scam images.

## What the bot does
- Scans image attachments with OCR (Tesseract) to extract text.
- Matches extracted text against scam detection rules stored in MongoDB.
- Uses a score threshold to decide whether an image is likely a scam.
- Supports real-time rule updates from MongoDB (hot refresh) without code edits.
- Uses auto-sharding (`AutoShardedBot`) to scale across larger guild counts.
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
- Optional owner report submission via webhook (`report_to_owner_enabled`)
- Optional DM safety warning to users caught posting scam images (`dm_user_warning_enabled`)

Commands:
- `/setupbot` - Initial setup and moderation options (admin only)
- `/antiscam-settings` - Update settings after setup (admin only)
- Both commands now include an option to DM users with account safety advice after detection

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
- `integrations.owner_report_webhook_url` for owner report submissions

Sensitive values are loaded from `config.ini` (ignored by git), not hardcoded in source.

## Install and run
1. Install Python 3.11+
2. Install Tesseract OCR:
   - Windows (winget): `winget install UB-Mannheim.TesseractOCR`
   - Ubuntu/Debian: `sudo apt update && sudo apt install -y tesseract-ocr`
   - Ensure `tesseract --version` works in your shell
3. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```
4. Optional override if auto-detect fails:
   - Set `ocr.tesseract_cmd` in `config.ini` (supports env var expansion)
   - Or set `TESSERACT_CMD` env var
5. Seed default scam rules (first run):
   ```bash
   python seed_rules.py
   ```
6. (Optional) mine conservative candidate rules from `pics/`:
   ```bash
   python mine_rules_from_pics.py
   python mine_rules_from_pics.py --apply
   ```
   The miner is intentionally conservative and requires repeated sightings before inserting candidates.
7. Start bot:
   ```bash
   python main.py
   ```

## Required Discord permissions
- View Channels
- Read Message History
- Manage Messages (for auto-delete)
- Moderate Members (for timeout)
- Message Content intent enabled in the Developer Portal
