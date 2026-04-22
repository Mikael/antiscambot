# Discord Anti-Scam Bot

Fast multi-guild Discord bot that scans image attachments with OCR and deletes likely bitcoin/crypto scam screenshots.

## Features
- Multi-guild support with persistent per-guild setup state
- Mandatory server setup flow (`/setupbot`) before moderation begins
- On guild join: setup state defaults to false, owner gets a DM explaining setup
- Admin-only setup and config commands (`/setupbot`, `/antiscam-settings`)
- Per-guild actions: auto-delete, optional timeout duration, optional alert channel
- Concurrent image scanning using a thread pool for OCR-heavy workloads
- Real-time MongoDB-backed scam rules with periodic hot refresh
- Clean handler/event/service architecture for easy extension

## Install
1. Install Python 3.11+
2. Install Tesseract OCR and ensure it is in PATH
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Copy `config.example.ini` to `config.ini` and edit values:
   ```bash
   copy config.example.ini config.ini
   ```

## Seed Rules (first run)
```bash
python seed_rules.py
```

## Commands
- `/setupbot` - initial setup with moderation actions and alert channel options (admin only)
- `/antiscam-settings` - update server moderation behavior after setup (admin only)

## Run
```bash
python main.py
```

## Required Bot Privileges
- Manage Messages (to delete scam messages)
- Read Message History / View Channels
- Message Content Intent enabled in Discord Developer Portal

## Project Layout
- `main.py` - app entrypoint and event wiring
- `bot/handlers/` - moderation and slash command handlers
- `bot/events/` - Discord event handlers
- `bot/services/` - OCR and scam analysis logic
- `bot/storage/` - MongoDB persistence for guild state and scam rule cache
- `bot/models/` - data models
