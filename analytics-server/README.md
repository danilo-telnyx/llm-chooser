# LLM Chooser Analytics Server

Self-hosted, privacy-conscious analytics for the LLM Chooser site with Telegram 2FA admin dashboard.

## Quick Start

```bash
cd analytics-server
npm install
npm run setup     # Generates admin password — SAVE IT!
node server.js    # Starts on port 3847
```

## Configuration

Set these environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | For 2FA | Telegram Bot API token (get from @BotFather) |
| `PORT` | No | Server port (default: 3847) |
| `JWT_SECRET` | No | JWT signing key (auto-generated if not set) |

### Example:
```bash
TELEGRAM_BOT_TOKEN=123456:ABC-DEF node server.js
```

## Connect to GitHub Pages

In `index.html`, the analytics beacon points to `ANALYTICS_URL`. Replace it with your server's public URL:

```html
<script>
  const ANALYTICS_URL = 'https://your-server.com'; // ← Change this
</script>
```

For local dev: `http://localhost:3847`

## Telegram 2FA Setup

1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Send `/start` to your bot (so it can message you)
3. Set `TELEGRAM_BOT_TOKEN` env var
4. The bot sends 2FA codes to chat ID `1023351889` (Danilo)

## Run with PM2

```bash
npm install -g pm2
TELEGRAM_BOT_TOKEN=xxx pm2 start server.js --name llm-analytics
pm2 save
pm2 startup
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/track` | POST | Receive pageview events |
| `/admin` | GET | Admin dashboard |
| `/admin/auth` | POST | Login (password) |
| `/admin/verify-2fa` | POST | 2FA verification |
| `/api/stats` | GET | Stats API (auth required) |
| `/health` | GET | Health check |
