# LLM Chooser — Serverless Analytics

Privacy-friendly, self-hosted analytics for LLM Chooser using **Cloudflare Workers** (free tier: 100k requests/day) and **D1** (free tier: 5GB storage).

Features:
- Pageview tracking with country/city detection (free via Cloudflare headers)
- IP hashing for unique visitor counting (no raw IPs stored)
- Beautiful dark-themed admin dashboard with Chart.js
- 2FA login via Telegram
- Stats: views over time, browsers, devices, countries, languages, referrers, screen resolutions

## Deploy Analytics Backend (Free — 5 minutes)

1. **Create Cloudflare account** (free): https://dash.cloudflare.com

2. **Install dependencies:**
   ```bash
   cd analytics
   npm install
   ```

3. **Login to Cloudflare:**
   ```bash
   npx wrangler login
   ```

4. **Create D1 database:**
   ```bash
   npx wrangler d1 create llm-analytics
   ```

5. **Update `wrangler.toml`** with the `database_id` from step 4

6. **Apply database schema:**
   ```bash
   npx wrangler d1 execute llm-analytics --file=schema.sql
   ```

7. **Set secrets:**
   ```bash
   npx wrangler secret put ADMIN_PASSWORD       # choose a strong password
   npx wrangler secret put TELEGRAM_BOT_TOKEN   # your Telegram bot token
   npx wrangler secret put JWT_SECRET           # any random string
   npx wrangler secret put TELEGRAM_CHAT_ID     # your Telegram chat ID
   ```

8. **Deploy:**
   ```bash
   npx wrangler deploy
   ```

9. **Note your Worker URL** (e.g. `https://llm-chooser-analytics.YOUR-SUBDOMAIN.workers.dev`)

10. **Update `ANALYTICS_URL` in `index.html`** — replace `CHANGE-ME` with your subdomain

## Admin Dashboard

Visit `https://llm-chooser-analytics.YOUR-SUBDOMAIN.workers.dev/admin`

1. Enter your admin password
2. Receive 2FA code on Telegram
3. Enter code → access dashboard with charts, metrics, and recent visits
