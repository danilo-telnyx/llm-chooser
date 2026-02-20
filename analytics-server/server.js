require('dotenv/config').catch?.(() => {});
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const { trackPageview, getStats, getConfig, setConfig } = require('./db');
const { sendTelegram2FA, verify2FA } = require('./telegram-2fa');

const app = express();
const PORT = process.env.PORT || 3847;
const JWT_SECRET = process.env.JWT_SECRET || require('crypto').randomBytes(32).toString('hex');
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const GITHUB_PAGES_ORIGIN = 'https://danilo-telnyx.github.io';

// CORS — allow GitHub Pages + localhost for dev
app.use(cors({
  origin: [GITHUB_PAGES_ORIGIN, 'http://localhost:3000', 'http://localhost:8080', `http://localhost:${PORT}`],
  credentials: true
}));

app.use(express.json({ limit: '1kb' }));

// Rate limiting
const trackLimiter = rateLimit({ windowMs: 60000, max: 60, standardHeaders: true });
const authLimiter = rateLimit({ windowMs: 15 * 60000, max: 10, standardHeaders: true });

// ── Analytics beacon endpoint ──
app.post('/api/track', trackLimiter, async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '';
    const data = {
      page_url: String(req.body.url || '').slice(0, 500),
      referrer: String(req.body.referrer || '').slice(0, 500),
      user_agent: String(req.headers['user-agent'] || '').slice(0, 500),
      screen_width: parseInt(req.body.sw) || 0,
      screen_height: parseInt(req.body.sh) || 0,
      language: String(req.body.lang || req.headers['accept-language'] || '').slice(0, 50),
      country: ''
    };

    // Try free IP geolocation (best-effort, non-blocking)
    try {
      if (ip && ip !== '127.0.0.1' && ip !== '::1') {
        const fetch = (await import('node-fetch')).default;
        const geo = await Promise.race([
          fetch(`http://ip-api.com/json/${ip}?fields=countryCode`).then(r => r.json()),
          new Promise((_, rej) => setTimeout(rej, 2000))
        ]);
        if (geo?.countryCode) data.country = geo.countryCode;
      }
    } catch {}

    trackPageview(data, ip);
    res.status(204).end();
  } catch (e) {
    console.error('Track error:', e.message);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ── Auth middleware ──
function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Admin login (step 1: password) ──
app.post('/admin/auth', authLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    const hash = getConfig('admin_password_hash');
    if (!hash) return res.status(500).json({ error: 'Admin not configured. Run: npm run setup' });

    const valid = await bcrypt.compare(password, hash);
    if (!valid) return res.status(401).json({ error: 'Invalid password' });

    if (!TELEGRAM_BOT_TOKEN) {
      // No 2FA configured — issue token directly (warn in logs)
      console.warn('⚠️  No TELEGRAM_BOT_TOKEN set — 2FA disabled!');
      const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
      return res.json({ token, twoFactor: false });
    }

    await sendTelegram2FA(TELEGRAM_BOT_TOKEN);
    res.json({ twoFactor: true, message: '2FA code sent to Telegram' });
  } catch (e) {
    console.error('Auth error:', e.message);
    res.status(500).json({ error: 'Auth failed' });
  }
});

// ── Admin 2FA verify (step 2) ──
app.post('/admin/verify-2fa', authLimiter, (req, res) => {
  const { code } = req.body;
  if (!verify2FA(String(code))) return res.status(401).json({ error: 'Invalid or expired code' });

  const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// ── Admin dashboard ──
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// ── Admin API ──
app.get('/api/stats', requireAuth, (req, res) => {
  const period = req.query.period || 'all';
  res.json(getStats(period));
});

// ── Health ──
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`\n🔍 LLM Chooser Analytics Server`);
  console.log(`   Dashboard: http://localhost:${PORT}/admin`);
  console.log(`   Tracking:  POST http://localhost:${PORT}/api/track`);
  console.log(`   2FA:       ${TELEGRAM_BOT_TOKEN ? '✅ Enabled' : '⚠️  Disabled (set TELEGRAM_BOT_TOKEN)'}\n`);
});
