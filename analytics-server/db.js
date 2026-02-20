const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'analytics.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS pageviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    page_url TEXT,
    referrer TEXT,
    user_agent TEXT,
    screen_width INTEGER,
    screen_height INTEGER,
    language TEXT,
    country TEXT,
    ip_hash TEXT,
    device_type TEXT,
    browser TEXT
  );

  CREATE TABLE IF NOT EXISTS admin_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_pageviews_timestamp ON pageviews(timestamp);
  CREATE INDEX IF NOT EXISTS idx_pageviews_ip_hash ON pageviews(ip_hash);
`);

function parseUserAgent(ua) {
  if (!ua) return { browser: 'Unknown', device: 'unknown' };
  let browser = 'Other';
  if (/Firefox/i.test(ua)) browser = 'Firefox';
  else if (/Edg/i.test(ua)) browser = 'Edge';
  else if (/Chrome/i.test(ua)) browser = 'Chrome';
  else if (/Safari/i.test(ua)) browser = 'Safari';
  else if (/Opera|OPR/i.test(ua)) browser = 'Opera';

  let device = 'desktop';
  if (/Mobile|Android.*Mobile|iPhone|iPod/i.test(ua)) device = 'mobile';
  else if (/iPad|Android(?!.*Mobile)|Tablet/i.test(ua)) device = 'tablet';

  return { browser, device };
}

function hashIP(ip) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(ip + 'llm-chooser-salt').digest('hex').slice(0, 16);
}

function trackPageview(data, ip) {
  const { browser, device } = parseUserAgent(data.user_agent);
  const stmt = db.prepare(`
    INSERT INTO pageviews (page_url, referrer, user_agent, screen_width, screen_height, language, country, ip_hash, device_type, browser)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    data.page_url || '',
    data.referrer || '',
    data.user_agent || '',
    data.screen_width || 0,
    data.screen_height || 0,
    data.language || '',
    data.country || '',
    hashIP(ip),
    device,
    browser
  );
}

function getStats(period) {
  const periods = {
    today: "datetime('now', 'start of day')",
    week: "datetime('now', '-7 days')",
    month: "datetime('now', '-30 days')",
    all: "'1970-01-01'"
  };
  const since = periods[period] || periods.all;

  const total = db.prepare(`SELECT COUNT(*) as count FROM pageviews WHERE timestamp >= ${since}`).get();
  const unique = db.prepare(`SELECT COUNT(DISTINCT ip_hash) as count FROM pageviews WHERE timestamp >= ${since}`).get();
  const referrers = db.prepare(`SELECT referrer, COUNT(*) as count FROM pageviews WHERE timestamp >= ${since} AND referrer != '' GROUP BY referrer ORDER BY count DESC LIMIT 10`).all();
  const browsers = db.prepare(`SELECT browser, COUNT(*) as count FROM pageviews WHERE timestamp >= ${since} GROUP BY browser ORDER BY count DESC`).all();
  const devices = db.prepare(`SELECT device_type, COUNT(*) as count FROM pageviews WHERE timestamp >= ${since} GROUP BY device_type ORDER BY count DESC`).all();
  const countries = db.prepare(`SELECT country, COUNT(*) as count FROM pageviews WHERE timestamp >= ${since} AND country != '' GROUP BY country ORDER BY count DESC LIMIT 10`).all();
  const recent = db.prepare(`SELECT timestamp, browser, referrer, country, device_type, language FROM pageviews ORDER BY id DESC LIMIT 50`).all();

  // Pageviews over time (last 30 days, grouped by day)
  const daily = db.prepare(`
    SELECT date(timestamp) as day, COUNT(*) as count
    FROM pageviews
    WHERE timestamp >= datetime('now', '-30 days')
    GROUP BY date(timestamp)
    ORDER BY day
  `).all();

  return { total: total.count, unique: unique.count, referrers, browsers, devices, countries, recent, daily };
}

function getConfig(key) {
  const row = db.prepare('SELECT value FROM admin_config WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setConfig(key, value) {
  db.prepare('INSERT OR REPLACE INTO admin_config (key, value) VALUES (?, ?)').run(key, value);
}

module.exports = { db, trackPageview, getStats, getConfig, setConfig };
