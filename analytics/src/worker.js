// LLM Chooser Analytics — Cloudflare Worker + D1
// Endpoints: POST /track, GET /admin, POST /admin/login, POST /admin/verify, GET /api/stats

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    try {
      if (path === '/track' && request.method === 'POST') return await handleTrack(request, env);
      if (path === '/admin' && request.method === 'GET') return serveAdminDashboard();
      if (path === '/admin/login' && request.method === 'POST') return await handleLogin(request, env);
      if (path === '/admin/verify' && request.method === 'POST') return await handleVerify(request, env);
      if (path === '/api/stats' && request.method === 'GET') return await handleStats(request, env, url);
      if (path === '/admin/change-password' && request.method === 'POST') return await handleChangePassword(request, env);
      return new Response('Not Found', { status: 404 });
    } catch (e) {
      return jsonResponse({ error: e.message }, 500);
    }
  }
};

// ── Helpers ──

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

async function hashIP(ip) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(ip + '_llm_chooser_salt'));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

async function createJWT(env) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({ exp: Date.now() + 86400000, iat: Date.now() }));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${payload}`)))));
  return `${header}.${payload}.${sig}`;
}

async function verifyJWT(token, env) {
  try {
    const [header, payload, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const valid = await crypto.subtle.verify('HMAC', key, Uint8Array.from(atob(sig), c => c.charCodeAt(0)), new TextEncoder().encode(`${header}.${payload}`));
    if (!valid) return false;
    const data = JSON.parse(atob(payload));
    return data.exp > Date.now();
  } catch { return false; }
}

// ── Track ──

async function handleTrack(request, env) {
  const data = await request.json();
  const cf = request.cf || {};
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'unknown';
  const ipHash = await hashIP(ip);

  await env.DB.prepare(
    `INSERT INTO pageviews (timestamp, path, referrer, user_agent, language, screen_width, screen_height, country, city, ip_hash, session_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    new Date().toISOString(),
    data.path || '/',
    data.referrer || null,
    data.user_agent || null,
    data.language || null,
    data.screen_width || null,
    data.screen_height || null,
    cf.country || null,
    cf.city || null,
    ipHash,
    data.session_id || null
  ).run();

  return jsonResponse({ ok: true });
}

// ── Auth ──

async function getPassword(env) {
  try {
    const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'admin_password'").first();
    if (row && row.value) return row.value;
  } catch {}
  return env.ADMIN_PASSWORD;
}

async function handleLogin(request, env) {
  const { password } = await request.json();
  const currentPw = await getPassword(env);
  if (!password || password !== currentPw) {
    return jsonResponse({ error: 'Invalid password' }, 401);
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  await env.DB.prepare('INSERT INTO auth_codes (code, created_at) VALUES (?, ?)').bind(code, new Date().toISOString()).run();

  // Send via Telegram
  const chatId = env.TELEGRAM_CHAT_ID;
  await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ chat_id: chatId, text: `🔐 LLM Chooser Analytics\n\nYour 2FA code: ${code}\n\nExpires in 5 minutes.` }),
  });

  return jsonResponse({ ok: true, message: '2FA code sent to Telegram' });
}

async function handleVerify(request, env) {
  const { code } = await request.json();
  const fiveMinAgo = new Date(Date.now() - 300000).toISOString();
  const row = await env.DB.prepare(
    'SELECT id FROM auth_codes WHERE code = ? AND used = 0 AND created_at > ? ORDER BY id DESC LIMIT 1'
  ).bind(code, fiveMinAgo).first();

  if (!row) return jsonResponse({ error: 'Invalid or expired code' }, 401);

  await env.DB.prepare('UPDATE auth_codes SET used = 1 WHERE id = ?').bind(row.id).run();
  const token = await createJWT(env);
  return jsonResponse({ ok: true, token });
}

// ── Change Password ──

async function handleChangePassword(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !await verifyJWT(auth.replace('Bearer ', ''), env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }
  const { currentPassword, newPassword } = await request.json();
  const currentPw = await getPassword(env);
  if (!currentPassword || currentPassword !== currentPw) {
    return jsonResponse({ error: 'Current password is incorrect' }, 401);
  }
  if (!newPassword || newPassword.length < 8) {
    return jsonResponse({ error: 'New password must be at least 8 characters' }, 400);
  }
  // Note: Cloudflare Worker secrets can't be changed at runtime via the API from within the worker itself.
  // We store the new password in D1 as an override. Check D1 first, then fall back to env.
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`
  ).run();
  await env.DB.prepare(
    `INSERT OR REPLACE INTO settings (key, value) VALUES ('admin_password', ?)`
  ).bind(newPassword).run();
  return jsonResponse({ ok: true, message: 'Password changed successfully' });
}

// ── Stats ──

async function handleStats(request, env, url) {
  const auth = request.headers.get('Authorization');
  if (!auth || !await verifyJWT(auth.replace('Bearer ', ''), env)) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const period = url.searchParams.get('period') || 'all';
  let dateFilter = '';
  const now = new Date();
  if (period === 'today') dateFilter = `AND timestamp >= '${now.toISOString().split('T')[0]}'`;
  else if (period === 'week') { const d = new Date(now - 7 * 86400000); dateFilter = `AND timestamp >= '${d.toISOString().split('T')[0]}'`; }
  else if (period === 'month') { const d = new Date(now - 30 * 86400000); dateFilter = `AND timestamp >= '${d.toISOString().split('T')[0]}'`; }

  const [totalR, uniqueR, dailyR, referrerR, countryR, langR, screenR, recentR] = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) as total FROM pageviews WHERE 1=1 ${dateFilter}`).first(),
    env.DB.prepare(`SELECT COUNT(DISTINCT ip_hash) as unique_visitors FROM pageviews WHERE 1=1 ${dateFilter}`).first(),
    env.DB.prepare(`SELECT substr(timestamp, 1, 10) as day, COUNT(*) as views FROM pageviews WHERE 1=1 ${dateFilter} GROUP BY day ORDER BY day`).all(),
    env.DB.prepare(`SELECT referrer, COUNT(*) as count FROM pageviews WHERE referrer IS NOT NULL AND referrer != '' ${dateFilter} GROUP BY referrer ORDER BY count DESC LIMIT 10`).all(),
    env.DB.prepare(`SELECT country, COUNT(*) as count FROM pageviews WHERE country IS NOT NULL ${dateFilter} GROUP BY country ORDER BY count DESC LIMIT 20`).all(),
    env.DB.prepare(`SELECT language, COUNT(*) as count FROM pageviews WHERE language IS NOT NULL ${dateFilter} GROUP BY language ORDER BY count DESC LIMIT 10`).all(),
    env.DB.prepare(`SELECT screen_width || 'x' || screen_height as resolution, COUNT(*) as count FROM pageviews WHERE screen_width IS NOT NULL ${dateFilter} GROUP BY resolution ORDER BY count DESC LIMIT 10`).all(),
    env.DB.prepare(`SELECT timestamp, path, referrer, user_agent, country, language, screen_width, screen_height FROM pageviews ORDER BY id DESC LIMIT 50`).all(),
  ]);

  // Parse browsers and devices from user_agent in recent visits + all matching period
  const uaRows = (await env.DB.prepare(`SELECT user_agent FROM pageviews WHERE user_agent IS NOT NULL ${dateFilter}`).all()).results;
  const browsers = {}, devices = { Mobile: 0, Desktop: 0, Tablet: 0 };
  for (const { user_agent: ua } of uaRows) {
    let b = 'Other';
    if (/Edg\//i.test(ua)) b = 'Edge';
    else if (/Chrome/i.test(ua)) b = 'Chrome';
    else if (/Firefox/i.test(ua)) b = 'Firefox';
    else if (/Safari/i.test(ua)) b = 'Safari';
    else if (/Opera|OPR/i.test(ua)) b = 'Opera';
    browsers[b] = (browsers[b] || 0) + 1;

    if (/Tablet|iPad/i.test(ua)) devices.Tablet++;
    else if (/Mobile|Android|iPhone/i.test(ua)) devices.Mobile++;
    else devices.Desktop++;
  }

  // Today's views
  const todayStr = now.toISOString().split('T')[0];
  const todayR = await env.DB.prepare(`SELECT COUNT(*) as count FROM pageviews WHERE timestamp >= '${todayStr}'`).first();

  return jsonResponse({
    total: totalR.total,
    unique_visitors: uniqueR.unique_visitors,
    today: todayR.count,
    daily: dailyR.results,
    referrers: referrerR.results,
    countries: countryR.results,
    languages: langR.results,
    screens: screenR.results,
    browsers: Object.entries(browsers).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    devices: Object.entries(devices).map(([name, count]) => ({ name, count })),
    recent: recentR.results,
  });
}

// ── Admin Dashboard ──

function serveAdminDashboard() {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Chooser — Analytics Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
:root{--bg:#0d1117;--bg2:#161b22;--bg3:#21262d;--border:#30363d;--text:#e6edf3;--text2:#8b949e;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--purple:#bc8cff;--orange:#f0883e}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
a{color:var(--accent);text-decoration:none}
.container{max-width:1200px;margin:0 auto;padding:20px}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:20px 0;text-align:center;position:relative}
header h1{font-size:1.6em}
header p{color:var(--text2);font-size:0.9em;margin-top:4px}

/* Login */
#login-view{display:flex;justify-content:center;align-items:center;min-height:80vh}
.login-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:40px;width:100%;max-width:400px;text-align:center}
.login-card h2{margin-bottom:24px;font-size:1.4em}
.login-card input{width:100%;padding:12px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:1em;margin-bottom:12px;outline:none}
.login-card input:focus{border-color:var(--accent)}
.login-card button{width:100%;padding:12px;background:var(--accent);color:#fff;border:none;border-radius:8px;font-size:1em;cursor:pointer;font-weight:600}
.login-card button:hover{opacity:0.9}
.login-card .error{color:var(--red);font-size:0.85em;margin-top:8px}
.login-card .info{color:var(--green);font-size:0.85em;margin-top:8px}
#step2{display:none}

/* Dashboard */
#dashboard-view{display:none}
.period-bar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.period-bar button{background:var(--bg3);color:var(--text2);border:1px solid var(--border);padding:6px 16px;border-radius:6px;cursor:pointer;font-size:0.85em}
.period-bar button:hover,.period-bar button.active{color:var(--text);border-color:var(--accent);background:rgba(88,166,255,0.1)}

.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.metric-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px;text-align:center}
.metric-card .value{font-size:2em;font-weight:700;color:var(--accent)}
.metric-card .label{color:var(--text2);font-size:0.85em;margin-top:4px}

.charts{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px}
.chart-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px}
.chart-card h3{font-size:1em;color:var(--text2);margin-bottom:12px}
.chart-card.wide{grid-column:1/-1}

.recent-table{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:20px;overflow-x:auto}
.recent-table h3{margin-bottom:12px;color:var(--text2)}
.recent-table table{width:100%;border-collapse:collapse;font-size:0.8em}
.recent-table th,.recent-table td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
.recent-table th{color:var(--text2);font-weight:600}
.recent-table tr:hover{background:var(--bg3)}

@media(max-width:768px){.charts{grid-template-columns:1fr}.metrics{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<header>
  <h1>🤖 LLM Chooser Analytics</h1>
  <p>Serverless analytics powered by Cloudflare Workers + D1</p>
  <div id="header-actions" style="display:none;position:absolute;right:20px;top:16px">
    <button onclick="showProfile()" style="background:var(--bg3);color:var(--text);border:1px solid var(--border);padding:6px 14px;border-radius:6px;cursor:pointer;margin-right:8px;font-size:0.85em">⚙️ Profile</button>
    <button onclick="doLogout()" style="background:var(--red);color:#fff;border:none;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:0.85em">🚪 Logout</button>
  </div>
</header>

<!-- Profile Modal -->
<div id="profile-modal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:1000;justify-content:center;align-items:center">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:32px;width:100%;max-width:420px">
    <h2 style="margin-bottom:20px;font-size:1.2em">⚙️ Profile Settings</h2>
    <h3 style="font-size:0.95em;color:var(--text2);margin-bottom:12px">Change Password</h3>
    <input type="password" id="current-pw" placeholder="Current password" style="width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:0.95em;margin-bottom:10px;outline:none">
    <input type="password" id="new-pw" placeholder="New password (min 8 chars)" style="width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:0.95em;margin-bottom:10px;outline:none">
    <input type="password" id="confirm-pw" placeholder="Confirm new password" style="width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:0.95em;margin-bottom:14px;outline:none">
    <div style="display:flex;gap:10px">
      <button onclick="doChangePassword()" style="flex:1;padding:10px;background:var(--accent);color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600">Save Password</button>
      <button onclick="hideProfile()" style="flex:1;padding:10px;background:var(--bg3);color:var(--text);border:1px solid var(--border);border-radius:8px;cursor:pointer">Cancel</button>
    </div>
    <div id="pw-msg" style="font-size:0.85em;margin-top:10px;text-align:center"></div>
  </div>
</div>

<div id="login-view">
  <div class="login-card">
    <h2>🔐 Admin Login</h2>
    <div id="step1">
      <input type="password" id="password" placeholder="Enter admin password" autocomplete="off">
      <button onclick="doLogin()">Send 2FA Code</button>
      <div class="error" id="login-error"></div>
    </div>
    <div id="step2">
      <div class="info">✅ 2FA code sent to Telegram!</div>
      <input type="text" id="code" placeholder="Enter 6-digit code" maxlength="6" autocomplete="off" style="margin-top:16px">
      <button onclick="doVerify()">Verify & Login</button>
      <div class="error" id="verify-error"></div>
    </div>
  </div>
</div>

<div id="dashboard-view">
  <div class="container">
    <div class="period-bar">
      <button class="active" onclick="loadStats('all',this)">All Time</button>
      <button onclick="loadStats('month',this)">This Month</button>
      <button onclick="loadStats('week',this)">This Week</button>
      <button onclick="loadStats('today',this)">Today</button>
    </div>
    <div class="metrics">
      <div class="metric-card"><div class="value" id="m-total">—</div><div class="label">Total Pageviews</div></div>
      <div class="metric-card"><div class="value" id="m-unique">—</div><div class="label">Unique Visitors</div></div>
      <div class="metric-card"><div class="value" id="m-today">—</div><div class="label">Today's Views</div></div>
      <div class="metric-card"><div class="value" id="m-referrer">—</div><div class="label">Top Referrer</div></div>
    </div>
    <div class="charts">
      <div class="chart-card wide"><h3>📈 Views Over Time</h3><canvas id="chart-daily"></canvas></div>
      <div class="chart-card"><h3>🌐 Browsers</h3><canvas id="chart-browsers"></canvas></div>
      <div class="chart-card"><h3>📱 Devices</h3><canvas id="chart-devices"></canvas></div>
      <div class="chart-card"><h3>🌍 Countries</h3><canvas id="chart-countries"></canvas></div>
      <div class="chart-card"><h3>🗣️ Languages</h3><canvas id="chart-languages"></canvas></div>
    </div>
    <div class="recent-table">
      <h3>🕐 Recent Visits (last 50)</h3>
      <table><thead><tr><th>Time</th><th>Country</th><th>Path</th><th>Referrer</th><th>Browser</th><th>Screen</th><th>Language</th></tr></thead><tbody id="recent-body"></tbody></table>
    </div>
  </div>
</div>

<script>
const BASE = location.origin;
let TOKEN = '';
const COLORS = ['#58a6ff','#3fb950','#f0883e','#bc8cff','#f85149','#d29922','#79c0ff','#56d364','#ffa657','#d2a8ff'];
let charts = {};

function parseUA(ua) {
  if (!ua) return 'Unknown';
  if (/Edg\\//i.test(ua)) return 'Edge';
  if (/Chrome/i.test(ua)) return 'Chrome';
  if (/Firefox/i.test(ua)) return 'Firefox';
  if (/Safari/i.test(ua)) return 'Safari';
  return 'Other';
}

async function doLogin() {
  const pw = document.getElementById('password').value;
  const r = await fetch(BASE+'/admin/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
  const d = await r.json();
  if (!r.ok) { document.getElementById('login-error').textContent = d.error; return; }
  document.getElementById('step1').style.display = 'none';
  document.getElementById('step2').style.display = 'block';
}

async function doVerify() {
  const code = document.getElementById('code').value;
  const r = await fetch(BASE+'/admin/verify', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
  const d = await r.json();
  if (!r.ok) { document.getElementById('verify-error').textContent = d.error; return; }
  TOKEN = d.token;
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('dashboard-view').style.display = 'block';
  document.getElementById('header-actions').style.display = 'block';
  loadStats('all');
}

async function loadStats(period, btn) {
  if (btn) { document.querySelectorAll('.period-bar button').forEach(b=>b.classList.remove('active')); btn.classList.add('active'); }
  const r = await fetch(BASE+'/api/stats?period='+period, {headers:{'Authorization':'Bearer '+TOKEN}});
  if (!r.ok) { alert('Session expired'); location.reload(); return; }
  const s = await r.json();

  document.getElementById('m-total').textContent = s.total.toLocaleString();
  document.getElementById('m-unique').textContent = s.unique_visitors.toLocaleString();
  document.getElementById('m-today').textContent = s.today.toLocaleString();
  document.getElementById('m-referrer').textContent = s.referrers.length ? new URL(s.referrers[0].referrer).hostname : '—';

  // Daily chart
  destroyChart('daily');
  charts.daily = new Chart(document.getElementById('chart-daily'), {
    type:'line',
    data:{labels:s.daily.map(d=>d.day), datasets:[{label:'Views',data:s.daily.map(d=>d.views),borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,0.1)',fill:true,tension:0.3}]},
    options:{responsive:true,plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}}}}
  });

  // Pie charts
  makePie('browsers', s.browsers);
  makePie('devices', s.devices);
  makePie('countries', s.countries.slice(0,8));
  makePie('languages', s.languages.slice(0,8));

  // Recent table
  const tbody = document.getElementById('recent-body');
  tbody.innerHTML = s.recent.map(v => {
    const t = new Date(v.timestamp).toLocaleString();
    const ref = v.referrer ? new URL(v.referrer).hostname : '—';
    return '<tr><td>'+t+'</td><td>'+(v.country||'—')+'</td><td>'+(v.path||'/')+'</td><td>'+ref+'</td><td>'+parseUA(v.user_agent)+'</td><td>'+(v.screen_width?v.screen_width+'x'+v.screen_height:'—')+'</td><td>'+(v.language||'—')+'</td></tr>';
  }).join('');
}

function makePie(id, data) {
  destroyChart(id);
  const names = data.map(d => d.name || d.country || d.language || 'Unknown');
  const counts = data.map(d => d.count);
  charts[id] = new Chart(document.getElementById('chart-'+id), {
    type:'doughnut',
    data:{labels:names,datasets:[{data:counts,backgroundColor:COLORS.slice(0,names.length)}]},
    options:{responsive:true,plugins:{legend:{position:'right',labels:{color:'#e6edf3',font:{size:11}}}}}
  });
}

function destroyChart(id) { if (charts[id]) { charts[id].destroy(); delete charts[id]; } }

function doLogout() {
  TOKEN = '';
  document.getElementById('dashboard-view').style.display = 'none';
  document.getElementById('header-actions').style.display = 'none';
  document.getElementById('login-view').style.display = 'flex';
  document.getElementById('step1').style.display = 'block';
  document.getElementById('step2').style.display = 'none';
  document.getElementById('password').value = '';
  document.getElementById('code').value = '';
  document.getElementById('login-error').textContent = '';
  document.getElementById('verify-error').textContent = '';
}

function showProfile() {
  document.getElementById('profile-modal').style.display = 'flex';
  document.getElementById('current-pw').value = '';
  document.getElementById('new-pw').value = '';
  document.getElementById('confirm-pw').value = '';
  document.getElementById('pw-msg').textContent = '';
}

function hideProfile() {
  document.getElementById('profile-modal').style.display = 'none';
}

async function doChangePassword() {
  const msg = document.getElementById('pw-msg');
  const cur = document.getElementById('current-pw').value;
  const np = document.getElementById('new-pw').value;
  const cp = document.getElementById('confirm-pw').value;
  if (!cur || !np) { msg.style.color='var(--red)'; msg.textContent='All fields required'; return; }
  if (np !== cp) { msg.style.color='var(--red)'; msg.textContent='Passwords do not match'; return; }
  if (np.length < 8) { msg.style.color='var(--red)'; msg.textContent='Min 8 characters'; return; }
  const r = await fetch(BASE+'/admin/change-password', {
    method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+TOKEN},
    body:JSON.stringify({currentPassword:cur, newPassword:np})
  });
  const d = await r.json();
  if (!r.ok) { msg.style.color='var(--red)'; msg.textContent=d.error; return; }
  msg.style.color='var(--green)'; msg.textContent='✅ Password changed!';
  setTimeout(hideProfile, 1500);
}

document.getElementById('password').addEventListener('keydown', e => { if (e.key==='Enter') doLogin(); });
document.getElementById('code').addEventListener('keydown', e => { if (e.key==='Enter') doVerify(); });
</script>
</body>
</html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}
