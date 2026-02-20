const TELEGRAM_CHAT_ID = '1023351889';

// Store pending 2FA codes in memory (short-lived)
const pendingCodes = new Map();

async function sendTelegram2FA(botToken) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

  pendingCodes.set(code, { expiresAt });

  // Clean expired codes
  for (const [k, v] of pendingCodes) {
    if (v.expiresAt < Date.now()) pendingCodes.delete(k);
  }

  const fetch = (await import('node-fetch')).default;
  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: TELEGRAM_CHAT_ID,
      text: `🔐 LLM Chooser Analytics\n\nYour 2FA code: *${code}*\n\nExpires in 5 minutes.`,
      parse_mode: 'Markdown'
    })
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Telegram API error: ${err}`);
  }

  return true;
}

function verify2FA(code) {
  const entry = pendingCodes.get(code);
  if (!entry) return false;
  if (entry.expiresAt < Date.now()) {
    pendingCodes.delete(code);
    return false;
  }
  pendingCodes.delete(code);
  return true;
}

module.exports = { sendTelegram2FA, verify2FA };
