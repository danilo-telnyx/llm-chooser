const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { setConfig, getConfig } = require('./db');

async function setup() {
  const existing = getConfig('admin_password_hash');
  if (existing) {
    console.log('⚠️  Admin password already set. To reset, delete analytics.db and run again.');
    return;
  }

  const password = crypto.randomBytes(12).toString('base64url');
  const hash = await bcrypt.hash(password, 12);
  setConfig('admin_password_hash', hash);

  console.log('\n╔══════════════════════════════════════════╗');
  console.log('║   LLM Chooser Analytics — Setup Complete ║');
  console.log('╠══════════════════════════════════════════╣');
  console.log(`║  Admin Password: ${password.padEnd(23)}║`);
  console.log('║  ⚠️  Save this! It won\'t be shown again. ║');
  console.log('╚══════════════════════════════════════════╝\n');
  console.log('Next steps:');
  console.log('  1. Set TELEGRAM_BOT_TOKEN env var for 2FA');
  console.log('  2. Run: node server.js');
  console.log('  3. Open: http://localhost:3847/admin\n');
}

setup().catch(console.error);
