#!/usr/bin/env node

/**
 * ZeroTrace CLI Tool
 * Allows terminal / POSIX pipe usage to share secrets instantly.
 * 
 * Usage:
 *   node zerotrace-cli.js "my super secret password"
 *   cat ~/.ssh/id_rsa | node zerotrace-cli.js
 */

const crypto = require('crypto');
const http = require('http');

const API_HOST = process.env.ZEROTRACE_HOST || 'localhost';
const API_PORT = process.env.ZEROTRACE_PORT || 3000;

function bufferToBase64(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function encryptSecret(plaintext) {
  // 256-bit AES-GCM Key
  const key = crypto.randomBytes(32);
  // 96-bit IV
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(plaintext, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  // WebCrypto compatibility: append authTag to ciphertext
  const completeCiphertext = Buffer.concat([encrypted, authTag]);

  return {
    ciphertext: bufferToBase64(completeCiphertext),
    iv: bufferToBase64(iv),
    key: bufferToBase64(key)
  };
}

function postSecret(payload, callback) {
  const data = JSON.stringify({
    ciphertext: payload.ciphertext,
    iv: payload.iv
  });

  const options = {
    hostname: API_HOST,
    port: API_PORT,
    path: '/api/v1/secret/create',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data)
    }
  };

  const req = http.request(options, (res) => {
    let body = '';
    res.on('data', chunk => body += chunk);
    res.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        callback(null, parsed);
      } catch (e) {
        callback(e);
      }
    });
  });

  req.on('error', (e) => callback(e));
  req.write(data);
  req.end();
}

function handleInput(secret) {
  const cleanSecret = secret.trim();
  if (!cleanSecret) {
    console.error("❌ Error: Secret content cannot be empty.");
    process.exit(1);
  }

  console.log("🔒 Encrypting secret locally with AES-256-GCM...");
  const encrypted = encryptSecret(cleanSecret);

  postSecret(encrypted, (err, res) => {
    if (err || !res.id) {
      console.error("❌ Failed to reach ZeroTrace-Vault server:", err ? err.message : res.message);
      process.exit(1);
    }

    const secureUrl = `http://${API_HOST}:${API_PORT}/v/${res.id}#${encrypted.key}`;

    console.log("\n========================================================");
    console.log("🛡️  ZEROTRACE-VAULT: ZERO-KNOWLEDGE LINK GENERATED");
    console.log("========================================================");
    console.log(`🔗 URL: ${secureUrl}`);
    console.log("========================================================");
    console.log("⚡ Policy: STRICT SINGLE-VIEW (Burns permanently on 1st read)");
    console.log("🔒 Note  : Key is isolated in the '#' anchor (Server cannot decrypt)");
    console.log("========================================================\n");
  });
}

// Check arguments or stdin stream
if (process.argv[2]) {
  handleInput(process.argv.slice(2).join(' '));
} else {
  let stdinData = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => stdinData += chunk);
  process.stdin.on('end', () => {
    if (!stdinData) {
      console.log("Usage: node zerotrace-cli.js <secret>  OR  cat file | node zerotrace-cli.js");
      process.exit(0);
    }
    handleInput(stdinData);
  });
}
