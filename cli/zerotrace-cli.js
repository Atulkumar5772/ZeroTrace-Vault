#!/usr/bin/env node

/**
 * ZeroTrace CLI Tool
 * Encrypts secrets locally with AES-256-GCM and uploads only ciphertext + IV.
 *
 * Usage:
 *   node cli/zerotrace-cli.js "my super secret password"
 *   cat ~/.ssh/id_rsa | node cli/zerotrace-cli.js
 *
 * Environment Variables:
 *   ZEROTRACE_URL       Full base URL (e.g. https://zerotrace-vault.onrender.com)
 *   ZEROTRACE_PROTOCOL  http or https (default: http)
 *   ZEROTRACE_HOST      Hostname (default: localhost)
 *   ZEROTRACE_PORT      Port (default: 3000 for http, 443 for https)
 */

const crypto = require('crypto');
const http = require('http');
const https = require('https');

const MAX_SECRET_BYTES = 512 * 1024;

function printHelp() {
  console.log(`ZeroTrace-Vault CLI — Zero-Knowledge Single-View Secret Sharing

Usage:
  node cli/zerotrace-cli.js "<secret>"
  cat secret.txt | node cli/zerotrace-cli.js
  node cli/zerotrace-cli.js -- "-starts-with-dash"

Options:
  -h, --help    Show this help message and exit

Environment:
  ZEROTRACE_URL   Target server URL (default: http://localhost:3000)
                  Example: ZEROTRACE_URL=https://zerotrace-vault.onrender.com`);
}

function getTargetConfig() {
  if (process.env.ZEROTRACE_URL) {
    const parsed = new URL(process.env.ZEROTRACE_URL);
    const defaultPort = parsed.protocol === 'https:' ? 443 : 80;
    return {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port ? Number(parsed.port) : defaultPort,
      baseUrl: parsed.origin
    };
  }

  const protocol = (process.env.ZEROTRACE_PROTOCOL || 'http').replace(/:$/, '') + ':';
  const hostname = process.env.ZEROTRACE_HOST || 'localhost';
  const defaultPort = protocol === 'https:' ? 443 : 3000;
  const port = process.env.ZEROTRACE_PORT ? Number(process.env.ZEROTRACE_PORT) : defaultPort;
  const isStandardPort = (protocol === 'https:' && port === 443) || (protocol === 'http:' && port === 80);
  const baseUrl = `${protocol}//${hostname}${isStandardPort ? '' : ':' + port}`;

  return { protocol, hostname, port, baseUrl };
}

function bufferToBase64Url(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function encryptSecret(plaintext) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);

  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(plaintext, 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    const authTag = cipher.getAuthTag();

    const completeCiphertext = Buffer.concat([encrypted, authTag]);

    return {
      ciphertext: bufferToBase64Url(completeCiphertext),
      iv: bufferToBase64Url(iv),
      key: bufferToBase64Url(key)
    };
  } finally {
    key.fill(0);
    iv.fill(0);
  }
}

function postSecret(target, payload, callback) {
  const data = JSON.stringify({
    ciphertext: payload.ciphertext,
    iv: payload.iv
  });

  const transport = target.protocol === 'https:' ? https : http;
  const options = {
    hostname: target.hostname,
    port: target.port,
    path: '/api/v1/secret/create',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data)
    }
  };

  const req = transport.request(options, (res) => {
    let body = '';
    res.on('data', chunk => { body += chunk; });
    res.on('end', () => {
      let parsed = null;
      try {
        parsed = JSON.parse(body);
      } catch (e) {
        return callback(new Error(`Server returned non-JSON response (HTTP ${res.statusCode})`));
      }

      if (res.statusCode < 200 || res.statusCode >= 300 || !parsed.success || !parsed.data || !parsed.data.id) {
        const errMsg = (parsed && parsed.error && parsed.error.message) || parsed.message || `HTTP ${res.statusCode}`;
        return callback(new Error(errMsg));
      }

      callback(null, parsed.data);
    });
  });

  req.on('error', (e) => callback(e));
  req.write(data);
  req.end();
}

function handleInput(secret) {
  if (typeof secret !== 'string' || secret.length === 0) {
    console.error("❌ Error: Secret content cannot be empty.");
    process.exit(1);
  }

  const secretBytes = Buffer.byteLength(secret, 'utf8');
  if (secretBytes > MAX_SECRET_BYTES) {
    console.error(`❌ Error: Secret size (${secretBytes} bytes) exceeds maximum limit of ${MAX_SECRET_BYTES} bytes (512 KB).`);
    process.exit(1);
  }

  let target;
  try {
    target = getTargetConfig();
  } catch (err) {
    console.error("❌ Invalid ZEROTRACE_URL configuration:", err.message);
    process.exit(1);
  }

  console.error("🔒 Encrypting secret locally with AES-256-GCM...");
  const encrypted = encryptSecret(secret);

  postSecret(target, encrypted, (err, data) => {
    if (err) {
      console.error("❌ Failed to store secret:", err.message);
      process.exit(1);
    }

    const secureUrl = `${target.baseUrl}/v/${data.id}#${encrypted.key}`;

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

function main() {
  const args = process.argv.slice(2);

  if (args.length > 0) {
    if (args[0] === '--help' || args[0] === '-h') {
      printHelp();
      process.exit(0);
    }

    if (args[0] === '--') {
      if (args.length < 2) {
        console.error("❌ Error: No secret provided after '--'.");
        process.exit(1);
      }
      handleInput(args.slice(1).join(' '));
      return;
    }

    if (args[0].startsWith('-')) {
      console.error(`❌ Unknown option: ${args[0]}`);
      printHelp();
      process.exit(1);
    }

    handleInput(args.join(' '));
    return;
  }

  if (process.stdin.isTTY) {
    printHelp();
    process.exit(0);
  }

  let stdinData = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', chunk => { stdinData += chunk; });
  process.stdin.on('end', () => {
    if (!stdinData || stdinData.length === 0) {
      console.error("❌ Error: Stdin input is empty.");
      process.exit(1);
    }
    handleInput(stdinData);
  });
}

if (require.main === module) {
  main();
}

module.exports = { encryptSecret, getTargetConfig };
