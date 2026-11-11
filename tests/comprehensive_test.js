const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const { execFile } = require('child_process');
const { createApp } = require('../backend/src/server');
const vaultStore = require('../backend/src/vaultStore');
const { VaultStore } = require('../backend/src/vaultStore');
const RateLimiter = require('../backend/src/rateLimiter');

function bufferToBase64(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64ToBuffer(b64) {
  let str = b64.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

function encrypt(text) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let enc = cipher.update(text, 'utf8');
  enc = Buffer.concat([enc, cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: bufferToBase64(Buffer.concat([enc, tag])),
    iv: bufferToBase64(iv),
    key: bufferToBase64(key)
  };
}

function decrypt(ciphertextB64, ivB64, keyB64) {
  const fullBuf = base64ToBuffer(ciphertextB64);
  const tag = fullBuf.subarray(fullBuf.length - 16);
  const ciphertext = fullBuf.subarray(0, fullBuf.length - 16);
  const iv = base64ToBuffer(ivB64);
  const key = base64ToBuffer(keyB64);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let dec = decipher.update(ciphertext, null, 'utf8');
  dec += decipher.final('utf8');
  return dec;
}

function makeRawRequest(port, method, reqPath, rawBody = null, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const headers = { ...extraHeaders };
    if (rawBody !== null && !headers['Content-Length']) {
      headers['Content-Length'] = Buffer.byteLength(rawBody);
    }

    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: reqPath,
      method,
      headers
    }, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(body), raw: body });
        } catch (_) {
          resolve({ status: res.statusCode, headers: res.headers, body: null, raw: body });
        }
      });
    });

    req.on('error', reject);
    if (rawBody !== null) req.write(rawBody);
    req.end();
  });
}

function makeJsonRequest(port, method, reqPath, data = null, extraHeaders = {}) {
  const postData = data !== null ? JSON.stringify(data) : null;
  const headers = {
    ...(postData !== null ? { 'Content-Type': 'application/json' } : {}),
    ...extraHeaders
  };
  return makeRawRequest(port, method, reqPath, postData, headers);
}

function runCli(args, env = {}, stdinText = null) {
  return new Promise((resolve) => {
    const cliPath = path.join(__dirname, '..', 'cli', 'zerotrace-cli.js');
    const child = execFile(process.execPath, [cliPath, ...args], {
      env: { ...process.env, ...env }
    }, (error, stdout, stderr) => {
      resolve({
        code: error ? error.code : 0,
        stdout,
        stderr
      });
    });
    if (stdinText !== null) {
      child.stdin.write(stdinText);
      child.stdin.end();
    }
  });
}

async function runComprehensiveTests() {
  console.log("============================================================");
  console.log("🧪 RUNNING COMPREHENSIVE SECURITY & CONCURRENCY TEST SUITE");
  console.log("============================================================\n");

  // Start isolated server on ephemeral port with high rate limit for lifecycle tests
  const mainApp = createApp({
    trustProxy: false,
    forceHttps: false,
    rateLimiter: new RateLimiter(100, 60 * 1000)
  });

  const server = await new Promise((resolve) => {
    const s = mainApp.listen(0, '127.0.0.1', () => resolve(s));
  });
  const port = server.address().port;

  let passed = 0;
  let total = 0;

  async function test(name, fn) {
    total++;
    try {
      await fn();
      console.log(`✅ TEST ${total} PASSED: ${name}`);
      passed++;
    } catch (err) {
      console.error(`❌ TEST ${total} FAILED: ${name}`);
      console.error(`   Reason: ${err.message}`);
    }
  }

  try {
    // 1. Healthcheck & privacy
    await test("Healthcheck returns 200 and omits activeSecretsCount", async () => {
      const res = await makeJsonRequest(port, 'GET', '/api/v1/health');
      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.body.data.status, 'HEALTHY');
      assert.strictEqual(res.body.data.activeSecretsCount, undefined);
      assert.strictEqual(res.body.data.stats, undefined);
    });

    // 2. Cryptographic format & structural Base64URL validation
    await test("Reject malformed Base64URL, impossible lengths, and short IVs (422)", async () => {
      const validIv = bufferToBase64(crypto.randomBytes(12));
      const res1 = await makeJsonRequest(port, 'POST', '/api/v1/secret/create', {
        ciphertext: "not-valid-base64!@#$%",
        iv: "short"
      });
      assert.strictEqual(res1.status, 422);

      // Impossible Base64URL length (len % 4 === 1) and < 16-byte GCM tag
      const res2 = await makeJsonRequest(port, 'POST', '/api/v1/secret/create', {
        ciphertext: "AAAAA",
        iv: validIv
      });
      assert.strictEqual(res2.status, 422);

      // 1-char ciphertext
      const res3 = await makeJsonRequest(port, 'POST', '/api/v1/secret/create', {
        ciphertext: "a",
        iv: validIv
      });
      assert.strictEqual(res3.status, 422);

      // Wrong IV length (12 chars = 9 bytes instead of 12 bytes)
      const res4 = await makeJsonRequest(port, 'POST', '/api/v1/secret/create', {
        ciphertext: bufferToBase64(crypto.randomBytes(32)),
        iv: "AAAAAAAAAAAA"
      });
      assert.strictEqual(res4.status, 422);
    });

    // 3. Size boundaries & Express body-parser status codes (400 / 413 / 422)
    await test("Malformed JSON -> 400, null body -> 400, oversized body -> 413/422", async () => {
      const badJson = await makeRawRequest(port, 'POST', '/api/v1/secret/create', '{bad json', {
        'Content-Type': 'application/json'
      });
      assert.strictEqual(badJson.status, 400);
      assert.strictEqual(badJson.body.error.code, 'INVALID_JSON');

      const nullBody = await makeRawRequest(port, 'POST', '/api/v1/secret/create', 'null', {
        'Content-Type': 'application/json'
      });
      assert.strictEqual(nullBody.status, 400);

      const hugeRaw = JSON.stringify({
        ciphertext: "A".repeat(800000),
        iv: bufferToBase64(crypto.randomBytes(12))
      });
      const hugeRes = await makeRawRequest(port, 'POST', '/api/v1/secret/create', hugeRaw, {
        'Content-Type': 'application/json'
      });
      assert.strictEqual(hugeRes.status, 413);
    });

    // 4. End-to-end lifecycle + Cache-Control: no-store + unused salt ignored
    let validSecretId = null;
    let validKey = null;
    const testSecret = "  DB_CREDENTIAL_AWS_ROOT_KEY_998124_PROD \n";

    await test("End-to-End AES-GCM-256 lifecycle, salt ignored, and no-store headers", async () => {
      const { ciphertext, iv, key } = encrypt(testSecret);
      validKey = key;

      const createRes = await makeJsonRequest(port, 'POST', '/api/v1/secret/create', {
        ciphertext,
        iv,
        salt: "X".repeat(200000)
      });
      assert.strictEqual(createRes.status, 201);
      validSecretId = createRes.body.data.id;

      const metaRes = await makeJsonRequest(port, 'GET', `/api/v1/secret/${validSecretId}/meta`);
      assert.strictEqual(metaRes.status, 200);
      assert.strictEqual(metaRes.body.data.exists, true);
      assert.ok((metaRes.headers['cache-control'] || '').includes('no-store'));

      const burnRes = await makeJsonRequest(port, 'POST', `/api/v1/secret/${validSecretId}/burn`);
      assert.strictEqual(burnRes.status, 200);
      assert.strictEqual(burnRes.body.data.salt, undefined);
      assert.ok((burnRes.headers['cache-control'] || '').includes('no-store'));

      const decrypted = decrypt(burnRes.body.data.ciphertext, burnRes.body.data.iv, validKey);
      assert.strictEqual(decrypted, testSecret);
    });

    // 5. Replay attack & 20-way concurrent /burn race test
    await test("Atomic Burn-on-Read under 20 concurrent /burn requests (1x 200, 19x 404)", async () => {
      const replay = await makeJsonRequest(port, 'POST', `/api/v1/secret/${validSecretId}/burn`);
      assert.strictEqual(replay.status, 404);

      const { ciphertext, iv } = encrypt("race-condition-check");
      const created = await makeJsonRequest(port, 'POST', '/api/v1/secret/create', { ciphertext, iv });
      const raceId = created.body.data.id;

      const results = await Promise.all(
        Array.from({ length: 20 }, () => makeJsonRequest(port, 'POST', `/api/v1/secret/${raceId}/burn`))
      );
      const count200 = results.filter(r => r.status === 200).length;
      const count404 = results.filter(r => r.status === 404).length;
      assert.strictEqual(count200, 1, `Expected exactly 1 success, got ${count200}`);
      assert.strictEqual(count404, 19, `Expected 19 rejections, got ${count404}`);
    });

    // 6. Routing & ID validation (/api, /favicon.ico, INVALID_ID 400)
    await test("Invalid UUID -> 400 INVALID_ID, /api -> 404 JSON, /favicon.ico -> 204", async () => {
      const badId = await makeJsonRequest(port, 'GET', '/api/v1/secret/not-a-valid-uuid/meta');
      assert.strictEqual(badId.status, 400);
      assert.strictEqual(badId.body.error.code, 'INVALID_ID');

      const apiRoot = await makeJsonRequest(port, 'GET', '/api');
      assert.strictEqual(apiRoot.status, 404);
      assert.strictEqual(apiRoot.body.error.code, 'ENDPOINT_NOT_FOUND');

      const fav = await makeJsonRequest(port, 'GET', '/favicon.ico');
      assert.strictEqual(fav.status, 204);
    });

    // 7. Strict CORS & CSP/HSTS headers on plain HTTP
    await test("CORS rejects untrusted Origin and CSP omits 'unsafe-inline' and HSTS on HTTP", async () => {
      const evilRes = await makeJsonRequest(port, 'GET', '/api/v1/health', null, {
        Origin: 'https://evil-attacker.example'
      });
      assert.strictEqual(evilRes.headers['access-control-allow-origin'], undefined);

      const homeRes = await makeRawRequest(port, 'GET', '/');
      assert.strictEqual(homeRes.status, 200);
      assert.ok((homeRes.headers['cache-control'] || '').includes('no-store'));
      const csp = homeRes.headers['content-security-policy'] || '';
      assert.ok(!csp.includes('unsafe-inline'), `Unexpected unsafe-inline in CSP: ${csp}`);
      assert.ok(!csp.includes('upgrade-insecure-requests'), 'Plain HTTP should not upgrade-insecure-requests');
      assert.strictEqual(homeRes.headers['strict-transport-security'], undefined);
    });

    // 8. Bounded VaultStore capacity defense
    await test("VaultStore enforces maxSecrets and maxTotalBytes bounds (OOM DoS protection)", async () => {
      const boundedStore = new VaultStore({ maxSecrets: 2, maxTotalBytes: 1000 });
      const { ciphertext, iv } = encrypt("small-secret");
      boundedStore.storeSecret({ ciphertext, iv });
      boundedStore.storeSecret({ ciphertext, iv });
      assert.throws(() => boundedStore.storeSecret({ ciphertext, iv }), (err) => err.code === 'CAPACITY_REACHED');
      boundedStore.stop();
    });

    // 9. X-Forwarded-For spoofing immunity + Sliding Window + /health exemption
    await test("X-Forwarded-For spoofing blocked when trustProxy=false & /health exempted", async () => {
      const strictApp = createApp({
        trustProxy: false,
        forceHttps: false,
        rateLimiter: new RateLimiter(3, 60 * 1000)
      });
      const strictServer = await new Promise((resolve) => {
        const s = strictApp.listen(0, '127.0.0.1', () => resolve(s));
      });
      const strictPort = strictServer.address().port;

      try {
        const { ciphertext, iv } = encrypt("rate-limit-test");
        for (let i = 1; i <= 3; i++) {
          const r = await makeJsonRequest(strictPort, 'POST', '/api/v1/secret/create', { ciphertext, iv }, {
            'X-Forwarded-For': `203.0.113.${i}`
          });
          assert.strictEqual(r.status, 201);
        }

        // 4th request with a spoofed IP must still be blocked (429)
        const blocked = await makeJsonRequest(strictPort, 'POST', '/api/v1/secret/create', { ciphertext, iv }, {
          'X-Forwarded-For': '203.0.113.99'
        });
        assert.strictEqual(blocked.status, 429);
        assert.ok(Number(blocked.headers['retry-after']) >= 1);
        assert.strictEqual(blocked.headers['ratelimit-remaining'], '0');

        // Healthcheck must remain unthrottled
        const health = await makeJsonRequest(strictPort, 'GET', '/api/v1/health');
        assert.strictEqual(health.status, 200);
      } finally {
        strictApp.locals.rateLimiter.stop();
        await new Promise((resolve) => strictServer.close(resolve));
      }
    });

    // 10. CLI --help & live CLI upload + whitespace preservation
    await test("CLI --help exits 0 without uploading and CLI creates valid decryptable secret", async () => {
      const helpRes = await runCli(['--help'], { ZEROTRACE_PORT: String(port) });
      assert.strictEqual(helpRes.code, 0);
      assert.ok(helpRes.stdout.includes('Usage:'));

      const cliSecret = "  cli_secret_with_spaces  ";
      const cliRes = await runCli(['--', cliSecret], {
        ZEROTRACE_HOST: '127.0.0.1',
        ZEROTRACE_PORT: String(port)
      });
      assert.strictEqual(cliRes.code, 0, `CLI exited ${cliRes.code}: ${cliRes.stderr}`);
      const match = cliRes.stdout.match(/http:\/\/127\.0\.0\.1:\d+\/v\/([0-9a-f-]+)#([A-Za-z0-9_-]+)/i);
      assert.ok(match, `CLI did not output a valid ZeroTrace URL:\n${cliRes.stdout}`);

      const [, cliId, cliKey] = match;
      const burnRes = await makeJsonRequest(port, 'POST', `/api/v1/secret/${cliId}/burn`);
      assert.strictEqual(burnRes.status, 200);
      const decrypted = decrypt(burnRes.body.data.ciphertext, burnRes.body.data.iv, cliKey);
      assert.strictEqual(decrypted, cliSecret);
    });
  } finally {
    mainApp.locals.rateLimiter.stop();
    vaultStore.stop();
    await new Promise((resolve) => server.close(resolve));
  }

  console.log("\n============================================================");
  const summaryLabel = passed === total ? "100% SUCCESS" : `${total - passed} FAILED`;
  console.log(`🏁 TEST SUITE COMPLETED: ${passed}/${total} PASSED (${summaryLabel})`);
  console.log("============================================================\n");

  if (passed !== total) process.exit(1);
}

runComprehensiveTests().catch(err => {
  console.error("Test runner crashed:", err);
  process.exit(1);
});
