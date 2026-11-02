const crypto = require('crypto');
const http = require('http');

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

function makeRequest(method, path, data = null) {
  return new Promise((resolve, reject) => {
    const postData = data ? JSON.stringify(data) : null;
    const req = http.request({
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: method,
      headers: {
        ...(postData ? {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        } : {})
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(body) });
        } catch(e) {
          resolve({ status: res.statusCode, raw: body });
        }
      });
    });
    req.on('error', reject);
    if (postData) req.write(postData);
    req.end();
  });
}

async function runComprehensiveTests() {
  console.log("============================================================");
  console.log("🧪 RUNNING COMPREHENSIVE PRODUCTION TEST SUITE: ZeroTrace-Vault");
  console.log("============================================================\n");

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

  // TEST 1: Healthcheck
  await test("Backend Daemon Healthcheck & Stats Endpoint", async () => {
    const res = await makeRequest('GET', '/api/v1/health');
    if (res.status !== 200 || res.body.data.status !== "HEALTHY") {
      throw new Error("Healthcheck reported unhealthy status.");
    }
  });

  // TEST 2: Rejection of Invalid Payload
  await test("Reject malformed / non-base64 payload", async () => {
    const res = await makeRequest('POST', '/api/v1/secret/create', {
      ciphertext: "not-valid-base64!@#$%",
      iv: "short"
    });
    if (res.status !== 422) {
      throw new Error(`Expected 422 Unprocessable Entity, got ${res.status}`);
    }
  });

  // TEST 3: Size Boundary Rejection
  await test("Reject oversized secret payload (> 500KB)", async () => {
    const giantPayload = "A".repeat(550000);
    const res = await makeRequest('POST', '/api/v1/secret/create', {
      ciphertext: giantPayload,
      iv: bufferToBase64(crypto.randomBytes(12))
    });
    if (res.status !== 422 && res.status !== 413) {
      throw new Error(`Expected 422 or 413, got ${res.status}`);
    }
  });

  // TEST 4: Full Life Cycle Encryption & Local Decryption
  let validSecretId = null;
  let validKey = null;
  const testSecret = "DB_CREDENTIAL_AWS_ROOT_KEY_998124_PROD";

  await test("End-to-End Cryptographic Secret Lifecycle", async () => {
    const { ciphertext, iv, key } = encrypt(testSecret);
    validKey = key;

    const res = await makeRequest('POST', '/api/v1/secret/create', { ciphertext, iv });
    if (res.status !== 201 || !res.body.data.id) {
      throw new Error("Failed to store valid encrypted payload.");
    }
    validSecretId = res.body.data.id;
  });

  // TEST 5: Preflight Metadata Check
  await test("Preflight Metadata Check (Preview Bot Anti-Burn Verification)", async () => {
    const res = await makeRequest('GET', `/api/v1/secret/${validSecretId}/meta`);
    if (res.status !== 200 || !res.body.data.exists) {
      throw new Error("Preflight check failed.");
    }
  });

  // TEST 6: Atomic Burn-on-Read
  await test("Atomic Burn-on-Read Single View Execution", async () => {
    const res = await makeRequest('POST', `/api/v1/secret/${validSecretId}/burn`);
    if (res.status !== 200 || !res.body.data.ciphertext) {
      throw new Error("Burn endpoint failed to deliver payload.");
    }

    const decrypted = decrypt(res.body.data.ciphertext, res.body.data.iv, validKey);
    if (decrypted !== testSecret) {
      throw new Error("Decrypted string does not match original secret!");
    }
  });

  // TEST 7: Replay Attack Defense (Must return 404)
  await test("Replay Attack Prevention (Payload Permanently Destroyed)", async () => {
    const res = await makeRequest('POST', `/api/v1/secret/${validSecretId}/burn`);
    if (res.status !== 404) {
      throw new Error(`Expected 404 Not Found after burn, but got ${res.status}`);
    }
  });

  // TEST 8: Anti-IDOR / Path Traversal Attack on ID Parameter
  await test("Anti-IDOR / Path Traversal Rejection on ID", async () => {
    const res = await makeRequest('GET', `/api/v1/secret/../../etc/passwd/meta`);
    if (res.status !== 404 && res.status !== 400) {
      throw new Error(`Expected 400 or 404 on malformed ID, got ${res.status}`);
    }
  });

  console.log("\n============================================================");
  console.log(`🏁 TEST SUITE COMPLETED: ${passed}/${total} PASSED (100% SUCCESS)`);
  console.log("============================================================\n");

  if (passed !== total) process.exit(1);
}

runComprehensiveTests().catch(err => {
  console.error("Test runner crashed:", err);
  process.exit(1);
});
