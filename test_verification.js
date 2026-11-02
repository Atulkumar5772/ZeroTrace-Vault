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
  const ciphertextWithTag = Buffer.concat([enc, tag]);

  return {
    ciphertext: bufferToBase64(ciphertextWithTag),
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

async function runVerification() {
  console.log("🧪 Starting Automated Verification of Hardened ZeroTrace-Vault...");

  const originalPlaintext = "Production_Credentials_2026_@Hardened";
  console.log(`\n1. Plaintext to encrypt: "${originalPlaintext}"`);

  // Client encrypts
  const { ciphertext, iv, key } = encrypt(originalPlaintext);
  console.log("2. Encrypted payload generated.");
  console.log(`   Ciphertext: ${ciphertext.substring(0, 20)}...`);
  console.log(`   Isolated Key: ${key.substring(0, 10)}... (Client-only)`);

  // Alice posts ciphertext
  const createRes = await makeRequest('POST', '/api/v1/secret/create', { ciphertext, iv });
  if (createRes.status !== 201 || !createRes.body.data.id) {
    throw new Error("Failed to store secret: " + JSON.stringify(createRes));
  }
  const secretId = createRes.body.data.id;
  console.log(`3. Server accepted payload. Assigned Secret ID: ${secretId}`);

  // Bob verifies metadata check (Pre-flight check without burning)
  const metaRes = await makeRequest('GET', `/api/v1/secret/${secretId}/meta`);
  if (metaRes.status !== 200 || !metaRes.body.data.exists) {
    throw new Error("Meta check failed: " + JSON.stringify(metaRes));
  }
  console.log("4. Pre-flight check successful: Secret exists and was NOT burned by preview scan.");

  // Bob reads and burns
  const burnRes = await makeRequest('POST', `/api/v1/secret/${secretId}/burn`);
  if (burnRes.status !== 200 || !burnRes.body.data.ciphertext) {
    throw new Error("Burn request failed: " + JSON.stringify(burnRes));
  }
  console.log("5. Bob executed burn request. Payload retrieved from server.");

  // Bob decrypts locally
  const decryptedText = decrypt(burnRes.body.data.ciphertext, burnRes.body.data.iv, key);
  console.log(`6. Bob decrypted secret locally: "${decryptedText}"`);
  if (decryptedText !== originalPlaintext) {
    throw new Error("Decrypted text does NOT match original!");
  }
  console.log("   ✅ MATCH CONFIRMED!");

  // ATTACKER / SECOND ATTEMPT VERIFICATION:
  console.log("\n7. Simulating 2nd read attempt (Burn-on-Read test)...");
  const secondBurn = await makeRequest('POST', `/api/v1/secret/${secretId}/burn`);
  if (secondBurn.status === 404) {
    console.log("   ✅ SUCCESS: 2nd attempt returned 404. Payload has been completely destroyed!");
  } else {
    throw new Error("VULNERABILITY DETECTED: Secret was accessible after 1st read!");
  }

  console.log("\n🎉 ALL TESTS PASSED: Hardened Zero-Knowledge & Burn-on-Read verified!\n");
}

runVerification().catch(err => {
  console.error("❌ Test Failed:", err);
  process.exit(1);
});
