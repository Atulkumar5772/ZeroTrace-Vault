/**
 * VaultStore: Ephemeral In-Memory Zero-Knowledge Engine
 * Audited against OWASP & Strict Single-View Guidelines
 */

const crypto = require('crypto');

// Strict Base64URL and UUID v4 regex validation
const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;
const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

class VaultStore {
  constructor(defaultTtlMs = 24 * 60 * 60 * 1000) {
    this.store = new Map();
    this.defaultTtlMs = defaultTtlMs;

    // Periodic sweep for abandoned secrets (every 2 minutes)
    this.sweeperInterval = setInterval(() => this.sweepExpired(), 2 * 60 * 1000);
    if (this.sweeperInterval.unref) {
      this.sweeperInterval.unref();
    }
  }

  isValidPayload(ciphertext, iv) {
    if (!ciphertext || typeof ciphertext !== 'string' || ciphertext.length > 500000) return false;
    if (!iv || typeof iv !== 'string' || iv.length < 12 || iv.length > 64) return false;
    return BASE64URL_REGEX.test(ciphertext) && BASE64URL_REGEX.test(iv);
  }

  isValidId(id) {
    return typeof id === 'string' && UUID_V4_REGEX.test(id);
  }

  storeSecret({ ciphertext, iv, salt }) {
    if (!this.isValidPayload(ciphertext, iv)) {
      throw new Error("Invalid cryptographic payload format.");
    }

    const id = crypto.randomUUID();
    const now = Date.now();

    const record = {
      ciphertext,
      iv,
      salt: salt && typeof salt === 'string' && BASE64URL_REGEX.test(salt) ? salt : null,
      createdAt: now,
      expiresAt: now + this.defaultTtlMs,
      consumed: false
    };

    this.store.set(id, record);
    return id;
  }

  checkMetadata(id) {
    if (!this.isValidId(id)) return null;

    const record = this.store.get(id);
    if (!record) return null;

    if (Date.now() > record.expiresAt || record.consumed) {
      this.shredRecord(id);
      return null;
    }

    return {
      exists: true,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt
    };
  }

  burnAndRetrieve(id) {
    if (!this.isValidId(id)) return null;

    const record = this.store.get(id);
    if (!record) return null;

    // Atomic Extraction & Immediate Shred
    this.store.delete(id);

    if (Date.now() > record.expiresAt || record.consumed) {
      return null;
    }

    record.consumed = true;

    const payload = {
      ciphertext: record.ciphertext,
      iv: record.iv,
      salt: record.salt
    };

    // Shred record references
    record.ciphertext = null;
    record.iv = null;
    record.salt = null;

    return payload;
  }

  shredRecord(id) {
    const record = this.store.get(id);
    if (record) {
      record.ciphertext = null;
      record.iv = null;
      record.salt = null;
      this.store.delete(id);
    }
  }

  sweepExpired() {
    const now = Date.now();
    for (const [id, record] of this.store.entries()) {
      if (now > record.expiresAt) {
        this.shredRecord(id);
      }
    }
  }

  purgeAll() {
    for (const id of this.store.keys()) {
      this.shredRecord(id);
    }
    this.store.clear();
  }

  getStats() {
    return {
      activeSecretsCount: this.store.size,
      uptimeSeconds: Math.floor(process.uptime())
    };
  }
}

module.exports = new VaultStore();
