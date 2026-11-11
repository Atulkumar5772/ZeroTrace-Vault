/**
 * VaultStore: Ephemeral In-Memory Zero-Knowledge Engine
 *
 * Guarantees:
 * 1. Strict Single-View (Burn-on-Read): Retrieval and deletion execute atomically in a single step.
 * 2. Bounded Memory Footprint: Enforces max active secrets and max total byte caps to prevent OOM DoS.
 * 3. Structural Validation: Validates UUID v4 IDs, Base64URL encoding, 96-bit IV length, and AES-GCM payload bounds.
 * 4. TTL Eviction: Abandoned unread secrets expire automatically via periodic sweeps.
 */

const crypto = require('crypto');

const BASE64URL_REGEX = /^[A-Za-z0-9_-]+$/;
const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MAX_PAYLOAD_BYTES = 512 * 1024; // 512 KB raw secret + 16-byte GCM tag ceiling
const MAX_CIPHERTEXT_CHARS = 700000;  // ~525 KB Base64URL max string ceiling
const AES_GCM_TAG_BYTES = 16;
const AES_GCM_IV_BYTES = 12;

class VaultStore {
  constructor(options = {}) {
    this.store = new Map();
    this.defaultTtlMs = options.defaultTtlMs || DEFAULT_TTL_MS;
    this.maxSecrets = options.maxSecrets || Number(process.env.MAX_VAULT_SECRETS) || 10000;
    this.maxTotalBytes = options.maxTotalBytes || Number(process.env.MAX_VAULT_BYTES) || (100 * 1024 * 1024); // 100 MB
    this.currentBytes = 0;

    // Periodic sweep for expired secrets (every 2 minutes)
    this.sweeperInterval = setInterval(() => this.sweepExpired(), 2 * 60 * 1000);
    if (this.sweeperInterval.unref) {
      this.sweeperInterval.unref();
    }
  }

  isValidBase64Url(str) {
    if (typeof str !== 'string' || str.length === 0) return false;
    if (str.length % 4 === 1) return false; // Impossible unpadded Base64URL length
    return BASE64URL_REGEX.test(str);
  }

  decodeBase64UrlByteLength(b64Url) {
    // Exact byte length from unpadded Base64URL length: floor(len * 3 / 4)
    return Math.floor((b64Url.length * 3) / 4);
  }

  isValidPayload(ciphertext, iv) {
    if (typeof ciphertext !== 'string' || typeof iv !== 'string') return false;
    if (ciphertext.length > MAX_CIPHERTEXT_CHARS) return false;
    if (!this.isValidBase64Url(ciphertext) || !this.isValidBase64Url(iv)) return false;

    // AES-GCM 96-bit IV must be exactly 12 bytes (16 Base64URL chars)
    const ivBytes = this.decodeBase64UrlByteLength(iv);
    if (ivBytes !== AES_GCM_IV_BYTES) return false;

    // AES-GCM ciphertext must contain at least the 16-byte authentication tag and not exceed 512 KB + tag
    const cipherBytes = this.decodeBase64UrlByteLength(ciphertext);
    if (cipherBytes < AES_GCM_TAG_BYTES || cipherBytes > MAX_PAYLOAD_BYTES + AES_GCM_TAG_BYTES) {
      return false;
    }

    return true;
  }

  isValidId(id) {
    return typeof id === 'string' && UUID_V4_REGEX.test(id);
  }

  storeSecret({ ciphertext, iv }) {
    if (!this.isValidPayload(ciphertext, iv)) {
      const err = new Error("Invalid cryptographic payload format or size.");
      err.code = "INVALID_FORMAT";
      throw err;
    }

    const entryBytes = ciphertext.length + iv.length;

    // Reclaim expired items before checking capacity
    if (this.store.size >= this.maxSecrets || (this.currentBytes + entryBytes) > this.maxTotalBytes) {
      this.sweepExpired();
    }

    if (this.store.size >= this.maxSecrets || (this.currentBytes + entryBytes) > this.maxTotalBytes) {
      const err = new Error("Vault ephemeral memory capacity temporarily reached. Please try again shortly.");
      err.code = "CAPACITY_REACHED";
      throw err;
    }

    const id = crypto.randomUUID();
    const now = Date.now();

    const record = {
      ciphertext,
      iv,
      byteSize: entryBytes,
      createdAt: now,
      expiresAt: now + this.defaultTtlMs,
      consumed: false
    };

    this.store.set(id, record);
    this.currentBytes += entryBytes;
    return id;
  }

  checkMetadata(id) {
    if (!this.isValidId(id)) return null;

    const record = this.store.get(id);
    if (!record) return null;

    if (Date.now() >= record.expiresAt || record.consumed) {
      this.releaseRecord(id);
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

    // Atomic removal from store
    this.store.delete(id);
    this.currentBytes = Math.max(0, this.currentBytes - record.byteSize);

    if (Date.now() >= record.expiresAt || record.consumed) {
      record.ciphertext = null;
      record.iv = null;
      return null;
    }

    record.consumed = true;

    const payload = {
      ciphertext: record.ciphertext,
      iv: record.iv
    };

    // Release object references for GC
    record.ciphertext = null;
    record.iv = null;

    return payload;
  }

  releaseRecord(id) {
    const record = this.store.get(id);
    if (record) {
      this.currentBytes = Math.max(0, this.currentBytes - record.byteSize);
      record.ciphertext = null;
      record.iv = null;
      this.store.delete(id);
    }
  }

  sweepExpired() {
    const now = Date.now();
    for (const [id, record] of this.store.entries()) {
      if (now >= record.expiresAt) {
        this.releaseRecord(id);
      }
    }
  }

  purgeAll() {
    for (const id of Array.from(this.store.keys())) {
      this.releaseRecord(id);
    }
    this.store.clear();
    this.currentBytes = 0;
  }

  stop() {
    if (this.sweeperInterval) {
      clearInterval(this.sweeperInterval);
      this.sweeperInterval = null;
    }
    this.purgeAll();
  }

  getStats() {
    return {
      uptimeSeconds: Math.floor(process.uptime())
    };
  }
}

module.exports = new VaultStore();
module.exports.VaultStore = VaultStore;
module.exports.MAX_PAYLOAD_BYTES = MAX_PAYLOAD_BYTES;
