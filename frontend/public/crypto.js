/**
 * ZeroTrace WebCrypto Engine
 * Uses Browser Native window.crypto.subtle (AES-GCM-256)
 */

const ZeroCrypto = {
  MAX_SECRET_BYTES: 512 * 1024,

  isSupported() {
    return typeof window !== 'undefined' && Boolean(window.crypto && window.crypto.subtle);
  },

  assertSupported() {
    if (!this.isSupported()) {
      throw new Error("WebCrypto API is unavailable in this context. Please access ZeroTrace-Vault over HTTPS or localhost.");
    }
  },

  getUtf8ByteLength(str) {
    return new TextEncoder().encode(str).byteLength;
  },

  isValidBase64Url(str) {
    if (typeof str !== 'string' || str.length === 0) return false;
    if (str.length % 4 === 1) return false;
    return /^[A-Za-z0-9_-]+$/.test(str);
  },

  isValidKey(keyB64) {
    if (!this.isValidBase64Url(keyB64)) return false;
    try {
      const buf = this.base64ToBuffer(keyB64);
      return buf.byteLength === 32; // Exact 256-bit AES key
    } catch (_) {
      return false;
    }
  },

  bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.byteLength; i += chunkSize) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  },

  base64ToBuffer(base64) {
    if (!this.isValidBase64Url(base64)) {
      throw new Error("Malformed Base64URL data.");
    }
    let str = base64.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
      str += '=';
    }
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  },

  async encrypt(plaintext) {
    this.assertSupported();

    const encodedData = new TextEncoder().encode(plaintext);
    if (encodedData.byteLength > this.MAX_SECRET_BYTES) {
      throw new Error("Secret exceeds maximum 512 KB limit.");
    }

    const key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encodedData
    );

    const exportedRawKey = await window.crypto.subtle.exportKey("raw", key);

    return {
      ciphertext: this.bufferToBase64(ciphertextBuffer),
      iv: this.bufferToBase64(iv.buffer),
      key: this.bufferToBase64(exportedRawKey)
    };
  },

  async decrypt(ciphertextB64, ivB64, keyB64) {
    this.assertSupported();

    const rawKeyBuffer = this.base64ToBuffer(keyB64);
    if (rawKeyBuffer.byteLength !== 32) {
      throw new Error("Invalid 256-bit key length.");
    }

    const ivBuffer = this.base64ToBuffer(ivB64);
    const ciphertextBuffer = this.base64ToBuffer(ciphertextB64);

    const key = await window.crypto.subtle.importKey(
      "raw",
      rawKeyBuffer,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(ivBuffer) },
      key,
      ciphertextBuffer
    );

    return new TextDecoder().decode(decryptedBuffer);
  }
};
