/**
 * ZeroTrace WebCrypto Engine
 * Uses Browser Native window.crypto.subtle
 * Algorithm: AES-GCM-256 (Authenticated Encryption with Associated Data)
 * 
 * Guarantees:
 * - 0 External Dependencies (No third-party JS libraries, zero supply chain attack risk)
 * - 256-bit cryptographically secure keys
 * - 96-bit unique IV (Initialization Vector) per secret
 * - URL Safe Base64 conversions
 */

const ZeroCrypto = {
  // ArrayBuffer to URL-safe Base64
  bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  },

  // URL-safe Base64 to ArrayBuffer
  base64ToBuffer(base64) {
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

  /**
   * Encrypts plaintext using AES-GCM-256
   * Returns: { ciphertext, iv, key }
   */
  async encrypt(plaintext) {
    // 1. Generate 256-bit AES-GCM Key
    const key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true, // extractable
      ["encrypt", "decrypt"]
    );

    // 2. Generate 96-bit (12-byte) unique IV
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    // 3. Encrypt payload
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(plaintext);

    const ciphertextBuffer = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encodedData
    );

    // 4. Export Raw Key to URL-safe Base64
    const exportedRawKey = await window.crypto.subtle.exportKey("raw", key);

    return {
      ciphertext: this.bufferToBase64(ciphertextBuffer),
      iv: this.bufferToBase64(iv.buffer),
      key: this.bufferToBase64(exportedRawKey)
    };
  },

  /**
   * Decrypts ciphertext using AES-GCM-256 and the extracted key
   * Returns: plaintext string
   */
  async decrypt(ciphertextB64, ivB64, keyB64) {
    const rawKeyBuffer = this.base64ToBuffer(keyB64);
    const ivBuffer = this.base64ToBuffer(ivB64);
    const ciphertextBuffer = this.base64ToBuffer(ciphertextB64);

    // 1. Import raw key into WebCrypto KeyObject
    const key = await window.crypto.subtle.importKey(
      "raw",
      rawKeyBuffer,
      { name: "AES-GCM" },
      false, // non-extractable once imported
      ["decrypt"]
    );

    // 2. Decrypt & Verify 128-bit AEAD Authentication Tag
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(ivBuffer) },
      key,
      ciphertextBuffer
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  }
};
