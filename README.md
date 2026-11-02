# 🛡️ ZeroTrace-Vault: Zero-Knowledge Ephemeral Secret Sharing Vault

> **Domain:** Application Security, Applied End-to-End Cryptography, Zero-Knowledge Architecture, Distributed Ephemeral Memory.  
> **Codename:** `ZeroTrace-Vault`

---

## 📌 1. The Real-World Incident & Why This Exists
In the **Uber 2022 Breach**, an attacker compromised the entire corporate AWS infrastructure and VPN network simply because a DevOps engineer shared admin credentials in an internal **Slack channel**. The attacker ran a simple search query: `search "AWS_SECRET_ACCESS_KEY"` and gained root access.

Corporate chats (Slack, WhatsApp, Teams, Emails) are **permanent, indexed, searchable databases**. Credentials shared there remain vulnerable indefinitely.

### Why Existing Tools (Pastebin/Privnote) Fail:
Most pastebins encrypt on the server side or hold plaintext credentials in memory. If the server is compromised or an admin goes rogue, all secrets are leaked.

---

## 🎯 2. The Zero-Knowledge Guarantee (RFC 3986 Anchor Isolation)

`ZeroTrace-Vault` guarantees that **even the system owner or cloud hosting provider CANNOT read the shared secrets.**

### How the `#` Anchor Isolation Works:
1. Alice's browser/CLI generates a **256-bit AES-GCM** key locally.
2. The secret is encrypted on the client machine.
3. The server receives **ONLY** the ciphertext and 96-bit IV. **The key is NEVER sent over the wire.**
4. A unique URL is generated:
   `https://vault.domain.com/v/c0ed7d19...#knN2IeVIVu...`
5. According to **RFC 3986**, web browsers **never transmit the hash fragment (`#...`) in HTTP requests**. The key remains strictly in Bob's browser memory.

```
[ Alice Browser/CLI ] ──(AES-GCM-256 + IV)──> Ciphertext ──> [ ZeroTrace Server ] ──> [ RAM Memory ]
          │                                                                                 ▲
          └──────> URL: https://vault.dev/v/{UUID}#{Key}                                     │
                             │                                                             │
  [ Bob Browser ] <──────────┴──────── (Fetch Ciphertext & Burn) ──────────────────────────┘
    (Decrypts locally using #Key)
```

---

## 🔥 3. Strict Single-View Policy (Burn-on-Read)

1. **Pre-flight Crawl Protection (`/api/v1/secret/:id/meta`):**  
   Social link crawlers (Slackbot, WhatsApp, Discord) fetching link previews **will NOT destroy the secret**.
2. **Atomic Burn Execution (`/api/v1/secret/:id/burn`):**  
   When Bob clicks **"Reveal Secret"**, the server retrieves the payload and **instantly purges it from RAM**.
3. **Second Attempt Defense:**  
   Any subsequent request with the same UUID immediately yields `404 Not Found`.

---

## 💻 4. Running the Project Locally

### Start the Vault Server:
```bash
cd backend
npm install
npm start
```
Server opens at `http://localhost:3000`.

### CLI Tool Usage (Terminal / Pipes):
```bash
# Share a direct string
node cli/zerotrace-cli.js "my-production-token"

# Or pipe output from any command:
cat ~/.ssh/id_rsa | node cli/zerotrace-cli.js
```

---

## 🧪 5. Automated Verification
Run the end-to-end cryptographic and burn test:
```bash
node test_verification.js
```
Expected output:
* Client AES-256-GCM encryption verified
* Pre-flight metadata check confirmed
* Local client decryption matched 100%
* 2nd read attempt verified as `404 Burned & Destroyed`

---

## 🎯 6. Resume & Interview Pitch
> *"Engineered **ZeroTrace-Vault**, an end-to-end zero-knowledge secret orchestration engine designed to eliminate credential sprawl in enterprise communications. Leveraged the browser WebCrypto API (AES-GCM-256) with client-side RFC 3986 `#` URL-fragment key isolation, guaranteeing zero server-side key exposure. Implemented an atomic single-view burn-on-read engine with anti-crawler preflight validation, ensuring sub-millisecond ephemeral memory destruction upon retrieval."*
