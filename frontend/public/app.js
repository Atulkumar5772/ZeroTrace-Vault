/**
 * ZeroTrace Frontend Application Logic
 * Audited for XSS prevention, address bar key scrubbing, and UX feedback.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const createView = document.getElementById("create-view");
  const shareView = document.getElementById("share-view");
  const revealConfirmView = document.getElementById("reveal-confirm-view");
  const revealedView = document.getElementById("revealed-view");
  const burnedView = document.getElementById("burned-view");

  const secretInput = document.getElementById("secret-input");
  const charCounter = document.getElementById("char-counter");
  const btnCreate = document.getElementById("btn-create");
  const shareLinkBox = document.getElementById("share-link");
  const btnCopy = document.getElementById("btn-copy");
  const btnNew = document.getElementById("btn-new");
  const btnReveal = document.getElementById("btn-reveal");
  const secretContent = document.getElementById("secret-content");
  const btnCopySecret = document.getElementById("btn-copy-secret");

  function hideAllViews() {
    createView.classList.add("hidden");
    shareView.classList.add("hidden");
    revealConfirmView.classList.add("hidden");
    revealedView.classList.add("hidden");
    burnedView.classList.add("hidden");
  }

  // Character counter
  if (secretInput && charCounter) {
    secretInput.addEventListener("input", () => {
      const len = secretInput.value.length;
      charCounter.textContent = `${len.toLocaleString()} chars`;
    });

    // Ctrl + Enter shortcut to trigger creation
    secretInput.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        btnCreate.click();
      }
    });
  }

  // Route Handling: Check if visiting /v/:id#key
  const pathname = window.location.pathname;
  const isViewRoute = pathname.startsWith("/v/");

  if (isViewRoute) {
    const secretId = pathname.replace("/v/", "").trim();
    const hashKey = window.location.hash.substring(1); // Extract key from '#'

    if (!secretId || !hashKey) {
      hideAllViews();
      burnedView.classList.remove("hidden");
      return;
    }

    // Pre-flight check: Verify secret is still active without triggering burn
    try {
      const res = await fetch(`/api/v1/secret/${encodeURIComponent(secretId)}/meta`);
      const responseBody = await res.json();

      if (!res.ok || !responseBody.success || !responseBody.data.exists) {
        hideAllViews();
        burnedView.classList.remove("hidden");
        return;
      }

      // Valid and active: present the reveal challenge
      hideAllViews();
      revealConfirmView.classList.remove("hidden");

      btnReveal.onclick = async () => {
        btnReveal.disabled = true;
        btnReveal.innerHTML = "<span>Decrypting & Burning...</span>";

        try {
          // 1. Call atomic burn endpoint
          const burnRes = await fetch(`/api/v1/secret/${encodeURIComponent(secretId)}/burn`, {
            method: "POST"
          });
          const burnData = await burnRes.json();

          if (!burnRes.ok || !burnData.success || !burnData.data.ciphertext) {
            hideAllViews();
            burnedView.classList.remove("hidden");
            return;
          }

          // 2. Decrypt locally using WebCrypto and Hash Key
          const plaintext = await ZeroCrypto.decrypt(
            burnData.data.ciphertext,
            burnData.data.iv,
            hashKey
          );

          // 3. Security: Scrub the hash key from address bar and session history
          window.history.replaceState(null, null, "/");

          // 4. Render with textContent strictly (Zero XSS)
          secretContent.textContent = plaintext;
          hideAllViews();
          revealedView.classList.remove("hidden");

        } catch (err) {
          console.error("Local decryption failure:", err);
          alert("Decryption failed. The encryption key may be malformed or tampered with.");
        }
      };

    } catch (err) {
      hideAllViews();
      burnedView.classList.remove("hidden");
    }

    return;
  }

  // --- ALICE (CREATOR WORKFLOW) ---
  btnCreate.onclick = async () => {
    const rawSecret = secretInput.value.trim();
    if (!rawSecret) {
      secretInput.focus();
      return;
    }

    btnCreate.disabled = true;
    btnCreate.innerHTML = "<span>Encrypting In Browser...</span>";

    try {
      // 1. WebCrypto AES-GCM 256-bit client-side encryption
      const { ciphertext, iv, key } = await ZeroCrypto.encrypt(rawSecret);

      // 2. Transmit ONLY ciphertext & IV to server
      const res = await fetch("/api/v1/secret/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ciphertext, iv })
      });

      const responseBody = await res.json();
      if (!res.ok || !responseBody.success || !responseBody.data.id) {
        alert(responseBody.error ? responseBody.error.message : "Failed to store secret on server.");
        btnCreate.disabled = false;
        btnCreate.innerHTML = "<span>🔐 Encrypt & Generate One-Time Link</span>";
        return;
      }

      // 3. Form URL with key strictly after '#'
      const secretUrl = `${window.location.origin}/v/${responseBody.data.id}#${key}`;

      // 4. Update UI
      shareLinkBox.textContent = secretUrl;
      hideAllViews();
      shareView.classList.remove("hidden");

      // Memory wipe of input field
      secretInput.value = "";
      if (charCounter) charCounter.textContent = "0 chars";
    } catch (err) {
      console.error("Encryption error:", err);
      alert("Encryption error: " + err.message);
      btnCreate.disabled = false;
      btnCreate.innerHTML = "<span>🔐 Encrypt & Generate One-Time Link</span>";
    }
  };

  btnCopy.onclick = () => {
    navigator.clipboard.writeText(shareLinkBox.textContent).then(() => {
      btnCopy.innerHTML = "<span>✅ Link Copied!</span>";
      setTimeout(() => {
        btnCopy.innerHTML = "<span>📋 Copy Link to Clipboard</span>";
      }, 2500);
    });
  };

  btnCopySecret.onclick = () => {
    navigator.clipboard.writeText(secretContent.textContent).then(() => {
      btnCopySecret.innerHTML = "<span>✅ Secret Copied to Clipboard!</span>";
      setTimeout(() => {
        btnCopySecret.innerHTML = "<span>📋 Copy Secret to Clipboard</span>";
      }, 2500);
    });
  };

  btnNew.onclick = () => {
    hideAllViews();
    createView.classList.remove("hidden");
    btnCreate.disabled = false;
    btnCreate.innerHTML = "<span>🔐 Encrypt & Generate One-Time Link</span>";
    secretInput.focus();
  };
});
