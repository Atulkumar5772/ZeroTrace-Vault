/**
 * ZeroTrace Frontend Application Logic
 * - Preserves intentional whitespace in secrets (never trims plaintext)
 * - Scrubs #key fragment from address bar/history immediately on load
 * - Validates WebCrypto availability and key integrity BEFORE burning server secrets
 * - Distinguishes 404/burned from 429 rate-limits, 5xx, and network failures
 */

document.addEventListener("DOMContentLoaded", async () => {
  const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  const createView = document.getElementById("create-view");
  const shareView = document.getElementById("share-view");
  const revealConfirmView = document.getElementById("reveal-confirm-view");
  const revealedView = document.getElementById("revealed-view");
  const burnedView = document.getElementById("burned-view");
  const invalidKeyView = document.getElementById("invalid-key-view");

  const errorBanner = document.getElementById("error-banner");
  const errorBannerTitle = document.getElementById("error-banner-title");
  const errorBannerMessage = document.getElementById("error-banner-message");

  const secretInput = document.getElementById("secret-input");
  const charCounter = document.getElementById("char-counter");
  const btnCreate = document.getElementById("btn-create");
  const shareLinkBox = document.getElementById("share-link");
  const btnCopy = document.getElementById("btn-copy");
  const btnNew = document.getElementById("btn-new");
  const btnReveal = document.getElementById("btn-reveal");
  const expiryCountdown = document.getElementById("expiry-countdown");
  const secretContent = document.getElementById("secret-content");
  const btnCopySecret = document.getElementById("btn-copy-secret");

  let countdownInterval = null;

  function hideAllViews() {
    createView.classList.add("hidden");
    shareView.classList.add("hidden");
    revealConfirmView.classList.add("hidden");
    revealedView.classList.add("hidden");
    burnedView.classList.add("hidden");
    if (invalidKeyView) invalidKeyView.classList.add("hidden");
  }

  function showErrorBanner(title, message) {
    if (!errorBanner) return;
    errorBannerTitle.textContent = title;
    errorBannerMessage.textContent = message;
    errorBanner.classList.remove("hidden");
  }

  function hideErrorBanner() {
    if (errorBanner) errorBanner.classList.add("hidden");
  }

  async function safeParseJson(res) {
    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      return null;
    }
    try {
      return await res.json();
    } catch (_) {
      return null;
    }
  }

  function formatDuration(ms) {
    const totalSeconds = Math.max(0, Math.floor(ms / 1000));
    const hrs = String(Math.floor(totalSeconds / 3600)).padStart(2, "0");
    const mins = String(Math.floor((totalSeconds % 3600) / 60)).padStart(2, "0");
    const secs = String(totalSeconds % 60).padStart(2, "0");
    return `${hrs}:${mins}:${secs}`;
  }

  function startCountdown(expiresAt) {
    if (!expiryCountdown || !expiresAt) return;
    if (countdownInterval) clearInterval(countdownInterval);

    const update = () => {
      const remaining = expiresAt - Date.now();
      if (remaining <= 0) {
        clearInterval(countdownInterval);
        hideAllViews();
        burnedView.classList.remove("hidden");
        return;
      }
      expiryCountdown.textContent = `⏳ Auto-expires in: ${formatDuration(remaining)}`;
      expiryCountdown.classList.remove("hidden");
    };

    update();
    countdownInterval = setInterval(update, 1000);
  }

  async function copyToClipboard(text, buttonEl, successLabel, defaultHtml) {
    let copied = false;
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(text);
        copied = true;
      }
    } catch (_) {
      copied = false;
    }

    if (!copied) {
      // Fallback for plain-HTTP non-localhost origins where navigator.clipboard is undefined
      try {
        const helper = document.createElement("textarea");
        helper.value = text;
        helper.setAttribute("readonly", "");
        helper.className = "hidden";
        document.body.appendChild(helper);
        helper.classList.remove("hidden");
        helper.select();
        copied = document.execCommand("copy");
        document.body.removeChild(helper);
      } catch (_) {
        copied = false;
      }
    }

    if (copied) {
      buttonEl.textContent = successLabel;
    } else {
      buttonEl.textContent = "⚠️ Select & Copy Manually (Ctrl+C)";
    }

    setTimeout(() => {
      buttonEl.innerHTML = defaultHtml;
    }, 2500);
  }

  // Warn immediately if WebCrypto is unavailable (e.g. plain HTTP over LAN IP)
  if (!ZeroCrypto.isSupported()) {
    showErrorBanner(
      "Secure Context Required:",
      "Browser encryption (WebCrypto) requires HTTPS or localhost. Please open this app over HTTPS."
    );
    if (btnCreate) btnCreate.disabled = true;
  }

  // Byte counter & Ctrl+Enter shortcut
  if (secretInput && charCounter) {
    const updateByteCounter = () => {
      const bytes = ZeroCrypto.getUtf8ByteLength(secretInput.value);
      const maxKb = Math.floor(ZeroCrypto.MAX_SECRET_BYTES / 1024);
      const isOver = bytes > ZeroCrypto.MAX_SECRET_BYTES;
      charCounter.textContent = `${bytes.toLocaleString()} bytes / ${maxKb} KB`;
      charCounter.classList.toggle("char-counter-danger", isOver);
      if (btnCreate && ZeroCrypto.isSupported()) {
        btnCreate.disabled = isOver;
      }
    };

    secretInput.addEventListener("input", updateByteCounter);
    secretInput.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        btnCreate.click();
      }
    });
  }

  // Route Handling: /v/:id#<key>
  const pathname = window.location.pathname;
  const isViewRoute = pathname.startsWith("/v/");

  if (isViewRoute) {
    const secretId = pathname.replace(/^\/v\/+/, "").replace(/\/+$/, "").trim();
    const rawHash = window.location.hash ? window.location.hash.substring(1) : "";
    const hashKey = rawHash.trim();

    // Immediately scrub the #key fragment from browser address bar & session history
    if (window.location.hash) {
      window.history.replaceState(null, "", `/v/${encodeURIComponent(secretId)}`);
    }

    if (!secretId || !UUID_V4_REGEX.test(secretId)) {
      hideAllViews();
      burnedView.classList.remove("hidden");
      return;
    }

    // Validate WebCrypto availability and key BEFORE hitting/burning the secret
    if (!ZeroCrypto.isSupported()) {
      hideAllViews();
      showErrorBanner(
        "Secure Context Required:",
        "Cannot decrypt over insecure HTTP. Please open this link via HTTPS."
      );
      return;
    }

    if (!hashKey || !ZeroCrypto.isValidKey(hashKey)) {
      hideAllViews();
      if (invalidKeyView) {
        invalidKeyView.classList.remove("hidden");
      } else {
        burnedView.classList.remove("hidden");
      }
      return;
    }

    // Pre-flight check: Verify secret is active without burning it
    try {
      const res = await fetch(`/api/v1/secret/${encodeURIComponent(secretId)}/meta`);
      const responseBody = await safeParseJson(res);

      if (res.status === 404 || res.status === 400) {
        hideAllViews();
        burnedView.classList.remove("hidden");
        return;
      }

      if (!res.ok || !responseBody || !responseBody.success || !responseBody.data.exists) {
        hideAllViews();
        const msg = (responseBody && responseBody.error && responseBody.error.message) ||
          `Server temporarily unavailable (HTTP ${res.status}). Your secret was NOT burned — please retry.`;
        showErrorBanner("Temporary Error:", msg);
        return;
      }

      // Active secret: show reveal confirmation + live TTL countdown
      hideAllViews();
      revealConfirmView.classList.remove("hidden");
      startCountdown(responseBody.data.expiresAt);

      btnReveal.onclick = async () => {
        hideErrorBanner();
        btnReveal.disabled = true;
        btnReveal.textContent = "Decrypting & Burning...";

        const resetRevealButton = () => {
          btnReveal.disabled = false;
          btnReveal.innerHTML = "<span>🔥 Click to Reveal &amp; Burn Secret</span>";
        };

        try {
          const burnRes = await fetch(`/api/v1/secret/${encodeURIComponent(secretId)}/burn`, {
            method: "POST"
          });
          const burnData = await safeParseJson(burnRes);

          if (burnRes.status === 404 || burnRes.status === 400) {
            if (countdownInterval) clearInterval(countdownInterval);
            hideAllViews();
            burnedView.classList.remove("hidden");
            return;
          }

          if (!burnRes.ok || !burnData || !burnData.success || !burnData.data || !burnData.data.ciphertext) {
            const msg = (burnData && burnData.error && burnData.error.message) ||
              `Request failed (HTTP ${burnRes.status}). Please try again.`;
            showErrorBanner("Retrieval Interrupted:", msg);
            resetRevealButton();
            return;
          }

          const plaintext = await ZeroCrypto.decrypt(
            burnData.data.ciphertext,
            burnData.data.iv,
            hashKey
          );

          if (countdownInterval) clearInterval(countdownInterval);
          window.history.replaceState(null, "", "/");

          // Strictly textContent (Zero XSS)
          secretContent.textContent = plaintext;
          hideAllViews();
          revealedView.classList.remove("hidden");
        } catch (err) {
          console.error("Decryption / network error:", err);
          showErrorBanner(
            "Decryption or Network Failure:",
            err.message || "Unable to decrypt payload. Please check your connection or link integrity."
          );
          resetRevealButton();
        }
      };
    } catch (err) {
      hideAllViews();
      showErrorBanner(
        "Network Error:",
        "Could not reach ZeroTrace-Vault server. Your secret was NOT burned — please refresh to retry."
      );
    }

    return;
  }

  // --- ALICE (CREATOR WORKFLOW) ---
  btnCreate.onclick = async () => {
    hideErrorBanner();
    const rawSecret = secretInput.value; // Preserve intentional leading/trailing whitespace
    if (rawSecret.length === 0) {
      secretInput.focus();
      return;
    }

    const byteLen = ZeroCrypto.getUtf8ByteLength(rawSecret);
    if (byteLen > ZeroCrypto.MAX_SECRET_BYTES) {
      showErrorBanner("Payload Too Large:", "Secret exceeds the 512 KB maximum limit.");
      return;
    }

    btnCreate.disabled = true;
    btnCreate.textContent = "Encrypting In Browser...";

    const resetCreateButton = () => {
      btnCreate.disabled = false;
      btnCreate.innerHTML = "<span>🔐 Encrypt &amp; Generate One-Time Link</span>";
    };

    try {
      const { ciphertext, iv, key } = await ZeroCrypto.encrypt(rawSecret);

      const res = await fetch("/api/v1/secret/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ciphertext, iv })
      });

      const responseBody = await safeParseJson(res);
      if (!res.ok || !responseBody || !responseBody.success || !responseBody.data || !responseBody.data.id) {
        const msg = (responseBody && responseBody.error && responseBody.error.message) ||
          `Server returned HTTP ${res.status}. Please try again.`;
        showErrorBanner("Storage Failed:", msg);
        resetCreateButton();
        return;
      }

      const secretUrl = `${window.location.origin}/v/${responseBody.data.id}#${key}`;

      shareLinkBox.textContent = secretUrl;
      hideAllViews();
      shareView.classList.remove("hidden");

      secretInput.value = "";
      if (charCounter) {
        charCounter.textContent = "0 bytes / 512 KB";
        charCounter.classList.remove("char-counter-danger");
      }
    } catch (err) {
      console.error("Encryption / upload error:", err);
      showErrorBanner("Encryption Error:", err.message || "Unexpected failure during encryption.");
      resetCreateButton();
    }
  };

  btnCopy.onclick = () => {
    copyToClipboard(
      shareLinkBox.textContent,
      btnCopy,
      "✅ Link Copied!",
      "<span>📋 Copy Link to Clipboard</span>"
    );
  };

  btnCopySecret.onclick = () => {
    copyToClipboard(
      secretContent.textContent,
      btnCopySecret,
      "✅ Secret Copied to Clipboard!",
      "<span>📋 Copy Secret to Clipboard</span>"
    );
  };

  btnNew.onclick = () => {
    hideErrorBanner();
    hideAllViews();
    createView.classList.remove("hidden");
    btnCreate.disabled = !ZeroCrypto.isSupported();
    btnCreate.innerHTML = "<span>🔐 Encrypt &amp; Generate One-Time Link</span>";
    secretInput.focus();
  };
});
