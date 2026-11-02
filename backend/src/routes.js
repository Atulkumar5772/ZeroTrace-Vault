const express = require('express');
const router = express.Router();
const vaultStore = require('./vaultStore');

/**
 * Standard API Response Envelope
 */
function sendSuccess(res, statusCode, data, message = null) {
  return res.status(statusCode).json({
    success: true,
    data,
    message,
    timestamp: new Date().toISOString()
  });
}

function sendError(res, statusCode, errorCode, message) {
  return res.status(statusCode).json({
    success: false,
    error: {
      code: errorCode,
      message: message
    },
    timestamp: new Date().toISOString()
  });
}

// POST /api/v1/secret/create
router.post('/secret/create', (req, res) => {
  try {
    const { ciphertext, iv, salt } = req.body;

    if (!ciphertext || !iv) {
      return sendError(res, 400, "MISSING_PAYLOAD", "Ciphertext and IV are strictly required.");
    }

    if (!vaultStore.isValidPayload(ciphertext, iv)) {
      return sendError(res, 422, "INVALID_FORMAT", "Payload fails cryptographic format or size specifications.");
    }

    const id = vaultStore.storeSecret({ ciphertext, iv, salt });

    return sendSuccess(res, 201, { id }, "Secret stored securely. One-time retrieval armed.");
  } catch (err) {
    return sendError(res, 500, "SERVER_FAULT", "Unable to store secret at this moment.");
  }
});

// GET /api/v1/secret/:id/meta
// Pre-flight check without burning (prevents social media link crawler premature destruction)
router.get('/secret/:id/meta', (req, res) => {
  const { id } = req.params;

  if (!vaultStore.isValidId(id)) {
    return sendError(res, 400, "INVALID_ID", "Invalid secret identifier format.");
  }

  const meta = vaultStore.checkMetadata(id);

  if (!meta) {
    return sendError(res, 404, "NOT_FOUND_OR_BURNED", "Secret does not exist or has already been burned.");
  }

  return sendSuccess(res, 200, {
    exists: true,
    createdAt: meta.createdAt,
    expiresAt: meta.expiresAt
  });
});

// POST /api/v1/secret/:id/burn
// Atomic single-view retrieval and permanent eradication
router.post('/secret/:id/burn', (req, res) => {
  const { id } = req.params;

  if (!vaultStore.isValidId(id)) {
    return sendError(res, 400, "INVALID_ID", "Invalid secret identifier format.");
  }

  const payload = vaultStore.burnAndRetrieve(id);

  if (!payload) {
    return sendError(res, 404, "ALREADY_BURNED", "This secret has already been consumed or has expired. It leaves zero trace on our servers.");
  }

  return sendSuccess(res, 200, payload, "Payload retrieved and permanently purged from server memory.");
});

// GET /api/v1/health
router.get('/health', (req, res) => {
  return sendSuccess(res, 200, {
    service: "ZeroTrace-Vault",
    status: "HEALTHY",
    stats: vaultStore.getStats()
  });
});

module.exports = router;
