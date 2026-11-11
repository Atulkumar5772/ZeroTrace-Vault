const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const routes = require('./routes');
const RateLimiter = require('./rateLimiter');
const vaultStore = require('./vaultStore');

function createApp(options = {}) {
  const app = express();
  const isTrustProxy = options.trustProxy ?? (process.env.TRUST_PROXY === 'true' || process.env.RENDER === 'true');
  const useHttpsHeaders = options.forceHttps ?? (process.env.FORCE_HTTPS === 'true' || process.env.RENDER === 'true');
  const allowedOriginsEnv = (process.env.ALLOWED_ORIGINS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

  if (isTrustProxy) {
    app.set('trust proxy', 1);
  }

  // Strict Production Security Headers via Helmet (no 'unsafe-inline')
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        ...(useHttpsHeaders ? { upgradeInsecureRequests: [] } : { upgradeInsecureRequests: null })
      }
    },
    crossOriginEmbedderPolicy: false,
    xContentTypeOptions: true,
    xFrameOptions: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: useHttpsHeaders ? { maxAge: 31536000, includeSubDomains: true } : false
  }));

  // Strict Same-Origin / Explicit Allowlist CORS (Never reflects arbitrary origins)
  app.use(cors((req, callback) => {
    const origin = req.header('Origin');
    if (!origin) {
      return callback(null, { origin: false });
    }

    let isAllowed = false;
    if (allowedOriginsEnv.length > 0) {
      isAllowed = allowedOriginsEnv.includes(origin);
    } else {
      try {
        const originUrl = new URL(origin);
        const reqHost = req.get('host');
        isAllowed = Boolean(reqHost && originUrl.host === reqHost);
      } catch (_) {
        isAllowed = false;
      }
    }

    return callback(null, {
      origin: isAllowed,
      methods: ['GET', 'POST'],
      allowedHeaders: ['Content-Type']
    });
  }));

  // JSON body parsing with ceiling aligned to 512 KB secret + Base64URL overhead
  app.use(express.json({ limit: '750kb' }));

  // Sliding-window rate limiter on secret endpoints only (healthcheck remains unthrottled)
  const rateLimiter = options.rateLimiter || new RateLimiter(
    Number(process.env.RATE_LIMIT_MAX) || 30,
    Number(process.env.RATE_LIMIT_WINDOW_MS) || 60 * 1000
  );
  app.locals.rateLimiter = rateLimiter;
  app.use('/api/v1/secret', rateLimiter.middleware());

  // REST API routes
  app.use('/api/v1', routes);

  // API 404 handler (covers both /api and /api/*)
  app.use('/api', (req, res) => {
    res.status(404).json({
      success: false,
      error: {
        code: "ENDPOINT_NOT_FOUND",
        message: "The requested API endpoint was not found."
      },
      timestamp: new Date().toISOString()
    });
  });

  // Avoid serving index.html for favicon.ico probes
  app.get('/favicon.ico', (req, res) => {
    res.status(204).end();
  });

  // Serve Static Frontend Assets (CSS/JS cached normally, HTML always no-store)
  const frontendPublicPath = path.join(__dirname, '../../frontend/public');
  app.use(express.static(frontendPublicPath, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      }
    }
  }));

  // SPA Fallback only for UI routes (/ and /v/:id), never for API/unknown static files
  app.get(['/', '/v/*'], (req, res) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.sendFile(path.join(frontendPublicPath, 'index.html'));
  });

  // Remaining unmatched paths return 404
  app.use((req, res) => {
    res.status(404).json({
      success: false,
      error: {
        code: "NOT_FOUND",
        message: "Resource not found."
      },
      timestamp: new Date().toISOString()
    });
  });

  // Global Error Catcher preserving HTTP status codes (400 malformed JSON, 413 payload too large, etc.)
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({
        success: false,
        error: {
          code: "INVALID_JSON",
          message: "Malformed JSON request payload."
        },
        timestamp: new Date().toISOString()
      });
    }

    if (err.type === 'entity.too.large') {
      return res.status(413).json({
        success: false,
        error: {
          code: "PAYLOAD_TOO_LARGE",
          message: "Request payload exceeds the maximum allowable size."
        },
        timestamp: new Date().toISOString()
      });
    }

    const status = err.status || err.statusCode || 500;
    if (status >= 500) {
      console.error("Unhandled Server Error:", err.message);
    }

    return res.status(status).json({
      success: false,
      error: {
        code: status >= 500 ? "INTERNAL_ERROR" : "REQUEST_ERROR",
        message: status >= 500 ? "An internal server error occurred." : err.message
      },
      timestamp: new Date().toISOString()
    });
  });

  return app;
}

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  const app = createApp();

  const server = app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🛡️  ZeroTrace-Vault Daemon active on port ${PORT}`);
    console.log(`🔒 Zero-Knowledge Ephemeral Storage: READY`);
    console.log(`🔥 Single-View Atomic Burn-on-Read: ARMED`);
    console.log(`🌐 Web App running at: http://localhost:${PORT}`);
    console.log(`====================================================`);
  });

  server.on('error', (err) => {
    console.error(`❌ Server failed to bind port ${PORT}:`, err.message);
    app.locals.rateLimiter.stop();
    vaultStore.stop();
    process.exit(1);
  });

  let shuttingDown = false;
  function handleShutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\nReceived ${signal}. Releasing active vault records from memory...`);
    app.locals.rateLimiter.stop();
    vaultStore.stop();
    server.close(() => {
      console.log("Vault store cleared. Server shut down.");
      process.exit(0);
    });
  }

  process.on('SIGINT', () => handleShutdown('SIGINT'));
  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
}

module.exports = { createApp };
