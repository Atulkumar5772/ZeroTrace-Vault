const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const routes = require('./routes');
const RateLimiter = require('./rateLimiter');
const vaultStore = require('./vaultStore');

const app = express();
const PORT = process.env.PORT || 3000;

// Production Security Headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  },
  crossOriginEmbedderPolicy: false,
  xContentTypeOptions: true, // Prevent MIME sniffing
  xFrameOptions: { action: 'deny' }, // Anti-Clickjacking
  hsts: { maxAge: 31536000, includeSubDomains: true }
}));

// CORS Configuration (Strict Local & Same-Origin)
app.use(cors({
  origin: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type']
}));

// JSON body parsing with strict size ceiling
app.use(express.json({ limit: '600kb' }));

// Anti-Brute-Force Rate Limiter (max 30 requests/min per IP)
const rateLimiter = new RateLimiter(30, 60 * 1000);
app.use('/api/', rateLimiter.middleware());

// REST API routes
app.use('/api/v1', routes);

// Serve Static Frontend UI
const frontendPublicPath = path.join(__dirname, '../../frontend/public');
app.use(express.static(frontendPublicPath));

// API 404 handler (prevent SPA fallback for API routes!)
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: "ENDPOINT_NOT_FOUND",
      message: "The requested API endpoint was not found."
    }
  });
});

// SPA Fallback for /v/:id routes (only non-API)
app.get('*', (req, res) => {
  res.sendFile(path.join(frontendPublicPath, 'index.html'));
});

// Global Error Catcher
app.use((err, req, res, next) => {
  console.error("Unhandled Server Error:", err);
  res.status(500).json({
    success: false,
    error: {
      code: "INTERNAL_ERROR",
      message: "An internal server error occurred."
    }
  });
});

const server = app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🛡️  ZeroTrace-Vault Daemon active on port ${PORT}`);
  console.log(`🔒 Zero-Knowledge Ephemeral Storage: READY`);
  console.log(`🔥 Single-View Atomic Burn-on-Read: ARMED`);
  console.log(`🌐 Web App running at: http://localhost:${PORT}`);
  console.log(`====================================================`);
});

// Graceful Memory Shredding on Shutdown (SIGINT, SIGTERM)
function handleShutdown(signal) {
  console.log(`\nReceived ${signal}. Shredding all active vault records from memory...`);
  vaultStore.purgeAll();
  server.close(() => {
    console.log("Vault memory cleanly shredded. Server shut down.");
    process.exit(0);
  });
}

process.on('SIGINT', () => handleShutdown('SIGINT'));
process.on('SIGTERM', () => handleShutdown('SIGTERM'));
