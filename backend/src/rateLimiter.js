/**
 * In-Memory Sliding Window / Token Bucket Rate Limiter
 * Protects endpoints from brute-force UUID harvesting & DoS
 */

class RateLimiter {
  constructor(limit = 30, windowMs = 60 * 1000) {
    this.limit = limit; // max 30 requests per minute per IP
    this.windowMs = windowMs;
    this.hits = new Map();

    // Auto-cleanup stale IPs every 2 minutes
    setInterval(() => this.cleanup(), 2 * 60 * 1000).unref();
  }

  middleware() {
    return (req, res, next) => {
      const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
      const now = Date.now();

      let clientRecord = this.hits.get(ip);
      if (!clientRecord) {
        clientRecord = { count: 1, resetTime: now + this.windowMs };
        this.hits.set(ip, clientRecord);
        return next();
      }

      if (now > clientRecord.resetTime) {
        clientRecord.count = 1;
        clientRecord.resetTime = now + this.windowMs;
        return next();
      }

      clientRecord.count++;
      if (clientRecord.count > this.limit) {
        return res.status(429).json({
          error: "Too Many Requests",
          message: "Rate limit exceeded. Please wait a moment before trying again."
        });
      }

      next();
    };
  }

  cleanup() {
    const now = Date.now();
    for (const [ip, record] of this.hits.entries()) {
      if (now > record.resetTime) {
        this.hits.delete(ip);
      }
    }
  }
}

module.exports = RateLimiter;
