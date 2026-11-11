/**
 * Bounded Sliding-Window Log Rate Limiter
 *
 * Guarantees:
 * - True sliding window (prevents 2x boundary bursts across fixed-window edges)
 * - Bounded IP table size (prevents OOM DoS under spoofed IP floods)
 * - Emits standard RateLimit-* and Retry-After HTTP headers
 */

class RateLimiter {
  constructor(limit = 30, windowMs = 60 * 1000, maxTrackedIps = 50000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.maxTrackedIps = maxTrackedIps;
    this.hits = new Map(); // ip -> number[] (ascending timestamps)

    // Auto-cleanup stale IP buckets every 2 minutes
    this.cleanupInterval = setInterval(() => this.cleanup(), 2 * 60 * 1000);
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  middleware() {
    return (req, res, next) => {
      const ip = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
      const now = Date.now();
      const windowStart = now - this.windowMs;

      let timestamps = this.hits.get(ip);

      if (!timestamps) {
        if (this.hits.size >= this.maxTrackedIps) {
          this.cleanup(now);
          if (this.hits.size >= this.maxTrackedIps) {
            const oldestKey = this.hits.keys().next().value;
            if (oldestKey !== undefined) {
              this.hits.delete(oldestKey);
            }
          }
        }
        timestamps = [];
      } else {
        // Refresh insertion order for LRU eviction when bounded
        this.hits.delete(ip);
      }

      // Prune expired timestamps outside sliding window
      while (timestamps.length > 0 && timestamps[0] <= windowStart) {
        timestamps.shift();
      }

      if (timestamps.length >= this.limit) {
        const oldestInWindow = timestamps[0];
        const retryAfterSec = Math.max(1, Math.ceil((oldestInWindow + this.windowMs - now) / 1000));
        this.hits.set(ip, timestamps);

        res.setHeader('RateLimit-Limit', String(this.limit));
        res.setHeader('RateLimit-Remaining', '0');
        res.setHeader('RateLimit-Reset', String(retryAfterSec));
        res.setHeader('Retry-After', String(retryAfterSec));

        return res.status(429).json({
          success: false,
          error: {
            code: "RATE_LIMIT_EXCEEDED",
            message: "Rate limit exceeded. Please wait a moment before trying again."
          },
          timestamp: new Date().toISOString()
        });
      }

      timestamps.push(now);
      this.hits.set(ip, timestamps);

      const remaining = Math.max(0, this.limit - timestamps.length);
      const resetSec = Math.max(1, Math.ceil((timestamps[0] + this.windowMs - now) / 1000));
      res.setHeader('RateLimit-Limit', String(this.limit));
      res.setHeader('RateLimit-Remaining', String(remaining));
      res.setHeader('RateLimit-Reset', String(resetSec));

      next();
    };
  }

  cleanup(now = Date.now()) {
    const windowStart = now - this.windowMs;
    for (const [ip, timestamps] of this.hits.entries()) {
      while (timestamps.length > 0 && timestamps[0] <= windowStart) {
        timestamps.shift();
      }
      if (timestamps.length === 0) {
        this.hits.delete(ip);
      }
    }
  }

  stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.hits.clear();
  }
}

module.exports = RateLimiter;
