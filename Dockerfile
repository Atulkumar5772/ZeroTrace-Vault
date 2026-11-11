# Multi-stage deterministic production Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY backend/package*.json ./
RUN npm ci --omit=dev

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Copy application code and production dependencies with non-root ownership
COPY --chown=node:node backend ./backend
COPY --chown=node:node --from=builder /app/node_modules ./backend/node_modules
COPY --chown=node:node frontend ./frontend

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "const http=require('http');http.get('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/v1/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "backend/src/server.js"]
