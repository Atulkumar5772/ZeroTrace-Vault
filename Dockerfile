# Multi-stage production Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY backend/package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Copy node modules from builder
COPY --from=builder /app/node_modules ./backend/node_modules
COPY backend ./backend
COPY frontend ./frontend
COPY cli ./cli

# Non-root secure user
USER node

EXPOSE 3000

CMD ["node", "backend/src/server.js"]
