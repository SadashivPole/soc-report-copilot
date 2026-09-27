# ---- SOC Report Copilot API ----
FROM node:20-alpine
WORKDIR /app

# Install deps first for better layer caching
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# App source
COPY . .

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

# Container-level readiness probe (busybox wget ships with the alpine image).
# /api/health returns 503 when the database is unreachable, so the container is
# marked unhealthy and the restart policy / orchestrator can react.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD wget -qO- http://127.0.0.1:3000/api/health | grep -q '"status":"ok"' || exit 1

# Entry waits for the DB, runs migrations, then boots the API (see src/index.js)
CMD ["node", "src/index.js"]
