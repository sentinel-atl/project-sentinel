# ═══════════════════════════════════════════════════
# Sentinel STP Server — Production Dockerfile
# ═══════════════════════════════════════════════════
# Multi-stage build for minimal image size.
#
# Build:    docker build -t sentinel-server .
# Run:      docker run -p 3000:3000 sentinel-server
# Compose:  docker compose up

FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json turbo.json ./
COPY packages/ packages/

# Install dependencies and build
RUN npm ci --ignore-scripts && \
    npx turbo run build --filter=@sentinel-atl/server...

# ─── Production stage ─────────────────────────────
FROM node:20-alpine AS runner

WORKDIR /app

# Non-root user for security
RUN addgroup --system sentinel && adduser --system --ingroup sentinel sentinel

# Copy built artifacts
COPY --from=builder /app/package.json ./
COPY --from=builder /app/package-lock.json ./
COPY --from=builder /app/packages/core/package.json packages/core/package.json
COPY --from=builder /app/packages/core/dist packages/core/dist
COPY --from=builder /app/packages/audit/package.json packages/audit/package.json
COPY --from=builder /app/packages/audit/dist packages/audit/dist
COPY --from=builder /app/packages/reputation/package.json packages/reputation/package.json
COPY --from=builder /app/packages/reputation/dist packages/reputation/dist
COPY --from=builder /app/packages/revocation/package.json packages/revocation/package.json
COPY --from=builder /app/packages/revocation/dist packages/revocation/dist
COPY --from=builder /app/packages/handshake/package.json packages/handshake/package.json
COPY --from=builder /app/packages/handshake/dist packages/handshake/dist
COPY --from=builder /app/packages/safety/package.json packages/safety/package.json
COPY --from=builder /app/packages/safety/dist packages/safety/dist
COPY --from=builder /app/packages/offline/package.json packages/offline/package.json
COPY --from=builder /app/packages/offline/dist packages/offline/dist
COPY --from=builder /app/packages/attestation/package.json packages/attestation/package.json
COPY --from=builder /app/packages/attestation/dist packages/attestation/dist
COPY --from=builder /app/packages/mcp-plugin/package.json packages/mcp-plugin/package.json
COPY --from=builder /app/packages/mcp-plugin/dist packages/mcp-plugin/dist
COPY --from=builder /app/packages/gateway/package.json packages/gateway/package.json
COPY --from=builder /app/packages/gateway/dist packages/gateway/dist
COPY --from=builder /app/packages/sdk/package.json packages/sdk/package.json
COPY --from=builder /app/packages/sdk/dist packages/sdk/dist
COPY --from=builder /app/packages/server/package.json packages/server/package.json
COPY --from=builder /app/packages/server/dist packages/server/dist

# Install production deps only
RUN npm ci --omit=dev --ignore-scripts

# Create data directory for audit logs
RUN mkdir -p /data && chown sentinel:sentinel /data

USER sentinel

ENV NODE_ENV=production
ENV SENTINEL_PORT=3000
ENV SENTINEL_HOST=0.0.0.0
ENV SENTINEL_DATA_DIR=/data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/.well-known/sentinel-configuration || exit 1

CMD ["node", "packages/server/dist/index.js"]
