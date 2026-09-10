# ==============================================================================
# SentinelAI Web Dashboard — Multi-Stage Hardened Unprivileged Dockerfile
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Production Assets
# ------------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests for deterministic caching
COPY package.json package-lock.json ./
RUN npm ci

# Copy sources and build production bundle
COPY . .
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Unprivileged Nginx Runtime
# ------------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:alpine AS runner

# Copy custom hardened Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy compiled SPA static assets
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose standard unprivileged non-root port
EXPOSE 8080

# Health check probe against local Nginx liveness endpoint
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

# Start Nginx in foreground as default unprivileged user (UID 101)
CMD ["nginx", "-g", "daemon off;"]
