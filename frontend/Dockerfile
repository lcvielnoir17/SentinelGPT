# =============================================================================
# Multi-stage Dockerfile for the SentinelGPT frontend (Phase 0 skeleton)
# Build: Vite/TypeScript -> static assets; Serve: nginx (unprivileged, :8080)
# =============================================================================

FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
# npm ci = reproducible install strictly from package-lock.json
RUN npm ci

COPY . .
RUN npm run build

# -----------------------------------------------------------------------------
# Runtime Stage — non-root nginx serving the built SPA and proxying /api
# -----------------------------------------------------------------------------
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

USER 101

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/login || exit 1

CMD ["nginx", "-g", "daemon off;"]
