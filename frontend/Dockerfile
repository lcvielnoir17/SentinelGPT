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
# The proxy upstream is resolved at container start via envsubst from
# API_UPSTREAM (http://api:8000 in Compose; the API's Cloud Run URL in the
# cloud deployment). See nginx.conf.template. The stock default.conf is
# removed at build time (root) so the unprivileged envsubst step can create
# a fresh, user-owned default.conf at container start.
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime

COPY nginx.conf.template /etc/nginx/templates/default.conf.template
RUN rm -f /etc/nginx/conf.d/default.conf
ENV API_UPSTREAM=http://api:8000
COPY --from=build /app/dist /usr/share/nginx/html

USER 101

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/login || exit 1

CMD ["nginx", "-g", "daemon off;"]
