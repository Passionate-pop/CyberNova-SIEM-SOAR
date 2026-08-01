# ── Stage 1: Build ───────────────────────────────────────────
FROM node:25-alpine AS builder

WORKDIR /app

# Install deps first (layer caching — only re-runs when package.json changes)
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund; else npm install --ignore-scripts --no-audit --no-fund; fi

# Copy source and build
# In Docker, the unified nginx always proxies /app/ -> frontend (strips prefix),
# so the HTML must reference /app/assets/... for the browser to request the right path.
# VITE_BASE_PATH=/app/ ensures asset URLs are /app/assets/... in the built HTML.
ARG VITE_BASE_PATH=/app/
ENV VITE_BASE_PATH=/app/
COPY . .
RUN npm run build

# ── Stage 2: Serve ───────────────────────────────────────────
FROM nginx:1.31-alpine

# Drop root — nginx runs as non-root user in alpine by default
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

# Healthcheck for the nginx server
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["nginx", "-t"]

CMD ["nginx", "-g", "daemon off;"]
