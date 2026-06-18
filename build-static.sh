#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# CyberNova — Build Static Assets
# ═══════════════════════════════════════════════════════════════════
# Builds frontend + marketing page into one directory for nginx to serve.
# Run: bash build-static.sh

set -e

echo "🔧 Step 1/3: Building cybernova-frontend (base=/app/)..."
cd cybernova-frontend
npm install --ignore-scripts 2>&1 | tail -1
VITE_BASE_PATH=/app/ npm run build 2>&1
cd ..

echo "🔧 Step 2/3: Building web-page (static export)..."
cd web-page
npm install --ignore-scripts 2>&1 | tail -1
npm run build 2>&1
cd ..

echo "🔧 Step 3/3: Copying frontend into web-page/out/app/..."
# Remove old app build if it exists
rm -rf web-page/out/app

# Copy the frontend dist into web-page/out/app/
cp -r cybernova-frontend/dist web-page/out/app

# Also copy the nginx-unified.conf to the root for easy access
cp nginx/nginx-unified.conf nginx/nginx.conf 2>/dev/null || true

echo ""
echo "✅ Build complete!"
echo ""
echo "Output structure:"
echo "  web-page/out/           — Marketing site (Next.js static export)"
echo "  web-page/out/app/       — SPA Dashboard (Vite build)"
echo ""
echo "To test locally:"
echo "  cd web-page && npx serve out -p 3000"
echo "  Open http://localhost:3000       — Marketing site"
echo "  Open http://localhost:3000/app/  — Dashboard SPA"
echo ""
echo "For Docker:"
echo "  docker compose up -d"
echo "  Open https://localhost           — Marketing site"
echo "  Open https://localhost/app/      — Dashboard SPA"
