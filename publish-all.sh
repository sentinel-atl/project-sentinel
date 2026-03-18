#!/bin/bash
set -e

echo "Publishing all @sentinel-atl packages to npm at 0.2.0"
echo "You'll need to approve 2FA in the browser for each package."
echo ""

# New packages (need --access public)
NEW_PACKAGES="store telemetry budget mcp-proxy approval"

# Updated packages (already public)
UPDATED_PACKAGES="core handshake reputation audit recovery revocation attestation stepup offline safety adapters mcp-plugin sdk cli hsm dashboard gateway server conformance"

echo "=== Publishing NEW packages ==="
for pkg in $NEW_PACKAGES; do
  echo ""
  echo "📦 Publishing @sentinel-atl/$pkg..."
  cd "packages/$pkg"
  npm publish --access public
  cd ../..
  echo "✅ @sentinel-atl/$pkg published!"
done

echo ""
echo "=== Publishing UPDATED packages ==="
for pkg in $UPDATED_PACKAGES; do
  echo ""
  echo "📦 Publishing @sentinel-atl/$pkg..."
  cd "packages/$pkg"
  npm publish
  cd ../..
  echo "✅ @sentinel-atl/$pkg published!"
done

echo ""
echo "📦 Publishing create-sentinel-app..."
cd packages/create-sentinel-app
npm publish
cd ../..
echo "✅ create-sentinel-app published!"

echo ""
echo "🎉 All packages published to npm at 0.2.0!"
