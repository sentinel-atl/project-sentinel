#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
# Deploy Sentinel infrastructure to Azure
# ═══════════════════════════════════════════════════
# Usage: ./infra/scripts/deploy.sh [dev|staging|prod]

set -euo pipefail

ENVIRONMENT="${1:-prod}"
RESOURCE_GROUP="sentinel-${ENVIRONMENT}-rg"
LOCATION="eastus2"

echo "🔷 Deploying Sentinel infrastructure (${ENVIRONMENT})..."
echo "   Resource group: ${RESOURCE_GROUP}"
echo "   Location: ${LOCATION}"

# Create resource group if it doesn't exist
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none 2>/dev/null || true

# Prompt for PostgreSQL password
read -s -p "PostgreSQL admin password: " PG_PASSWORD
echo

# Deploy Bicep
az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --template-file infra/main.bicep \
  --parameters \
    environment="$ENVIRONMENT" \
    postgresPassword="$PG_PASSWORD" \
  --output table

echo ""
echo "✅ Infrastructure deployed!"
echo ""
echo "Next steps:"
echo "  1. Run database migrations:"
echo "     DATABASE_URL=\$(az deployment group show -g $RESOURCE_GROUP -n main --query properties.outputs.postgresConnectionString.value -o tsv)"
echo "     npx sentinel-migrate \$DATABASE_URL"
echo ""
echo "  2. Build and push worker image:"
echo "     ACR=\$(az deployment group show -g $RESOURCE_GROUP -n main --query properties.outputs.acrLoginServer.value -o tsv)"
echo "     az acr login --name \$ACR"
echo "     docker build -f Dockerfile.worker -t \$ACR/sentinel-worker:latest ."
echo "     docker push \$ACR/sentinel-worker:latest"
