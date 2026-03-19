// ═══════════════════════════════════════════════════
// Sentinel Data Moat — Azure Infrastructure (Bicep)
// ═══════════════════════════════════════════════════
// Deploy: az deployment group create -g sentinel-rg -f infra/main.bicep
//
// Resources:
//   - PostgreSQL Flexible Server (B1ms)
//   - Storage Account (Blob + Queue)
//   - Container Registry
//   - Container App (Public API)
//   - Key Vault (Secrets)

targetScope = 'resourceGroup'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Environment name suffix')
@allowed(['dev', 'staging', 'prod'])
param environment string = 'prod'

@secure()
@description('PostgreSQL admin password')
param postgresPassword string

@description('PostgreSQL admin username')
param postgresAdmin string = 'sentinel_admin'

var prefix = 'sentinel-${environment}'
var uniqueSuffix = uniqueString(resourceGroup().id)

// ─── Key Vault ────────────────────────────────────────────────

module keyVault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    name: '${prefix}-kv-${uniqueSuffix}'
    location: location
  }
}

// ─── PostgreSQL Flexible Server ──────────────────────────────

module postgres 'modules/postgres.bicep' = {
  name: 'postgres'
  params: {
    name: '${prefix}-pg-${uniqueSuffix}'
    location: location
    administratorLogin: postgresAdmin
    administratorPassword: postgresPassword
  }
}

// ─── Storage Account (Blob + Queue) ─────────────────────────

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    name: 'sentinel${uniqueSuffix}'
    location: location
  }
}

// ─── Container Registry ──────────────────────────────────────

module acr 'modules/container-registry.bicep' = {
  name: 'acr'
  params: {
    name: 'sentinel${uniqueSuffix}'
    location: location
  }
}

// ─── Container App (Public API) ──────────────────────────────

module containerApp 'modules/container-app.bicep' = {
  name: 'container-app'
  params: {
    name: '${prefix}-api'
    location: location
    acrLoginServer: acr.outputs.loginServer
    postgresConnectionString: postgres.outputs.connectionString
    storageConnectionString: storage.outputs.connectionString
  }
}

// ─── Outputs ─────────────────────────────────────────────────

output postgresHost string = postgres.outputs.fqdn
output storageAccountName string = storage.outputs.accountName
output acrLoginServer string = acr.outputs.loginServer
output apiUrl string = containerApp.outputs.fqdn
output keyVaultName string = keyVault.outputs.name
