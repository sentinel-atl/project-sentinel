// PostgreSQL Flexible Server — B1ms tier
// Cheapest production-ready tier: 1 vCore, 2GB RAM, 32GB storage

@description('Server name')
param name string

@description('Azure region')
param location string

@description('Admin login')
param administratorLogin string

@secure()
@description('Admin password')
param administratorPassword string

resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' = {
  name: name
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '16'
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorPassword
    storage: {
      storageSizeGB: 32
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
  }
}

// Allow Azure services to connect
resource firewallRule 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-12-01-preview' = {
  parent: postgres
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

// Create the sentinel database
resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-12-01-preview' = {
  parent: postgres
  name: 'sentinel'
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

output fqdn string = postgres.properties.fullyQualifiedDomainName
output connectionString string = 'postgresql://${administratorLogin}:${administratorPassword}@${postgres.properties.fullyQualifiedDomainName}:5432/sentinel?sslmode=require'
