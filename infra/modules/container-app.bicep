// Container App — Public API (Registry + Trust Scores)
// Runs on consumption plan, scales to zero when idle

@description('App name')
param name string

@description('Azure region')
param location string

@description('ACR login server')
param acrLoginServer string

@description('PostgreSQL connection string')
@secure()
param postgresConnectionString string

@description('Storage connection string')
@secure()
param storageConnectionString string

// Container App Environment
resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${name}-env'
  location: location
  properties: {
    zoneRedundant: false
  }
}

// Container App
resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: {
        external: true
        targetPort: 3000
        transport: 'http'
        corsPolicy: {
          allowedOrigins: ['*']
          allowedMethods: ['GET', 'POST', 'OPTIONS']
          allowedHeaders: ['*']
        }
      }
      secrets: [
        { name: 'database-url', value: postgresConnectionString }
        { name: 'storage-connection', value: storageConnectionString }
      ]
    }
    template: {
      containers: [
        {
          name: 'api'
          image: '${acrLoginServer}/sentinel-server:latest'
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            { name: 'DATABASE_URL', secretRef: 'database-url' }
            { name: 'STORAGE_CONNECTION_STRING', secretRef: 'storage-connection' }
            { name: 'PORT', value: '3000' }
            { name: 'NODE_ENV', value: 'production' }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 3
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

output fqdn string = app.properties.configuration.ingress.fqdn
