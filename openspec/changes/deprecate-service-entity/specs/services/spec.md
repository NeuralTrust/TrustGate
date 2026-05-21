# Delta: services

## REMOVED Requirements

### Requirement: Service CRUD endpoints

(Reason: Service entity deprecated; upstream is the only target abstraction.)

Removes:

- HTTP routes `POST/GET/PUT/DELETE /api/v1/gateways/{gateway_id}/services[/:service_id]`
- App layer: `service.Creator`, `service.Updater`, `service.Finder`
- Domain: `service.Repository`, `domain/service` package (entity, builder, errors, mocks)
- Infra: `pkg/infra/repository/service_repository.go`
- Cache: `cache.Client.GetService`, `cache.Client.SaveService`, `ServiceTTLName`, `ServiceKeyPattern`, `ServicesKeyPattern`
- Events: `DeleteServiceCacheEvent` and its subscriber
- Audit constants: `EventTypeServiceCreated/Updated/Deleted`, `TargetTypeService`
- Swagger entries for `/services`

#### Scenario: Legacy endpoint

- WHEN any request hits `/api/v1/gateways/*/services*`
- THEN router returns 404 (route absent)

#### Scenario: Service package import

- WHEN any file imports `github.com/NeuralTrust/TrustGate/pkg/domain/service` or `github.com/NeuralTrust/TrustGate/pkg/app/service`
- THEN the build fails (packages do not exist)
