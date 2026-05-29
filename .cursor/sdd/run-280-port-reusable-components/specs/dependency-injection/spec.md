# Delta for Dependency Injection

## ADDED Requirements

### Requirement: Reusable Proxy Module Wiring

The container MUST wire cache, telemetry, provider adapter, load-balancer, and proxy forwarder modules for the proxy surface. Unsatisfied B.1 proxy dependencies MUST be detected at boot.

#### Scenario: Proxy modules resolve

- GIVEN proxy mode is enabled with valid B.1 configuration
- WHEN the container builds
- THEN cache, telemetry, provider, load-balancer, and proxy forwarder dependencies resolve

#### Scenario: Proxy module dependency is missing

- GIVEN a required B.1 proxy dependency is not registered
- WHEN the container builds
- THEN startup fails with a container error before binding

### Requirement: Shared Runtime Singletons

The container MUST share reusable runtime singletons across contexts when both admin and proxy run in one process. Test overrides MUST still replace any newly wired proxy dependency.

#### Scenario: Single-binary reuse

- GIVEN admin and proxy contexts start in one process
- WHEN cache or telemetry dependencies are resolved from both contexts
- THEN each shared runtime dependency is instantiated once

#### Scenario: Proxy dependency override

- GIVEN a test overrides a cache, telemetry, provider, load-balancer, or proxy forwarder dependency
- WHEN a dependent service resolves
- THEN it receives the override without rebuilding unrelated production wiring
