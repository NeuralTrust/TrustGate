# RUN-915 Behavioral Spec: TLS Enrolment Auth

## Purpose

RUN-915 SHALL switch the default DataAgent -> DataBridge southbound path from mandatory client mTLS to DataBridge server TLS plus application-level enrolment-token authentication, while preserving server identity validation and fail-closed authentication.

## Requirements

### Requirement R1: DataBridge Server TLS

DataBridge MUST serve southbound gRPC with server-side TLS in deployed non-dev environments. It MUST fail startup when required server cert/key material is missing. It MAY request client certificates only when explicit compatibility mTLS is configured.

#### Scenario: Deployed TLS server starts

- GIVEN non-dev DataBridge config with server cert/key and no client CA
- WHEN the southbound server starts
- THEN it SHALL serve TLS
- AND it SHALL NOT require a DataAgent client certificate

#### Scenario: Missing deployed TLS material fails closed

- GIVEN non-dev DataBridge config without server cert or key
- WHEN DataBridge starts
- THEN startup MUST fail before accepting southbound streams

### Requirement R2: Enrolment Token Authentication

DataBridge MUST authenticate each DataAgent `Connect` stream using the `x-enrolment-token` metadata before registry registration. Missing or invalid tokens MUST be rejected without registering an agent. The singular token model assumes an isolated 1:1 tenant/DataAgent deployment.

#### Scenario: Valid token registers stream

- GIVEN a configured `ENROLMENT_TOKEN`
- WHEN a DataAgent connects with that token and claims tenant `T`
- THEN DataBridge SHALL accept authentication
- AND it MAY register the stream for tenant `T`

#### Scenario: Missing or invalid token is rejected

- GIVEN DataBridge requires enrolment authentication
- WHEN a stream omits `x-enrolment-token` or sends an invalid token
- THEN DataBridge MUST reject the stream
- AND no registry entry SHALL be created

#### Scenario: Token is not multi-tenant routing

- GIVEN the singular token model
- WHEN a deployment needs one DataBridge to accept independent tokens for multiple tenants
- THEN that deployment MUST add tenant-bound credential storage before using the shared DataBridge as a multi-tenant router

### Requirement R3: Token Safety And Error Behavior

DataBridge and DataAgent MUST NOT log enrolment-token values. Authentication failures SHOULD return stable unauthenticated errors that do not reveal the expected token, configured token count, or tenant binding internals.

#### Scenario: Token failure is audit-safe

- GIVEN an invalid enrolment-token attempt
- WHEN DataBridge records logs or returns an error
- THEN the token value MUST NOT appear
- AND the error MUST identify authentication failure without secret detail

### Requirement R4: DataAgent TLS Credentials

DataAgent MUST support a default deployed server-TLS credential mode that requires `ENROLMENT_TOKEN` and `DATABRIDGE_SERVER_NAME`, does not require client cert/key files, uses `TLS_CA_FILE` when set, and uses system roots when `TLS_CA_FILE` is empty.

#### Scenario: TLS-only config is valid

- GIVEN `ENROLMENT_TOKEN` and `DATABRIDGE_SERVER_NAME` are set
- AND no client cert/key files are configured
- WHEN DataAgent validates deployed TLS config
- THEN validation SHALL succeed

#### Scenario: Server identity is required

- GIVEN deployed TLS mode without `DATABRIDGE_SERVER_NAME`
- WHEN DataAgent validates config
- THEN validation MUST fail before dialing DataBridge

### Requirement R5: Secure Token Transmission

DataAgent MUST send `ENROLMENT_TOKEN` metadata only on secure DataBridge transports. It MUST NOT send the token over insecure dev transport.

#### Scenario: Token is sent over TLS

- GIVEN DataAgent uses server TLS
- WHEN it opens the southbound stream
- THEN it SHALL attach `x-enrolment-token`

#### Scenario: Token is withheld over insecure transport

- GIVEN DataAgent uses explicit insecure dev transport
- WHEN it opens the southbound stream
- THEN it MUST NOT attach `x-enrolment-token`

### Requirement R6: Default Kubernetes And Secrets Contract

Default dev and production overlays MUST NOT mount or require `dataagent-client-tls` for DataAgent. DataBridge deployed overlays MUST provide server TLS cert/key material. Both sides MUST source `ENROLMENT_TOKEN` from secrets or equivalent deployment configuration.

#### Scenario: Default overlays omit client mTLS

- GIVEN default hybrid dev or production manifests
- WHEN manifests are rendered
- THEN DataAgent SHALL have no required client cert/key mount
- AND DataBridge SHALL still have server TLS material in deployed environments

### Requirement R7: Documentation And Rotation Guidance

Production documentation MUST describe DataBridge server TLS, `DATABRIDGE_SERVER_NAME`, optional `TLS_CA_FILE`, and `ENROLMENT_TOKEN`. It MUST NOT require customer-side DataAgent client certificate rotation in the default path. DataCore changes SHALL be documentation-only.

#### Scenario: Default docs match TLS enrolment flow

- GIVEN an operator follows the production hybrid secrets docs
- WHEN they provision default RUN-915 secrets
- THEN they SHALL provision enrolment token and DataBridge server TLS material
- AND they SHALL NOT be instructed to rotate DataAgent client cert/key material

### Requirement R8: Compatibility And Non-Goals

Explicit mTLS compatibility MAY remain for internal or transitional deployments, but it MUST NOT be the default documented or rendered path. RUN-915 SHALL NOT add one-time token exchange, per-agent credential lifecycle, or residency proto changes for `INSTANCE_ID`.

#### Scenario: Compatibility is opt-in

- GIVEN a deployment uses default RUN-915 config
- WHEN DataAgent connects to DataBridge
- THEN the connection SHALL use server TLS plus enrolment auth
- AND mTLS SHALL require explicit non-default configuration

### Requirement R9: Test Coverage

Automated tests MUST cover TLS-only success, private-CA and system-root DataAgent TLS validation, missing/invalid enrolment-token rejection, no registration on auth failure, safe error/log behavior, and default manifest/docs expectations where repo tooling supports them.

#### Scenario: Tests prove the behavioral contract

- GIVEN the RUN-915 test suite is run
- WHEN TLS-only and rejected-auth cases execute
- THEN valid enrolment SHALL connect without client cert/key
- AND invalid enrolment SHALL fail before registration
