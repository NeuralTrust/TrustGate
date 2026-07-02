# Delta for Config-Sync Security

This change adds the security guarantees for pull-based config sync. The compiled
snapshot carries secret material (registry credentials, `Auth.KeyHash`), so
transport authentication is mandatory and fail-closed, snapshot bodies are never
logged, and the on-disk LKG is encrypted at rest. Maps to ENG-950 QA: "snapshot
transport is authenticated and the LKG is AES-256-GCM encrypted; no secret bodies
are logged".

## ADDED Requirements

### Requirement: Mandatory transport authentication (fail-closed)

The snapshot HTTP endpoint MUST require a bearer token (`CONFIG_SYNC_TOKEN`) via a
`config_sync_auth` guard. A request without a valid token MUST be rejected with an
unauthorized response and MUST NOT return any snapshot body. When the token is not
configured the endpoint MUST fail closed (reject all requests) rather than serve
unauthenticated, and the data-plane fetcher MUST send the configured token on
every pull.

#### Scenario: Missing/invalid token rejected
- GIVEN the snapshot endpoint with a configured token
- WHEN a request arrives with no token or a wrong token
- THEN it MUST be rejected as unauthorized with no snapshot body

#### Scenario: Unset token fails closed
- GIVEN `CONFIG_SYNC_TOKEN` is unset on the control plane
- WHEN any request hits the snapshot endpoint
- THEN it MUST be rejected (fail-closed), never served unauthenticated

#### Scenario: Data plane authenticates every pull
- GIVEN the data-plane fetcher with a configured token
- WHEN it pulls the snapshot
- THEN it MUST include the bearer token on the request

### Requirement: Snapshot bodies never logged

Neither the control plane nor the data plane MUST log the encoded snapshot body or
any secret material it contains (registry credentials, `Auth.KeyHash`). Log lines
around compile, serve, pull, and load MAY include the version and sizes but MUST
NOT include the body.

#### Scenario: No body in logs
- GIVEN compile/serve/pull/load operations execute
- WHEN their logs are inspected
- THEN they MUST NOT contain the snapshot body or embedded secret values

### Requirement: LKG encrypted at rest

The on-disk last-known-good snapshot MUST be encrypted with AES-256-GCM using the
configured key (`CONFIG_SYNC_LKG_KEY`, base64 32-byte). It MUST NOT be written in
plaintext, and it MUST be authenticated on read so tampering is detectable.

#### Scenario: LKG file is ciphertext
- GIVEN a data plane that persists an LKG
- WHEN the LKG file is inspected
- THEN it MUST be AES-256-GCM ciphertext, not a plaintext snapshot

#### Scenario: Tampering is detected on read
- GIVEN an LKG file modified after write
- WHEN the data plane reads it
- THEN authentication MUST fail and the tampered LKG MUST be rejected
