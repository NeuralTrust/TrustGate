# Delta for MCP Dual-Era Northbound

## ADDED Requirements

### Requirement: Era classification

After authentication, the server MUST parse each POST independently before consumer lookup. `initialize` or a known legacy header MUST select legacy despite modern metadata. Any `2026-07-28` header or metadata signal MUST select modern; an unknown version header MUST produce `-32022`; no modern signal MUST select legacy.

#### Scenario: Legacy precedence
- GIVEN `initialize` or a known legacy header with modern metadata
- WHEN the request is classified
- THEN legacy semantics apply

#### Scenario: Modern intent
- GIVEN one or both modern signals
- WHEN the request is classified
- THEN modern validation runs and missing counterparts fail closed

### Requirement: Modern request validation

A modern request MUST contain JSON-RPC 2.0, object `params._meta`, matching `MCP-Protocol-Version` and `io.modelcontextprotocol/protocolVersion`, object `io.modelcontextprotocol/clientCapabilities`, and matching `Mcp-Method`. `tools/call`, `resources/read`, and `prompts/get` MUST match `Mcp-Name` after exact Base64-sentinel UTF-8 decoding. Any `Mcp-Param-*` MUST be rejected. Header names are case-insensitive; values are case-sensitive.

#### Scenario: Valid modern request
- GIVEN all metadata and mirrored headers match
- WHEN validation runs
- THEN execution MAY continue

#### Scenario: Invalid modern request
- GIVEN malformed metadata, a mismatch, invalid Base64, or `Mcp-Param-*`
- WHEN validation runs
- THEN HTTP 400 returns `-32602` for body shape or `-32020` for header validation

### Requirement: Modern statuses and errors

Unsupported versions MUST return HTTP 400 `-32022` with exact `data.requested` and newest-first `data.supported`: `[2026-07-28, 2025-06-18, 2025-03-26, 2024-11-05]`. Unknown modern methods MUST return HTTP 404 `-32601`. Valid modern notifications MUST return HTTP 202 without a body.

#### Scenario: Unsupported version
- GIVEN an unknown non-legacy version
- WHEN validated
- THEN the exact `-32022` payload is returned

#### Scenario: Unknown method or notification
- GIVEN a validated modern request
- WHEN its method is unknown or it is a notification
- THEN HTTP 404 `-32601` or HTTP 202 is returned, respectively

### Requirement: Role-scoped discovery

`server/discover` MUST use only the role-scoped configured view and MUST NOT probe upstreams. It SHALL advertise supported versions, server identity, and capabilities; denied kinds MUST be omitted and allowed kinds MUST map to `{}`.

#### Scenario: Different role grants
- GIVEN two principals have different visible primitive kinds
- WHEN each calls `server/discover`
- THEN each sees only their configured kinds

#### Scenario: Local discovery
- GIVEN a valid discover request
- WHEN it completes
- THEN local telemetry is recorded without upstream, plugin, rate-limit, consent, or composer effects

### Requirement: Modern response and caching

Every modern success MUST preserve existing fields and add `resultType: "complete"` plus `io.modelcontextprotocol/serverInfo`. Discover/list results MUST use `ttlMs: 300000`; `resources/read` MUST use `ttlMs: 0`; all MUST use `cacheScope: "private"`.

#### Scenario: Cacheable result
- GIVEN a successful modern discover, list, or resource read
- WHEN serialized
- THEN identity and method-specific private cache hints are present

#### Scenario: Legacy result
- GIVEN a legacy success
- WHEN serialized
- THEN no modern result or cache fields are added

### Requirement: Northbound schema sanitization

Modern `tools/list` output MUST recursively omit every `x-mcp-header` key and MUST preserve all other schema fields. Sanitization MUST NOT mutate cached or southbound payloads.

#### Scenario: Concurrent sanitization
- GIVEN a shared tool schema contains nested `x-mcp-header` keys
- WHEN concurrent modern and legacy responses serialize it
- THEN modern omits only those keys while cached, legacy, and southbound views remain unchanged

### Requirement: Validation isolation

Modern parsing and validation MUST finish before consumer lookup, role scoping, routing, rate limiting, plugins, composer, or upstream discovery. Failures MUST create no composer span and MUST mark operation metrics skipped.

#### Scenario: Boundary rejection
- GIVEN any modern parse or validation failure
- WHEN the handler rejects it
- THEN none of the downstream collaborators or policy effects occur

### Requirement: Transport and legacy compatibility

The endpoint MUST remain `POST /{consumer_slug}/mcp`; validated non-discover requests SHALL use the existing gateway/composer. Modern handling MUST ignore and never emit `Mcp-Session-Id`. GET and DELETE MUST return 405 with `Allow: POST`. All existing legacy initialization, methods, errors, policies, filtering, consent, and telemetry MUST remain unchanged.

#### Scenario: Stateless modern transport
- GIVEN a modern request carries a session ID
- WHEN handled
- THEN the ID has no effect and no response session header is emitted

#### Scenario: Legacy regression
- GIVEN an existing legacy request or unsupported HTTP method
- WHEN handled
- THEN prior legacy behavior or HTTP 405 with `Allow: POST` is preserved
