# Delta for HTTP Server

## ADDED Requirements

### Requirement: Proxy Metrics Middleware

The proxy HTTP surface MUST apply metrics middleware to proxy traffic so completed requests emit proxy metrics without changing response semantics.

#### Scenario: Proxied request is measured

- GIVEN a request reaches the proxy surface
- WHEN the response completes
- THEN proxy metrics record method, path, status, latency, and request id

#### Scenario: Handler returns an error

- GIVEN a proxy handler returns an error response
- WHEN metrics middleware records the request
- THEN the emitted metrics contain the final error status and request id

### Requirement: Catch-All Non-Streaming Proxy Route

The proxy HTTP surface MUST route unmatched proxy paths to the non-streaming forwarder after shared middleware has run. Health or explicitly registered routes MUST keep their existing behavior.

#### Scenario: Unmatched proxy path

- GIVEN a proxy request path has no more specific proxy route
- WHEN the proxy router handles the request
- THEN the non-streaming forwarder receives the request

#### Scenario: Existing explicit route

- GIVEN a health or explicitly registered route matches the request
- WHEN the proxy router handles the request
- THEN that route handles the request instead of the catch-all forwarder
