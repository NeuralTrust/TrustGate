# Proposal: API-Key Self-Service Connect Endpoint

## Intent

Enable API-key MCP consumers to open a browser flow that validates their key, creates a ticket for the runtime principal, and reuses the provider consent page without exposing the key.

## Scope

### In Scope

- Add `GET` and `POST /:slug/connect` before `/+/connect`.
- On GET, resolve the gateway from Host and require an active MCP consumer; otherwise return a generic 404.
- Accept POST only as `application/x-www-form-urlencoded`, with the API key body-only.
- Validate gateway, consumer, enabled API-key auth, matching gateway, and explicit consumer AuthID attachment.
- Create `CreateTicket(gatewayID, auth.Name, MCPPath(slug))` and redirect with `303` to `/{slug}/mcp/connect?ticket=...`.
- Add DI wiring and focused use-case, handler, page, and Fiber dispatch tests.

### Out of Scope

- Vault changes, multiple humans per key, principal derivation migration, or App UI.
- Brute-force rate limiting and hardening, tracked by RUN-1142.
- Origin validation or a new gateway-status contract.

## Capabilities

### New Capabilities

- `api-key-self-service-connect`: Browser entry, authorization, ticket creation, secure responses, and route precedence.

### Modified Capabilities

None.

## Approach

Introduce a thin browser handler and a dedicated OAuth application use case. The handler uses `SubdomainGatewayResolver` with `MCPBaseDomain`, reads `slug` directly from the route, enforces form media type, and never copies the key into headers. The use case resolves the active consumer before key lookup, uses `MatchSlug`, validates MCP type and AuthID association, preserves `principalSub = auth.Name`, and delegates ticket persistence to the existing `ConnectService`.

Expected authorization failures return one generic 401; malformed forms return 400, unsupported media types 415, and dependency failures 500. Responses are `no-store`; the form uses `type=password` and `autocomplete=off`; key material never enters query strings, logs, redirects, or rendered values.

## Affected Areas

- `pkg/app/oauth/`: new API-key connect use case and generated mock.
- `pkg/api/handler/http/oauth/`: handler, request DTO, secure form/page behavior.
- `pkg/server/router/mcp_router.go`: ordered GET/POST routes and dispatch tests.
- `pkg/container/modules/{api,mcp,server_mcp}.go`: resolver, use-case, handler, and router wiring.

## Risks

- Route shadowing: verify precedence through real Fiber dispatch and preserve OAuth2 routes.
- Authorization drift: assert parity with runtime identity and cross-gateway/cross-consumer rejection.
- Secret leakage: assert response, Location, and error paths never contain the key.

## Rollback Plan

Remove the two routes, handler/use case, DTO/template additions, tests, and DI providers. Existing OAuth2 connect and runtime API-key authentication remain unchanged; no data migration or vault rollback is required.

## Dependencies

- RUN-1141, parent RUN-1136; `APIKeyFinder`, consumer data finder, `ConnectService`, and MCP provider page.

## Success Criteria

- [ ] Safe GET and valid POST ticket/303 redirect work.
- [ ] Invalid, disabled, cross-consumer, wrong-host/gateway/slug, and non-MCP cases follow the specified generic failures.
- [ ] OAuth2 behavior remains unchanged.
- [ ] Focused tests and race-enabled Go tests pass.
