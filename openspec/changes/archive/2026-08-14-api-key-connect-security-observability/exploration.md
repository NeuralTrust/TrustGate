# Explore: API-key connect security and observability

## Scope and baseline

- Linear issue: RUN-1142
- Change: `api-key-connect-security-observability`
- Implementation branch: `fix/api-key-connect-security-observability`
- Stacked base and PR target: `feat/api-key-self-service-connect-endpoint` at `fd8782b5`
- Artifact mode: hybrid; `openspec/config.yaml` is absent
- Analysis baseline: the working tree `HEAD` is `fd8782b5`, so all findings below describe the RUN-1141 stacked base. `origin/develop` was not used.

RUN-1141 already introduced the browser form, target-first API-key authorization and ticket redirect. RUN-1142 should harden that use case without moving authentication into the transport layer or changing the existing OAuth2 ticket/state semantics.

## Executive finding

The safest bounded change is a dedicated Redis fixed-window limiter with independent source and consumer buckets, identifier-only structured audit events carried by additive ticket metadata, operation-route classification by MCP connect path shape, and an OAuth-challenge eligibility signal produced by the existing path-first auth lookup. Reusing the commercial plan limiter or adding an untrusted forwarded-IP middleware would couple unrelated concerns and would not correctly satisfy the security boundary.

## Current behavior

### API-key connect endpoint

- `GET /:slug/connect` resolves the gateway from `Host`, validates an active MCP consumer, and renders a blank password input with `autocomplete="off"`.
- `POST /:slug/connect` resolves the gateway before parsing or looking up a key, accepts only an `application/x-www-form-urlencoded` body, ignores query/header credentials, and redirects with `303` to `/{slug}/mcp/connect?ticket={ticket}`.
- The raw key is passed only to `APIKeyFinder.FindByAPIKey`. That finder hashes the value before using it as an in-process cache key.
- Expected authorization misses converge on `ErrAPIKeyConnectUnauthorized`; the handler maps them to the same `401` status and `"Unable to authorize this request."` body. Covered cases include missing, disabled, wrong auth type, wrong gateway and AuthID not attached to the addressed consumer.
- Invalid Host/consumer resolution also becomes the same generic POST `401` and occurs before key lookup. GET deliberately remains a generic `404`.
- Dependency failures after target resolution are not returned to the client; the handler emits a generic `500`.
- There is no attempt limiter on the public POST route.

### Secret exposure

- The key is body-only. Success redirects contain only the opaque ticket.
- The access logger records method, path, status, latency and sanitized errors; it does not record headers, query strings, request bodies or response bodies.
- Operational metrics record bounded route/method/outcome labels and no request content.
- The self-service routes are registered before authenticated MCP metrics middleware, so the form body is not copied into product MCP metrics.
- Existing handler/service errors do not interpolate the submitted key.
- `logredact` handles common bearer/API-key header and JSON forms plus `sk-`/`tgk_` prefixes, but it cannot guarantee redaction of an arbitrary raw secret embedded without context. The primary protection must remain never logging or wrapping the submitted value.

### Browser response headers

- The API-key handler sets `Cache-Control: no-store` before all GET and POST outcomes.
- `renderHTML` also sets `Cache-Control: no-store` and `Pragma: no-cache`.
- The MCP base transport includes `SecurityHeadersMiddleware`, which sets `Referrer-Policy: no-referrer` globally.
- The required headers therefore exist in the production middleware stack. The missing piece is an end-to-end router regression test proving both headers on the self-service responses; duplicating `Referrer-Policy` in the handler is unnecessary.

### Ticket and OAuth state invariants

- Redis connect tickets retain a fifteen-minute TTL and are read with `GET`, so they remain reusable while the user links multiple providers.
- OAuth callback states retain a ten-minute TTL and are consumed with atomic `GETDEL`, preserving one-time use.
- Additive fields on the JSON `ConnectTicket` record are backward-compatible with existing stored tickets and do not require changes to either TTL or state consumption.

### Auditability

- There is no dedicated audit-event port, schema or sink in this repository.
- Ticket creation has no audit event.
- Successful provider unlink has no audit event.
- Successful provider link currently logs `"oauth connect: provider grant stored"` with provider, subject, gateway, refresh-token presence, expiry and scopes. It lacks consumer/AuthID identifiers and contains more than the requested identifier-only field set.
- The connect ticket currently stores gateway ID, principal subject, consumer path and resume URL. It does not carry consumer ID or AuthID, so callback/unlink code cannot currently emit the requested identifiers without another lookup or additive ticket metadata.

### Operation metrics

- `OpsMetricsMiddleware` sees the real request path through `c.Path()`.
- `classifyRoute` recognizes `/oauth/*` and only the literal `"/+/connect"` as `RouteMCPOAuth`.
- Real paths such as `/tools/connect` and `/tools/mcp/connect` are therefore classified as `RouteOther`, despite using the MCP OAuth/connect flow.
- Existing route labels are bounded enums, so the correction needs no new metric label and must not include slugs.

### OAuth challenge

- `OAuthChallengeMiddleware` adds a Bearer `WWW-Authenticate` header to every `401`, including direct-status responses.
- The auth chain already performs a path-first lookup and computes whether any auth attached to the addressed consumer is OAuth2. It also knows whether the configured default identity provider makes OAuth available.
- That eligibility is currently local to `chainIdentityResolver.pathScope` and is not exposed to the challenge middleware.
- Conditional behavior is feasible without another repository lookup: publish a bounded challenge-eligibility value into Fiber request locals while resolving path scope, then let the outer challenge middleware consult it after downstream completion.
- The self-service form bypasses the auth chain, so it must explicitly mark its route as not Bearer-challengeable. A form POST never accepts Bearer credentials, even when the consumer also supports OAuth2.
- Unknown paths or lookup failures should preserve today's challenge behavior by default; only a positively identified path with no usable OAuth2 option should suppress the header. This minimizes OAuth2 compatibility risk.

## Affected-areas map

| Area | Primary files | Expected change |
|---|---|---|
| API-key transport | `pkg/api/handler/http/oauth/api_key_connect_handler.go`, tests | Apply source limit before credential work, map `429`/limiter failure safely, mark form responses as not Bearer-challengeable, prove no secret/header leakage |
| API-key use case | `pkg/app/oauth/api_key_connect.go`, tests, mocks | Apply consumer limit before key lookup; keep all expected auth misses uniform; pass consumer/AuthID metadata into ticket creation/audit |
| Connect lifecycle | `pkg/app/oauth/connect.go`, `connect_chain.go`, tests | Carry identifier metadata and emit success-only link/unlink audit events without subject, token, scopes, ticket or error detail |
| Ticket persistence | `pkg/infra/oauth/connect_store.go`, tests | Persist additive `consumer_id` and `auth_id` fields while preserving ticket TTL and state `GETDEL` |
| Fixed-window limiting | `pkg/app/oauth` narrow limiter port; `pkg/infra/ratelimit` Redis adapter/tests | Independent expiring source and consumer counters using the existing atomic `INCR` + first-hit `PEXPIRE` pattern |
| Configuration and wiring | `pkg/config/config.go`, config tests, `.env.example`, `pkg/container/modules/oauth.go` and/or `ratelimit.go` | Dedicated security-limiter enable/limits/window; do not inherit the commercial plan-limiter flag |
| Operation metrics | `pkg/api/middleware/ops_metrics.go`, tests | Classify path shapes without adding slug cardinality |
| Challenge policy | `pkg/api/middleware/auth_chain.go`, `oauth_challenge.go`, tests | Surface path OAuth eligibility and suppress challenge only for known API-key-only paths/form routes |
| Router integration | `pkg/server/router/mcp_router_test.go` | Verify real routing, security headers, metric class and challenge behavior in middleware order |
| Secret redaction regression | `pkg/api/middleware/access_log_test.go`, OAuth handler/service tests | Capture logs and all response surfaces using a sentinel raw key |

## Reusable patterns

1. `pkg/infra/ratelimit/store.go` already has the required atomic fixed-window Redis primitive: `INCR` followed by `PEXPIRE` only on the first hit, plus `PTTL` for `Retry-After`.
2. `pkg/app/ratelimit.Exceeded` demonstrates typed retry metadata and HTTP mappings, but its commercial `reason`, limit and quota payload should not be reused verbatim because it leaks which security bucket fired.
3. `pkg/app/oauth/api_key_connect.go` already centralizes target-first validation and expected-miss normalization.
4. `pkg/infra/oauth/connect_store.go` provides additive JSON ticket storage and preserves the required TTL/single-use split.
5. `chainIdentityResolver.pathScope` already resolves the exact auth set needed to decide Bearer challenge eligibility.
6. `OpsMetricsMiddleware` already maps `429` to the bounded throttled outcome and uses a bounded route enum.
7. `SecurityHeadersMiddleware` already provides the strongest applicable referrer policy.
8. `logredact.RedactLogString` is a final safety net for access-log errors, not a substitute for identifier-only event construction.

## Approaches comparison

| Approach | Shape | Advantages | Disadvantages and risks | Effort |
|---|---|---|---|---|
| A. Extend the commercial plan limiter | Add source/consumer methods to `app/ratelimit.Checker`; use `RATE_LIMIT_ENABLED`; emit audit through existing ad hoc `slog`; classify/challenge with path string heuristics | Few new types; reuses Redis module | Mixes entitlement and credential-abuse policy; security can be disabled with plan limiting; existing fail-open behavior is wrong for brute-force protection; public response reveals bucket/limit; challenge heuristics cannot distinguish API-key-only from OAuth2 consumers | Medium |
| B. Dedicated connect-security controls | Narrow connect limiter port with Redis fixed windows; independent source and consumer checks; additive ticket identity; identifier-only audit emitter; path-scope challenge signal; shape-based metric classification | Correct separation of concerns; bounded keys/labels; testable; preserves OAuth2 and ticket/state behavior; no duplicate auth lookup for challenge | More wiring and tests; requires explicit source trust, thresholds, failure policy and audit-sink decisions | Medium-high |
| C. Generic authentication-security framework | Introduce a repository-wide generic limiter, formal audit domain/event bus and authorization capability resolver, then migrate connect | Strong long-term reuse and formal semantics | Excessive RUN-1142 scope; high regression surface across all planes; likely far above the review budget; delays the public-endpoint hardening | High |
| D. In-process/IP-only middleware | Fiber middleware with local token buckets keyed by `c.IP()`/slug; direct logs; unconditional challenge suppression on connect-looking paths | Fast and operationally simple | Limits differ per replica and reset on restart; source may be ingress IP; slug buckets are mutable identifiers; no consumer/AuthID audit context; does not solve runtime OAuth challenge correctly | Low, not acceptable |

## Recommended approach

Use Approach B with the following boundaries:

1. Create a dedicated connect-attempt limiter contract, separate from the plan `ratelimit.Checker`.
   - Check every POST by source before Host/consumer/key work so invalid-host spraying is also bounded.
   - After resolving a valid target, check a second bucket keyed by immutable consumer ID before calling `FindByAPIKey`.
   - Count successful and failed attempts; otherwise an attacker with one valid key can still exhaust ticket/Redis work.
   - Default to 10 attempts per source and 100 attempts per consumer in a one-minute fixed window.
   - Configure these independently through `MCP_CONNECT_RATE_LIMIT_SOURCE=10`, `MCP_CONNECT_RATE_LIMIT_CONSUMER=100` and `MCP_CONNECT_RATE_LIMIT_WINDOW=1m`; keep `MCP_CONNECT_RATE_LIMIT_ENABLED=true` independent from commercial plan limiting.
   - Use fixed windows with Redis atomic increment/expiry and bounded TTL.
   - Return a generic `429` plus `Retry-After`; do not expose source-versus-consumer reason or raw bucket key.
   - Fail closed for POST when the security limiter is unavailable. The same flow already depends on Redis to mint a ticket, so fail-open does not provide a reliable successful path and removes the stated brute-force bound.

2. Keep expected authorization results indistinguishable below the limit.
   - Preserve the existing target-first order and common `401` body for nonexistent, disabled, wrong-type, wrong-gateway and cross-consumer API keys.
   - Keep malformed media/form failures (`415`/`400`) distinct because they are protocol errors, not key-existence signals.
   - Keep `429` distinct after the threshold, as required by the repeated-attempt QA.

3. Add a narrow audit emitter rather than scattering `slog` calls.
   - Emit only after successful ticket persistence, vault upsert and vault delete.
   - Use stable event names such as connect ticket created, provider linked and provider unlinked.
   - Permit only gateway ID, consumer ID, AuthID, provider ID and event name. Do not emit principal subject, API key/hash, ticket/state, token presence, scopes, expiry, resume URL or raw error.
   - Replace the existing provider-grant log with the identifier-only event instead of emitting both.
   - Add consumer/AuthID fields to `ConnectTicket`; populate them at ticket creation so callback/unlink do not repeat target lookup and cannot drift from the identity that authorized the ticket.
   - Emit this RUN-1142 event set only for identity-complete tickets minted by the API-key self-service flow; existing OAuth2-originated tickets and behavior remain unchanged.

4. Reuse path-first authentication knowledge for `WWW-Authenticate`.
   - Let auth scope produce `OAuth challenge allowed = true` when the addressed consumer has OAuth2 or the configured default IdP applies.
   - Publish that boolean to request locals before credential resolution can fail.
   - Make the challenge middleware preserve current behavior when no decision exists and suppress only when the value is explicitly false.
   - Mark self-service form routes explicitly false because they accept only the body API key.

5. Correct operation classification with bounded path-shape matching.
   - Classify `/:slug/connect` and paths ending in `/mcp/connect` as `RouteMCPOAuth`, retaining `/oauth/*` and compatibility with the literal route pattern.
   - Never place the slug/path into metric attributes.

6. Treat browser headers as regression coverage.
   - Retain handler `Cache-Control: no-store`.
   - Retain global `Referrer-Policy: no-referrer`.
   - Add complete-router tests covering form, errors and redirect. No extra policy header implementation is needed unless tests reveal a route that bypasses base transport.

7. Preserve persistence behavior mechanically.
   - Do not modify connect ticket/state TTL constants.
   - Do not replace state `GETDEL`.
   - Add focused regression assertions for the fifteen-minute ticket TTL, the ten-minute OAuth state TTL and one-time state consumption around any ticket-record changes.

## QA and test impact

- Table-driven API-key service cases: nonexistent, disabled, wrong type, wrong gateway, cross-consumer and valid all share the expected result class.
- Limiter unit tests: independent source/consumer counters, threshold boundary, expiry/`Retry-After`, Redis error behavior, no secret in key or error.
- Handler/router tests: repeated invalid POST becomes `429`; the sentinel secret is absent from body, headers, `Location`, captured logs and metric attributes for success, auth miss, rate limit and dependency failure.
- Audit tests: exactly one event after each successful mutation, no event before persistence or on failure, exact attribute allowlist.
- Operation-metric tests: `/tools/connect`, `/tools/mcp/connect` and relevant nested suffixes map to `mcp_oauth`; unrelated `/connect`-looking paths do not.
- Challenge tests: API-key-only runtime path omits Bearer challenge; OAuth2 and default-IdP paths retain the current challenge; form POST omits it; unknown/error scope preserves compatibility.
- OAuth connect regressions: full consent flow, auto-registration, single-use state, unknown ticket/provider, chain URL and provider denial remain green.
- Verification gate after implementation: focused tests with `-race`, then repository lint and full unit/race suite per repository commands.

## Resolved decisions

1. **Limits and window**
   - Enable the connect limiter by default.
   - Defaults: 10 attempts per source per minute and 100 attempts per consumer per minute.
   - Configuration: `MCP_CONNECT_RATE_LIMIT_ENABLED=true`, `MCP_CONNECT_RATE_LIMIT_SOURCE=10`, `MCP_CONNECT_RATE_LIMIT_CONSUMER=100`, `MCP_CONNECT_RATE_LIMIT_WINDOW=1m`.
   - All values are positive and validated at startup. The fixed window and both counters share the configured duration. A hit at the exact limit is allowed; the next hit returns `429` with only `Retry-After`.
   - Rationale: interactive provider connection is low-frequency; the 10:100 ratio requires a distributed attack to exhaust a consumer while leaving room for shared-NAT users.

2. **Network source and trusted proxies**
   - The authoritative source is the canonical remote socket IP by default. Trust no forwarding header when `MCP_CONNECT_TRUSTED_PROXY_CIDRS` is empty, which is the default.
   - When the direct peer belongs to a configured trusted CIDR, inspect only `X-Forwarded-For`, walk addresses from right to left, skip trusted proxy hops and select the first untrusted canonical IP. Ignore `Forwarded`, `X-Real-IP` and Cloudflare-specific headers in this change.
   - Canonicalize with `net/netip`: remove ports, unmap IPv4-mapped IPv6 and use the normalized address string. Invalid/missing forwarding data falls back to the direct peer; invalid configured CIDRs fail startup.
   - The worktree shows GKE `HTTPRoute` resources terminating at the MCP `ClusterIP`, but not the external Gateway proxy CIDRs. Therefore SaaS overlays must set `MCP_CONNECT_TRUSTED_PROXY_CIDRS` to the immediate GKE proxy ranges only after infrastructure verifies them. Until then, the safe fallback is the proxy peer bucket rather than trusting spoofable headers.

3. **Limiter failure policy**
   - Fail closed on Redis/counter errors before API-key lookup or ticket creation.
   - Return generic `503 Service Unavailable`, `Cache-Control: no-store`, no `WWW-Authenticate`, no bucket detail and no raw dependency error. Log one sanitized operational error without source, consumer slug or credential data.
   - Do not reuse the commercial plan limiter's fail-open behavior.

4. **Audit destination and schema**
   - Use the existing injected `*slog.Logger` at `INFO`, writing structured JSON to stdout through `pkg/infra/logger`; Kubernetes/GKE log collection is the destination.
   - Do not add Kafka, product telemetry, a database table or a new cross-service schema in RUN-1142.
   - Use message `"security audit"` and exact event values `mcp_connect_ticket_created`, `mcp_provider_linked` and `mcp_provider_unlinked`.
   - Attribute allowlist: `event`, `gateway_id`, `consumer_id`, `auth_id`, plus `provider_id` only for link/unlink. No outcome, subject, key/hash, ticket/state, scopes, tokens, expiry, URL, IP or error field.
   - Replace the existing pre-persistence provider-grant log; emit only after the relevant persistence mutation succeeds.

5. **Provider identifier**
   - `provider_id` is the canonical forwarded-auth `MCPAuth.Provider` value that keys the vault credential and callback route.
   - Do not emit mutable registry display names or add registry UUID lookup requirements. A successful vault delete proves that the supplied provider identifier matched an existing credential, preserving current unlink semantics.

6. **Event coverage**
   - Cover the complete successful lifecycle of API-key self-service tickets: ticket persisted, provider credential upserted, provider credential deleted.
   - Add `ConsumerID` and `AuthID` to `ConnectTicket`; emit link/unlink only when both fields are present. Tickets without them are legacy/OAuth2-originated and remain behaviorally unchanged with no new audit event.
   - Do not emit failure/attempt events, and do not retrofit global OAuth2 credential ownership or human attribution.

7. **`WWW-Authenticate` policy**
   - Never add a Bearer challenge to `/:slug/connect` responses; that form accepts only the body API key.
   - For runtime MCP `401`s on a known consumer path, add the challenge only when path scope contains an enabled OAuth2 auth or the configured default IdP applies. A known path with no usable OAuth2 omits it.
   - Preserve today's challenge when path eligibility is unknown because lookup failed or no path matched. This keeps existing OAuth2 discovery behavior stable.
   - Carry the decision as a bounded request-local boolean from the existing path-first auth lookup; do not add another gateway/consumer lookup in the challenge middleware.

8. **Bucket-key format**
   - Use `gt:mcp:connect:rl:v1:source:<digest>` and `gt:mcp:connect:rl:v1:consumer:<digest>`.
   - `<digest>` is lowercase hexadecimal HMAC-SHA-256 using the existing required `SERVER_SECRET_KEY`, with domain-separated inputs `source\x00<canonical-ip>` and `consumer\x00<consumer-uuid>`.
   - Never put raw IPs, forwarded-header text, Host, slug, consumer ID or API-key material in Redis keys, logs or metrics. Rotation of `SERVER_SECRET_KEY` intentionally resets these short-lived counters.

## Residual risks

1. **SaaS source granularity until proxy CIDRs are configured.** The safe default groups requests by the immediate GKE proxy peer; this may cause coarse throttling under load. It does not permit header spoofing, and the independent consumer bucket still bounds each resolved target.
2. **Fixed-window boundary burst.** Up to twice a nominal limit can pass around a window boundary. This is accepted to reuse the existing atomic Redis pattern and keep RUN-1142 small.
3. **Distributed consumer denial of service.** Ten or more source identities can exhaust the default consumer bucket. The one-minute recovery bound and independent source limit constrain impact but cannot eliminate distributed abuse.
4. **Audit durability follows platform log retention.** Structured stdout is queryable through the existing deployment pipeline but is not a transactional audit ledger. Durable cross-service audit storage remains outside RUN-1142.
5. **Mixed-version tickets during rolling deployment.** Tickets minted by an old replica lack consumer/AuthID and therefore produce no new link/unlink event. They continue to function; the gap lasts at most the existing fifteen-minute ticket TTL.
6. **High-cardinality/security data.** Tests must enforce the event allowlist and verify that source addresses, slugs, principal subjects, ticket IDs, errors and API-key hashes never become audit or metric labels.
7. **Review size.** Limiting, audit identity propagation, metrics and challenge policy may exceed the 400-line review budget. The tasks phase should split deliverables if its forecast remains high.

## Resolved from code

- The stacked base is exact and clean at `fd8782b5`; no comparison to `origin/develop` is needed.
- Uniform expected API-key misses are already implemented; RUN-1142 primarily needs broader explicit regression coverage and limiter ordering.
- `Cache-Control: no-store` and `Referrer-Policy: no-referrer` already apply in the production route stack.
- The raw key currently does not enter redirects, operation metrics, authenticated MCP metrics or normal access-log fields.
- Operation metric misclassification is confirmed for real connect paths.
- Conditional challenge behavior is feasible from the existing path-first auth lookup without changing OAuth2 validation.
- Additive ticket identity fields can preserve the fifteen-minute reusable ticket TTL, the ten-minute OAuth state TTL and one-time state behavior.
