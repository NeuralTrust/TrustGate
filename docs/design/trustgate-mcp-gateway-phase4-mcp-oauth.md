# Design: TrustGate MCP Gateway — Phase 4 (MCP OAuth 2.1 Resource Server + Authorization Server)

## Linked artifacts
- Epic plan: `.cursor/plans/trustgate_mcp_gateway_and_auth_016192dd.plan.md` (Phase 4 = `mcp-oauth` todo;
  flow **A9** in the Phase 2 inbound-auth section; appendix **C6**/**D6** `mcp_oauth { enabled, dcr, pkce }`)
- Phase 1 doc: `docs/design/trustgate-mcp-gateway-phase1-tenancy.md` (tenant scope, `identity.Principal`, ids,
  DI/module pattern, migration idiom — reused verbatim here)
- Phase 2 doc: **not yet written** — Phase 4 builds on the A2 (JWKS) validator + the 401 emission seam in
  `pkg/api/middleware/auth.go`; constraints taken from the plan's "Phase 2 — Inbound credential validation"
- Phase 3 doc: **not yet written** — the protected resource is the per-consumer virtual MCP server served on
  the MCP plane (`:8082`) at the consumer `path`; constraints taken from the plan's "Phase 3"
- Reference implementation grounded against the agentgateway POC: `/Users/victor/Code/poc/agentgateway/crates/agentgateway/src/mcp/auth.rs`
  and `.../src/http/oauth.rs` (the `McpIDP` adapter / metadata-rewrite model we mirror in Go)
- **No Linear `ENG-###` supplied** — this doc is tracked in-repo (same precedent as Phase 1). Create the
  ticket before implementation so `/task-check` can run, then optionally mirror this file to
  `.cursor/sdd/<ENG-###>/design.md`.

> Scope note: this designs **only Phase 4** — the gateway's MCP OAuth 2.1 **Resource Server** role
> (RFC 9728 protected-resource metadata + the `401`/`WWW-Authenticate` challenge) and its thin
> **Authorization Server facade** (RFC 8414 metadata, RFC 7591 DCR, PKCE S256), with per-IdP adapters for
> Entra / Okta / Keycloak / Auth0 / Google / generic OIDC. Token *minting* for downstream calls is Phase 5
> (STS) and appears here only as the claims-challenge machinery Phase 5 reuses.

---

## Grounding (verified against the code, not assumed)

| Claim | Evidence |
|---|---|
| Unauthenticated requests are rejected today with a bare `401 "unauthenticated"` — **no `WWW-Authenticate` header** | `pkg/api/middleware/auth.go` `AuthMiddleware.Middleware()` returns `fiber.NewError(fiber.StatusUnauthorized, "unauthenticated")` |
| The auth middleware resolves an `Identity` then loads gateway + `appconsumer.Data` and attaches to ctx — the **per-request consumer is already in reach** for a per-consumer challenge | `auth.go` `attach(...)` sets `appconsumer.ConsumerDataKey` |
| `oauth2` inbound config (issuer/jwks_url/audiences/required_scopes/algorithms) already exists — Phase 4 reuses it as the post-bootstrap validation backend | `pkg/domain/auth/config.go` `OAuth2Config` |
| Routes that must bypass the middleware chain are registered **before** `installMiddlewares(app, transport)` (Fiber `app.Use` only wraps later routes) | `pkg/server/router/proxy_router.go` registers `/healthz`/`/readyz` before `installMiddlewares` |
| Handler package layout = one dir per aggregate under `pkg/api/handler/http/<x>/` with `request/`+`response/` subpkgs, Swagger godoc, `helpers.WriteError`/`WriteCreated` | `pkg/api/handler/http/auth/create_auth_handler.go` |
| Secret-bearing columns are stored as a **hash, never plaintext**, with a partial unique index | `migrations/20260603140000_add_auth_key_hash.go` (`key_hash`), `repository/auth/repository.go` `nullableString(a.KeyHash)` |
| Migration idiom = Go `init()` + `database.RegisterMigration(Migration{ID,Name,Up,Down})`, single `tx.Exec`, `ADD COLUMN IF NOT EXISTS` + backfill, reversible `Down` | `migrations/20260603140000_add_auth_key_hash.go` |
| Repo idiom = raw pgx over `r.conn.Pool` / `database.WithTx`, `mapPgError` for `23505`/`23503`, `scan*` helper | `repository/auth/repository.go` |
| DI idiom = one `modules/<x>.go` with `c.Provide(constructor)`, named server instances, registered in `modules.All()`; routers consume a `Deps` struct so new handlers are struct fields, not positional args | `modules/auth.go`, `modules/server_proxy.go`, `router/admin_router.go` `AdminRouterDeps` |
| The reference (agentgateway) is an **RS + adapter/broker**, not a token issuer: it serves its own RFC 9728 doc, **proxies + rewrites** the IdP's RFC 8414 doc per `McpIDP`, and **proxies DCR** (adding CORS) or returns a mock DCR when a static `client_id` is set | `poc/agentgateway/crates/agentgateway/src/mcp/auth.rs` (`protected_resource_metadata`, `authorization_server_metadata`, `client_registration`, `build_mock_dcr_response`) |
| Per-IdP quirks the reference handles: Keycloak/Okta have no RFC 8414 (use OIDC discovery); Auth0/Okta need `?audience=` appended to `authorization_endpoint` (no RFC 8707); Keycloak/Okta DCR lacks CORS → rewrite `registration_endpoint` to a local proxied path | `auth.rs` `match auth.provider { Auth0/Okta/Keycloak ... }` |

The most consequential finding: **the consumer is already resolved inside the auth middleware before the
401 is emitted**, so a *per-consumer* challenge needs no new resolution path — only a new failure-branch
writer. And the reference implementation is unambiguously a **broker/adapter**, which anchors decision D1.

---

## Technical approach

TrustGate becomes an MCP **OAuth 2.1 Resource Server** plus a **thin Authorization Server facade** on the
Phase 3 MCP plane (`:8082`). It does **not** mint OAuth access tokens; the configured upstream IdP remains
the issuer and trust anchor. Phase 4 adds four things:

1. **The challenge (RS).** When a request hits an `mcp_oauth`-enabled consumer with no/invalid credential,
   the MCP auth middleware emits `401` + `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/v1/mcp/<consumer_id>"`
   (RFC 9728 §5.1) instead of today's bare 401.
2. **Protected-resource metadata (RFC 9728).** A new unauthenticated handler serves the per-consumer
   document: `resource` = the consumer's canonical MCP URL, `authorization_servers` = the issuer(s) of the
   consumer's `oauth2` `auth_ids`, `scopes_supported` = the consumer's `required_scopes`.
3. **AS metadata + DCR facade (RFC 8414 / RFC 7591).** A handler fetches the upstream IdP's metadata, runs
   it through a per-IdP **`IdPAdapter`** (audience injection, OIDC-discovery fallback, `registration_endpoint`
   rewrite, force `S256`), and serves it. DCR is **proxied** to the IdP by default (CORS added), returns a
   deterministic **mock** when a static `client_id` is configured, or is persisted **locally** in a new
   `oauth_clients` table for IdPs without DCR.
4. **Claims-challenge machinery.** A reusable `oauth.Challenge` + `WriteChallenge` helper emits the
   `WWW-Authenticate` header (with optional `error="insufficient_claims"` / `claims=…`), reused by Phase 5 to
   relay IdP `interaction_required` step-up challenges.

After the client obtains a token, **every subsequent request is just Phase 2 A2**: JWKS signature + `iss`/
`aud`/`exp`/`scope` validation against the consumer's `oauth2` Auth, producing the `identity.Principal`.
Phase 4 adds no steady-state hot-path cost; the OAuth dance is a one-time bootstrap.

The well-known + DCR routes mount on the MCP router **before** `installMiddlewares`, exactly like the Phase 3
health probes, so they are reachable without a credential.

---

## Decisions

### D1 — Broker / adapter (RS + thin AS facade), not a full token-issuing AS
- **Choice:** TrustGate is the **Resource Server** and an **AS facade**: it publishes its own RFC 9728 doc,
  and serves RFC 8414 AS metadata by **fetching the configured IdP's metadata and rewriting it** per IdP;
  the real IdP runs `/authorize` and `/token` and issues the access token (with `aud` = this gateway via a
  resource indicator / audience param). Post-bootstrap validation = Phase 2 JWKS (A2).
- **Rejected:** **AS-as-full-issuer** — TrustGate runs its own `/authorize` + `/token`, manages
  authorization-code + PKCE state, mints + signs its own access tokens, publishes its own JWKS, and stores
  client credentials/consent. Implications: a stateful auth-code store, a token signing key + key rotation, a
  confidential-client secret store, consent UI, and a second JWKS to operate — a large, security-critical
  surface that *duplicates the IdP*.
- **Rationale:** the reference implementation is a broker (`mcp/auth.rs`), the IdP stays the trust anchor,
  Phase 2's validator is reused unchanged, and the blast radius is tiny. The signing-key machinery the
  full-AS path would need is built once in **Phase 5 (STS)** for *downstream* tokens — we do not want a
  second, inbound issuer. `aud = gateway/consumer` is achieved via RFC 8707 `resource` (or the per-IdP
  `?audience=` workaround in D5/D9), not by issuing the token ourselves.

### D2 — Per-IdP behavior behind an `IdPAdapter` interface + a registry, not inline branching
- **Choice:** define `oauth.IdPAdapter` (resolve metadata source URL; rewrite the fetched AS-metadata
  document; resolve the DCR upstream URL + decide proxy vs local) and an `oauth.AdapterRegistry` keyed by
  `oauth.IDPKind` (`entra`/`okta`/`keycloak`/`auth0`/`google`/`generic`). The `generic` adapter is a no-op
  passthrough; concrete adapters override only the methods they need.
- **Rejected:** a single `switch auth.provider { … }` inside the handler (what the Rust code does today).
  Functional, but every new IdP edits the handler and every quirk is untested in isolation.
- **Rationale:** "accept interfaces, return structs" (golang.mdc); adding an IdP = one adapter + one golden
  fixture; the handler stays thin and the quirks become table-driven unit tests (D-testing).

### D3 — DCR: proxy-to-IdP by default; local `oauth_clients` store opt-in; secrets hashed/referenced, never stored plaintext
- **Choice:** three per-consumer DCR modes (`mcp_oauth.dcr`):
  - **`proxy`** (default) — forward the RFC 7591 body to the IdP's `registration_endpoint`, add CORS, return
    the IdP response unchanged. **No local row.**
  - **`static`** — operator pre-registered a `client_id` at the IdP; return a deterministic mock DCR response
    (`token_endpoint_auth_method: "none"`, `grant_types: ["authorization_code"]`, echo `redirect_uris`). **No
    secret, no row.**
  - **`local`** — TrustGate persists the registered client in a new `oauth_clients` table (for IdPs without
    DCR, or to normalize/audit registrations). Default to **public clients** (PKCE, `auth_method=none`) so no
    secret exists; if a confidential client is registered, store only a **`client_secret_hash`** (sha256, the
    `auths.key_hash` idiom) — the plaintext is returned once at registration and never persisted.
- **Rejected:** **in-memory-only** client store (lost on restart, not shared across MCP-plane replicas — the
  same anti-pattern the plan calls out for docker/mcp-gateway sessions); a plaintext `client_secret` column
  (violates the cross-cutting secret rule).
- **Rationale:** the broker default needs no table at all; the local store is opt-in for IdPs that can't DCR;
  public-client-first keeps us out of secret-storage entirely in the common case, and the hash fallback
  mirrors the audited `auths.key_hash` precedent.

### D4 — PKCE S256 enforced by metadata advertisement + DCR normalization (+ verifier check in `local` mode)
- **Choice:** with `mcp_oauth.pkce: true`, the rewritten AS metadata advertises
  `code_challenge_methods_supported: ["S256"]` only (strip `plain`), DCR responses force
  `token_endpoint_auth_method: "none"` (public client), and any local registration that requests `plain` is
  rejected. In broker mode the actual `code_verifier`↔`code_challenge` check happens at the IdP token
  endpoint; in `local`/full mode (future) TrustGate verifies S256 itself.
- **Rejected:** allowing `plain`; omitting `code_challenge_methods_supported` (lets a client silently
  downgrade).
- **Rationale:** MCP's OAuth profile mandates PKCE; S256 is the only secure method; advertising-only is the
  correct lever for a broker.

### D5 — Well-known + DCR routes mount before the auth middleware; the 401 is emitted *by* the middleware
- **Choice:** register `/.well-known/oauth-protected-resource/*`, `/.well-known/oauth-authorization-server/*`,
  and the local `…/client-registration` proxy route on `mcp_router.go` **before** `installMiddlewares(...)`
  (the Phase 3 health-probe precedent), so they are reachable unauthenticated. The challenge itself is
  emitted inside the MCP `AuthMiddleware` failure branch *after* it has resolved the consumer-by-path, so the
  `resource_metadata` URL is per-consumer.
- **Rejected:** an `is_well_known_endpoint(path)` allowlist *inside* the auth middleware (the Rust approach).
  It works, but Fiber's idiom here is route ordering (probes already do exactly this), and it keeps the auth
  middleware single-purpose rather than embedding path-string special-cases in the hot path.
- **Rationale:** matches the existing codebase seam verbatim; no string matching in the credential path.

### D6 — Per-consumer resource metadata, not per-gateway
- **Choice:** each virtual MCP server (consumer) is its own RFC 9728 protected resource. Metadata URL =
  `/.well-known/oauth-protected-resource/v1/mcp/<consumer_id>` (RFC 9728 path-insertion: the well-known
  segment is inserted *before* the resource's path `/v1/mcp/<id>`). `resource` = the consumer's canonical MCP
  URL; `authorization_servers` = issuer(s) from the consumer's `oauth2` `auth_ids`.
- **Rejected:** one per-gateway document — can't express a different IdP / audience / scope set per virtual
  server, and the plan's appendix (D6/A9) already specifies the per-consumer URL.
- **Rationale:** different consumers legitimately trust different IdPs and require different scopes; the
  resource identity must be the consumer.

### D7 — Scoped permissive CORS on the OAuth bootstrap routes only; proxy DCR to dodge IdP CORS gaps
- **Choice:** emit CORS (`Access-Control-Allow-Origin: *`, `…-Methods: GET, POST, OPTIONS`, `…-Headers:
  content-type, authorization`, `Access-Control-Expose-Headers: WWW-Authenticate`) and handle `OPTIONS`
  preflight on the well-known + DCR + 401-challenge responses **only**. For IdPs whose registration endpoint
  lacks CORS (Keycloak, Okta), the adapter rewrites `registration_endpoint` → the local `…/client-registration`
  proxy, which adds CORS (the agentgateway workaround).
- **Rejected:** relying on the IdP's own CORS (breaks browser MCP clients against Keycloak/Okta); a blanket
  permissive CORS middleware over the whole MCP plane (over-broad on the data path).
- **Rationale:** browser-based MCP clients (MCP Inspector, web-hosted agents) do CORS preflights against the
  metadata + DCR endpoints; scoping CORS to those routes is the reference behavior.

### D8 — One reusable `oauth.Challenge` builder, reused by Phase 5 step-up
- **Choice:** `oauth.Challenge{ ResourceMetadataURL, Error, ErrorDescription, Scope, ClaimsB64 }` + a
  `WriteChallenge(c *fiber.Ctx, ch oauth.Challenge) error` helper that sets the status (`401`), the
  `WWW-Authenticate: Bearer …` header, and a JSON body. Phase 4 emits it with just `resource_metadata`;
  Phase 5 emits it with `error="insufficient_claims"` + `claims="<base64url JSON>"` to relay an IdP
  `interaction_required` (RFC 9470-style step-up) from a downstream exchange.
- **Rejected:** bespoke `fiber.NewError`/header strings at each call site (drifts; Phase 5 would re-invent it).
- **Rationale:** the plan explicitly says the claims-challenge machinery is "introduced here and reused by
  Phase 5" — one builder, two callers.

### D9 — Resource binding via RFC 8707 `resource`, with per-IdP `audience` fallback
- **Choice:** prefer RFC 8707 resource indicators (`resource=<consumer MCP URL>`) so the issued token's `aud`
  binds to this gateway/consumer. For IdPs that don't support RFC 8707 (Auth0, Okta, Keycloak per the
  reference), the adapter falls back to injecting `?audience=<configured audience>` into the rewritten
  `authorization_endpoint`; Keycloak (no clean workaround) requires the operator to configure the audience
  mapper + the `audiences` value explicitly.
- **Rejected:** assuming every IdP honors `resource` (Auth0/Okta/Keycloak don't); ignoring audience binding
  (confused-deputy / token-reuse risk — the token would be valid at the IdP but not bound to us).
- **Rationale:** correct `aud` binding is what makes the post-bootstrap A2 validation meaningful and prevents
  a token minted for another resource from being replayed at TrustGate.

---

## Data flow

Full RS → AS → DCR → PKCE → token → validated-request sequence (builds on the plan's A9):

```mermaid
sequenceDiagram
  participant C as MCP client (CLI / browser)
  participant MW as MCP AuthMiddleware (:8082)
  participant OH as oauth handler (pre-mw routes)
  participant AD as IdPAdapter + registry
  participant CS as oauth_clients store (local mode only)
  participant I as Upstream IdP (Entra/Okta/Keycloak/Auth0/…)

  C->>MW: MCP request to /v1/mcp/<id>, no token
  MW->>MW: resolve consumer-by-path; mcp_oauth.enabled?
  MW-->>C: 401 + WWW-Authenticate: Bearer resource_metadata=".../oauth-protected-resource/v1/mcp/<id>"
  Note over C,MW: D5/D6/D8 — per-consumer challenge, emitted by the middleware

  C->>OH: GET /.well-known/oauth-protected-resource/v1/mcp/<id>  (unauthenticated, CORS)
  OH-->>C: RFC 9728 { resource, authorization_servers:[issuer], scopes_supported }

  C->>OH: GET /.well-known/oauth-authorization-server/v1/mcp/<id>
  OH->>AD: which metadata URL? (RFC 8414 vs OIDC discovery for Keycloak/Okta)
  OH->>I: GET AS / OIDC metadata
  I-->>OH: metadata JSON
  OH->>AD: rewrite (inject audience, force S256, rewrite registration_endpoint)
  OH-->>C: RFC 8414 { authorization_endpoint, token_endpoint, registration_endpoint, code_challenge_methods_supported:["S256"] }

  opt no client yet (RFC 7591 DCR)
    C->>OH: POST register (redirect_uris, …)
    alt dcr=proxy
      OH->>I: POST registration_endpoint (+CORS on response)
      I-->>OH: { client_id, ... }
    else dcr=static
      OH-->>OH: build mock DCR (operator client_id, auth_method=none)
    else dcr=local
      OH->>CS: persist client (public; or client_secret_hash)
    end
    OH-->>C: 201 { client_id, token_endpoint_auth_method:"none", ... }
  end

  C->>I: Authorization Code + PKCE (S256), resource=<consumer URL>
  I-->>C: access token (aud = gateway/consumer)

  C->>MW: MCP request + Authorization: Bearer eyJ...
  MW->>MW: Phase 2 A2 — JWKS sig + iss/aud/exp/scope -> identity.Principal
  MW-->>C: 200 + MCP response (Phase 3 toolkit)
```

Steady state after bootstrap is the dashed-free right-hand tail only: a cached-JWKS signature check. The
left/middle (challenge → metadata → DCR) runs once per client.

---

## Interfaces / contracts

New domain package `pkg/domain/oauth/` (RS/AS metadata, adapters, client store) — distinct from the inbound
`pkg/domain/auth` (which stays the validation backend). All Go names below are concrete proposals.

### IdP kind + the consumer `mcp_oauth` block (`pkg/domain/oauth/config.go`)
```go
type IDPKind string

const (
    IDPGeneric  IDPKind = "generic"  // RFC 8414 + RFC 7591, no quirks
    IDPEntra    IDPKind = "entra"
    IDPOkta     IDPKind = "okta"
    IDPKeycloak IDPKind = "keycloak"
    IDPAuth0    IDPKind = "auth0"
    IDPGoogle   IDPKind = "google"
)

func IsValidIDPKind(k IDPKind) bool { /* exhaustive switch */ }

type DCRMode string

const (
    DCRProxy  DCRMode = "proxy"  // forward to IdP registration_endpoint (default)
    DCRStatic DCRMode = "static" // mock response for a pre-registered client_id
    DCRLocal  DCRMode = "local"  // persist in oauth_clients
)

// MCPOAuthConfig is the consumer.mcp_oauth block (appendix C6/D6).
type MCPOAuthConfig struct {
    Enabled  bool     `json:"enabled"`
    DCR      DCRMode  `json:"dcr"`              // "proxy" if true-shorthand; see migration note
    PKCE     bool     `json:"pkce"`             // S256 enforced when true
    Provider IDPKind  `json:"provider,omitempty"`
    ClientID string   `json:"client_id,omitempty"` // DCRStatic: pre-registered at the IdP
    // Audiences/Scopes default to the linked oauth2 Auth's audiences/required_scopes
    // unless explicitly overridden here.
    Audiences []string `json:"audiences,omitempty"`
    Scopes    []string `json:"scopes,omitempty"`
}

func (c MCPOAuthConfig) Validate() error // dcr in {proxy,static,local}; static requires client_id; provider valid
```

### Metadata documents (`pkg/domain/oauth/metadata.go`)
```go
// ProtectedResourceMetadata is RFC 9728 §3 (served per-consumer).
type ProtectedResourceMetadata struct {
    Resource              string   `json:"resource"`
    AuthorizationServers  []string `json:"authorization_servers"`
    ScopesSupported       []string `json:"scopes_supported,omitempty"`
    BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"` // ["header"]
    ResourceName          string   `json:"resource_name,omitempty"`
}

// AuthorizationServerMetadata is RFC 8414 §2 (fetched upstream, rewritten per IdP).
type AuthorizationServerMetadata struct {
    Issuer                          string   `json:"issuer"`
    AuthorizationEndpoint           string   `json:"authorization_endpoint"`
    TokenEndpoint                   string   `json:"token_endpoint"`
    RegistrationEndpoint            string   `json:"registration_endpoint,omitempty"`
    JWKSURI                         string   `json:"jwks_uri,omitempty"`
    ScopesSupported                 []string `json:"scopes_supported,omitempty"`
    ResponseTypesSupported          []string `json:"response_types_supported,omitempty"`
    GrantTypesSupported             []string `json:"grant_types_supported,omitempty"`
    CodeChallengeMethodsSupported   []string `json:"code_challenge_methods_supported,omitempty"` // forced ["S256"]
    TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
    // Raw carries upstream fields we pass through untouched.
    Raw map[string]any `json:"-"`
}
```

### DCR request/response (`pkg/domain/oauth/dcr.go`, RFC 7591)
```go
type DCRRequest struct {
    RedirectURIs            []string `json:"redirect_uris"`
    ClientName              string   `json:"client_name,omitempty"`
    GrantTypes              []string `json:"grant_types,omitempty"`
    ResponseTypes           []string `json:"response_types,omitempty"`
    TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
    Scope                   string   `json:"scope,omitempty"`
}

type DCRResponse struct {
    ClientID                string   `json:"client_id"`
    ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
    ClientSecret            string   `json:"client_secret,omitempty"`        // confidential only; returned once
    ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
    RedirectURIs            []string `json:"redirect_uris"`
    GrantTypes              []string `json:"grant_types"`
    ResponseTypes           []string `json:"response_types"`
    TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`     // "none" for public clients
}

func (r DCRRequest) Validate(pkceRequired bool) error // require S256-capable public client when pkceRequired
```

### IdP adapter + registry (`pkg/domain/oauth/adapter.go`)
```go
// IdPAdapter encapsulates the per-IdP quirks behind a stable seam.
// Implementations live in pkg/infra/oauth/idp/ (entra.go, okta.go, …); generic is the no-op default.
type IdPAdapter interface {
    Kind() IDPKind
    // MetadataSourceURL returns the upstream URL to fetch AS metadata from
    // (RFC 8414 path-based for most; OIDC discovery for Keycloak/Okta).
    MetadataSourceURL(issuer string) string
    // RewriteASMetadata mutates the fetched document: inject audience into
    // authorization_endpoint (RFC 8707 fallback), force S256, rewrite
    // registration_endpoint to the local proxy when the IdP DCR lacks CORS.
    RewriteASMetadata(m *AuthorizationServerMetadata, req RewriteContext) error
    // RegistrationUpstreamURL returns the IdP DCR endpoint for dcr=proxy
    // (Okta's is org-relative, not issuer-relative).
    RegistrationUpstreamURL(issuer string) string
}

type RewriteContext struct {
    Issuer            string
    Audiences         []string
    LocalRegistration string // absolute URL of TrustGate's …/client-registration proxy
    PKCERequired      bool
}

type AdapterRegistry interface {
    For(kind IDPKind) IdPAdapter // never nil; falls back to the generic adapter
}
```

### Locally-registered client + store (`pkg/domain/oauth/client.go`, `repository.go`) — `dcr=local` only
```go
type Client struct {
    ID              ids.OAuthClientID   // UUID v7, == the issued client_id
    ConsumerID      ids.ConsumerID      // the virtual MCP server it was registered against
    TenantID        ids.OrgID           // Phase 1 scope (every row is tenant-scoped)
    RedirectURIs    []string
    GrantTypes      []string
    TokenEndpointAuthMethod string      // "none" (public) | "client_secret_basic"
    ClientSecretHash string             // sha256 hex; empty for public clients (mirrors auths.key_hash)
    CreatedAt       time.Time
}

type ClientStore interface {
    Save(ctx context.Context, scope tenant.Scope, c *Client) error
    FindByClientID(ctx context.Context, scope tenant.Scope, id ids.OAuthClientID) (*Client, error)
    DeleteByConsumer(ctx context.Context, scope tenant.Scope, consumerID ids.ConsumerID) error
}
```

### Challenge helper (`pkg/domain/oauth/challenge.go` + `pkg/api/handler/http/helpers`) — reused by Phase 5
```go
type Challenge struct {
    ResourceMetadataURL string // RFC 9728 §5.1
    Error               string // "" | "invalid_token" | "insufficient_scope" | "insufficient_claims"
    ErrorDescription    string
    Scope               string
    ClaimsB64           string // base64url OIDC claims request (Phase 5 step-up; "" in Phase 4)
}

// WWWAuthenticate renders the Bearer header value.
func (c Challenge) WWWAuthenticate() string

// WriteChallenge sets 401 + WWW-Authenticate + CORS expose-header + JSON body.
func WriteChallenge(c *fiber.Ctx, ch Challenge) error
```

The MCP `AuthMiddleware` failure branch builds the per-consumer `ResourceMetadataURL` from the resolved
consumer id + the request's external scheme/host (honoring `X-Forwarded-Proto`/`-Host`, like the reference's
`apply_forwarded_scheme`).

---

## Migration plan

New file `pkg/infra/database/migrations/20260606xxxxxx_add_mcp_oauth.go`, single transaction, Phase 1 idiom
(`init()` + `RegisterMigration`, `IF NOT EXISTS`, reversible `Down`).

**Up:**
1. **`oauth_clients` table** (only used by `dcr=local`; created regardless so the mode is available):
   ```sql
   CREATE TABLE IF NOT EXISTS oauth_clients (
       id          UUID PRIMARY KEY,                 -- == issued client_id
       tenant_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
       consumer_id UUID NOT NULL REFERENCES consumers(id)     ON DELETE CASCADE,
       redirect_uris            TEXT[] NOT NULL,
       grant_types              TEXT[] NOT NULL,
       token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
       client_secret_hash       TEXT,               -- sha256 hex; NULL for public clients
       created_at  TIMESTAMPTZ NOT NULL,
       updated_at  TIMESTAMPTZ NOT NULL
   );
   CREATE INDEX IF NOT EXISTS oauth_clients_consumer_idx ON oauth_clients (tenant_id, consumer_id);
   CREATE UNIQUE INDEX IF NOT EXISTS oauth_clients_secret_hash_uniq
       ON oauth_clients (client_secret_hash)
       WHERE token_endpoint_auth_method <> 'none' AND client_secret_hash IS NOT NULL;
   ```
   - `tenant_id` is `NOT NULL` and FK to `organizations` (Phase 1 invariant — every scoped row carries it);
     `consumer_id` cascades so deleting a virtual MCP server drops its registered clients.
   - **Secret handling (cross-cutting rule):** never a plaintext `client_secret` column — only
     `client_secret_hash` (sha256, the `auths.key_hash` precedent), and only for confidential clients.
2. **`consumers.mcp_oauth` column** — the `MCPOAuthConfig` block (jsonb, nullable; absent = disabled):
   ```sql
   ALTER TABLE consumers ADD COLUMN IF NOT EXISTS mcp_oauth JSONB;
   ```
   No backfill needed — `NULL`/absent means the challenge is off (backward compatible, opt-in per consumer).

**Down:** `DROP TABLE IF EXISTS oauth_clients;` then `ALTER TABLE consumers DROP COLUMN IF EXISTS mcp_oauth;`.

`ids.OAuthClientID` is added to the `ids.Kind` union (`OAuthClientKind`) in the same idiom Phase 1 adds
`OrgKind`/`TeamKind`.

---

## File changes (grouped into ≤400-line chained PRs)

Per `_base.mdc` the 400-line budget forces a split. Phase 4 ships as **3 stacked PRs** (4.1 → 4.3); each cut
is independently compilable + testable.

### PR 4.1 — Protected-resource metadata + the 401 challenge (RS half; ~360 LOC incl. tests)
| File | Action | Purpose |
|---|---|---|
| `pkg/domain/ids/ids.go` | Modify | Add `OAuthClientKind` + `OAuthClientID` to the `Kind` union |
| `pkg/domain/oauth/config.go` | Create | `IDPKind`, `DCRMode`, `MCPOAuthConfig` + `Validate` (no DCR/adapter logic yet — just enable + provider) |
| `pkg/domain/oauth/metadata.go` | Create | `ProtectedResourceMetadata` (RFC 9728) + builder from a consumer + its `oauth2` Auth(s) |
| `pkg/domain/oauth/challenge.go` | Create | `Challenge` + `WWWAuthenticate()` |
| `pkg/api/handler/http/helpers/challenge.go` | Create | `WriteChallenge` (401 + header + CORS expose + body) |
| `pkg/api/handler/http/oauth/protected_resource_handler.go` | Create | `GET /.well-known/oauth-protected-resource/v1/mcp/:consumer_id` (+CORS, +OPTIONS) |
| `pkg/api/middleware/auth.go` | Modify | When the resolved consumer has `mcp_oauth.enabled` and the credential is missing/invalid, emit `WriteChallenge` with the per-consumer `resource_metadata` URL instead of the bare 401 |
| `pkg/domain/consumer/consumer.go` + `…/request/*_consumer_request.go` + `response/consumer_response.go` | Modify | Add the `MCPOAuth *oauth.MCPOAuthConfig` field, DTO mapping, validation |
| `pkg/server/router/mcp_router.go` | Modify | Register the well-known route(s) **before** `installMiddlewares` (Phase 3 created this file) |
| `pkg/container/modules/oauth.go` | Create | Provide the protected-resource handler + challenge deps |
| `pkg/container/modules/modules.go`, `server_mcp.go` | Modify | Register the `OAuth` module; add handler to the MCP router `Deps` |
| `pkg/domain/oauth/*_test.go`, handler + middleware tests | Create | Metadata document correctness; challenge header format; opt-in on/off |

### PR 4.2 — DCR endpoint + client store + PKCE (~390 LOC)
| File | Action | Purpose |
|---|---|---|
| `pkg/infra/database/migrations/20260606xxxxxx_add_mcp_oauth.go` | Create | `oauth_clients` table + `consumers.mcp_oauth` column (idiom above) |
| `pkg/domain/oauth/dcr.go` | Create | `DCRRequest`/`DCRResponse` + `Validate(pkceRequired)` (force S256/public client) |
| `pkg/domain/oauth/client.go`, `repository.go` | Create | `Client` aggregate + `ClientStore` port |
| `pkg/infra/repository/oauthclient/repository.go` | Create | pgx `ClientStore` impl (tenant-scoped; `client_secret_hash`; `mapPgError`) |
| `pkg/api/handler/http/oauth/dcr_handler.go` | Create | `POST …/client-registration` — proxy / static-mock / local per `DCRMode`; +CORS |
| `pkg/infra/oauth/idpclient/client.go` | Create | Thin HTTP client used to proxy DCR + fetch metadata upstream (timeout, size-limit) |
| `pkg/server/router/mcp_router.go` | Modify | Mount the DCR route before middleware |
| `pkg/container/modules/oauth.go` | Modify | Provide the store, DCR handler, idp HTTP client |
| migration + repo + handler tests | Create | DCR happy/validation; PKCE S256 acceptance + `plain` rejection; mock-DCR echo; tenant-scoped store CRUD |

### PR 4.3 — AS metadata facade + per-IdP adapters (~390 LOC)
| File | Action | Purpose |
|---|---|---|
| `pkg/domain/oauth/adapter.go` | Create | `IdPAdapter`, `RewriteContext`, `AdapterRegistry` |
| `pkg/domain/oauth/metadata.go` | Modify | `AuthorizationServerMetadata` (RFC 8414) struct + JSON round-trip |
| `pkg/infra/oauth/idp/generic.go` | Create | No-op passthrough adapter (RFC 8414 + RFC 7591) |
| `pkg/infra/oauth/idp/entra.go` | Create | Entra: `{tid}` issuer, RFC 8707 `resource`, v2 metadata path |
| `pkg/infra/oauth/idp/okta.go` | Create | OIDC-discovery metadata; `?audience=` append; org-relative DCR URL; CORS-proxy registration |
| `pkg/infra/oauth/idp/keycloak.go` | Create | OIDC-discovery metadata; audience-mapper note; CORS-proxy registration |
| `pkg/infra/oauth/idp/auth0.go` | Create | `?audience=` append on `authorization_endpoint` |
| `pkg/infra/oauth/idp/google.go` | Create | Generic + Google caveat (opaque access tokens → A6 introspection downstream) |
| `pkg/infra/oauth/idp/registry.go` | Create | `AdapterRegistry` impl keyed by `IDPKind`, generic fallback |
| `pkg/api/handler/http/oauth/as_metadata_handler.go` | Create | `GET /.well-known/oauth-authorization-server/v1/mcp/:consumer_id` — fetch + adapter-rewrite + serve |
| `pkg/container/modules/oauth.go` | Modify | Provide the registry + AS-metadata handler |
| adapter + handler tests | Create | Per-IdP golden fixtures (input upstream doc → rewritten output); CORS preflight |

> Stacking: 4.1 turns on the *challenge* and is mergeable alone (a client gets a correct 401 + protected-resource
> doc, then talks to the IdP directly using a pre-known AS). 4.2 adds DCR + storage. 4.3 adds the AS-metadata
> facade + per-IdP rewrites. If 4.3 exceeds budget at implementation time, cut at the adapter boundary
> (4.3a: interface + registry + generic + AS handler; 4.3b: the five concrete IdP adapters + fixtures).

---

## Testing strategy

| Layer | What to test | How |
|---|---|---|
| Unit (table-driven) | `ProtectedResourceMetadata` builder: `resource` = consumer URL, `authorization_servers` = `oauth2` issuer(s), `scopes_supported` = `required_scopes`; per-consumer URL path-insertion | Pure, `testify/require`, `t.Parallel()` |
| Unit | `Challenge.WWWAuthenticate()` / `WriteChallenge`: exact `Bearer resource_metadata="…"` format; `insufficient_claims` + `claims=` variant (Phase 5 forward-compat); CORS expose header present | Fiber test app |
| Unit | `MCPOAuthConfig.Validate` + `DCRRequest.Validate`: `dcr` enum, `static` requires `client_id`, S256/public-client enforced when `pkce` | Pure |
| Unit (golden fixtures) | Per-IdP `RewriteASMetadata`: Entra resource indicator; Auth0/Okta `?audience=` appended; Keycloak/Okta `registration_endpoint` → local proxy; `code_challenge_methods_supported` forced to `["S256"]`; OIDC-discovery vs RFC 8414 source URL | One captured upstream metadata JSON per IdP → assert rewritten output |
| Unit | `AdapterRegistry.For(unknown)` → generic (never nil) | Pure |
| Integration | DCR happy paths: `proxy` (mock upstream IdP returns `client_id`, CORS added), `static` (deterministic mock, `auth_method=none`, echoes `redirect_uris`), `local` (row persisted; public client has no secret; confidential stores only the hash) | httptest IdP + real Postgres test DB (build-tagged) |
| Integration | `oauth_clients` store: tenant-scoped find/save/delete; cross-tenant `FindByClientID` → `ErrNotFound`; `consumer_id` cascade delete | Real Postgres test DB |
| Integration | Middleware end-to-end: unauthenticated request to an `mcp_oauth` consumer → `401` + correct per-consumer `resource_metadata`; valid Bearer (mock JWKS) falls through to Phase 2 A2 → `Principal`; `mcp_oauth` off → today's bare 401 unchanged | Fiber app + mock JWKS |
| Integration | CORS preflight: `OPTIONS` to well-known + DCR routes returns the allow-headers/methods; the routes are reachable **without** a credential (mounted before middleware) | Fiber app |
| Functional (E2E) | Extend `tests/functional/`: full A9 bootstrap against a mock IdP (challenge → metadata → DCR → token → validated MCP call) | Mock IdP + mock upstream MCP server |

Assert on behavior (header string, document fields, `ErrNotFound`), never on internal SQL/struct layout
(`_base.mdc`). New code paths get tests (none are `WIP`/`docs-only`).

---

## Migration / rollout

- **Opt-in per consumer.** The challenge only fires when `consumers.mcp_oauth.enabled = true`. The column is
  nullable and absent-by-default, so **every existing consumer is unaffected** — `mcp_oauth = NULL` means the
  MCP plane keeps emitting today's bare 401 and validating whatever Phase 2 credential is configured.
- **Backward compat with Phase 2/3.** Phase 4 adds no steady-state behavior: once a client holds a token,
  validation is exactly the Phase 2 A2 JWKS path. A consumer can use `mcp_oauth` *and* still accept API
  key / mTLS via its other `auth_ids` (the OR-set from A8) — the challenge is additive, not exclusive.
- **`oauth_clients` is inert until used.** The table ships in 4.2 but only `dcr=local` writes to it; `proxy`
  (default) and `static` never touch it, so the common deployment carries no client state.
- **Deploy order:** migrate (adds the column + table) → roll out the MCP-plane binary. Old binaries tolerate
  the new column (they ignore it), so a rolling deploy is safe. No feature flag is required beyond the
  per-consumer `enabled` toggle.
- **Secrets:** in the recommended public-client path there is nothing to store. If an operator enables a
  confidential `dcr=local` client, only the secret *hash* is persisted (sourced/rotated like `auths.key_hash`),
  and the plaintext is returned exactly once at registration time — never logged, never re-served.

---

## Open questions (lock before implementation)

1. **Broker vs full AS (OQ1).** *Recommended: broker/adapter (D1).* Confirm we are **not** issuing inbound
   OAuth access tokens in Phase 4 and that the IdP stays the issuer — the only signing key TrustGate operates
   is the Phase 5 STS key (downstream). Lock this before any handler is written; it determines whether 4.x
   needs an auth-code state store at all (it should not).
2. **Which IdPs ship first (OQ2).** *Recommended: `generic` + `entra` + `okta` in 4.3a; `keycloak` + `auth0`
   + `google` in 4.3b.* Entra/Okta are the enterprise priority and exercise both quirk classes (resource
   indicator vs `?audience=`, RFC 8414 vs OIDC discovery, CORS-proxy DCR). Confirm the priority order.
3. **Client-secret storage (OQ3).** *Recommended: public clients only by default (PKCE, `auth_method=none`),
   hash-only fallback for confidential `dcr=local`.* Confirm we never store a plaintext client secret and that
   the hash column is acceptable, or whether confidential clients should be **disallowed entirely** in v1
   (simplest, and aligned with the MCP public-client norm).
4. **Public clients only? (OQ4).** *Recommended: yes for v1* — MCP clients are overwhelmingly public
   (native/CLI/browser) and PKCE is the spec default. If we restrict to public clients, the `client_secret_hash`
   column and confidential branch in D3 can be dropped from 4.2, shrinking the PR. Decide before 4.2.
5. **`mcp_oauth.dcr` shape (OQ5).** The appendix shows `dcr` as a boolean; D3 needs a `proxy|static|local`
   enum. *Recommended: accept the boolean as `true ⇒ proxy` / `false ⇒ DCR disabled`, with the enum as the
   richer form.* Confirm the wire shape so the consumer DTO + migration match.
6. **Resource-indicator strategy per consumer (OQ6).** *Recommended: RFC 8707 `resource` where supported,
   `?audience=` fallback (D9).* Confirm the canonical `resource` value = the consumer's external MCP URL
   (`https://<gw-host>/v1/mcp/<id>`) and how it's derived behind a proxy (trust `X-Forwarded-Proto/Host`).
7. **Where DCR-disabled lands (OQ7).** If a consumer has `mcp_oauth.enabled=true` but DCR off and no
   pre-registered `client_id`, the AS-metadata doc should omit `registration_endpoint`. *Recommended: omit it
   and document that the operator must pre-provision a client at the IdP.* Confirm this is acceptable for the
   first release rather than hard-failing config validation.
