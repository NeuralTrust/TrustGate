# Design: Enterprise Agent Skills governance

Full technical design for the skills-governance capability described in
`proposal.md` / `exploration.md`. The target picture: **a per-gateway skill
registry managed by the platform admin — mirroring how MCP registries work today —
where skills are ingested, reviewed, version-pinned, attached to consumers, and
served to agents over the existing MCP plane (SEP-2640) and an authenticated HTTP
sync manifest.**

Everything below follows the repo's hexagonal layering and names real extension
points verified in the current codebase.

---

## 1. Entity model

```
Gateway 1 ──── * Skill ──── * SkillVersion ──── * SkillFile
                  │                │
                  │ pinned_version │ state: pending → approved | rejected
                  ▼
Consumer.MCP.SkillPolicy (grants)          Role.MCPPolicies (same shape, unioned)
```

| Entity | Analogy in MCP feature | Notes |
|---|---|---|
| `Skill` | `Registry{Type: MCP}` | Per-gateway, identified by `code` (= frontmatter `name`), carries the pin |
| `SkillVersion` | — (new) | Immutable content snapshot with digest + review state |
| `SkillFile` | — (new) | One file of a version (path, mime, bytes, per-file sha256) |
| `SkillPolicy` grant | `Toolkit` entry | Attaches skills to a consumer; role-based mode unions them |
| Curated seed (phase 3) | `seed/mcp-catalog/` | Read-only prefill catalog, embedded |

Key invariants:

- `Skill.Code` is unique per gateway and MUST satisfy agentskills.io naming
  (`^[a-z0-9]+(-[a-z0-9]+)*$`, ≤64 chars). It equals the `SKILL.md` frontmatter
  `name` and becomes the final `skill://` path segment (SEP-2640 rule).
- A `SkillVersion` is immutable after creation. State machine:
  `pending → approved` or `pending → rejected` (single transition, recorded with
  reviewer identity + timestamp). No other transitions.
- The data plane serves **only** the pinned version, and a version can be pinned
  **only** when `approved`. Unpinning (or disabling the skill) removes it from
  every surface at the next cache refresh.
- Version numbers are a per-skill monotonic integer (`v1, v2, …`); the digest is
  the identity the outside world sees.

## 2. Domain layer — `pkg/domain/skill/`

New ID kinds in `pkg/domain/ids/ids.go` (added to the `Kind` union):

```go
type (
    SkillKind        struct{}
    SkillVersionKind struct{}
)
type (
    SkillID        = ID[SkillKind]
    SkillVersionID = ID[SkillVersionKind]
)
```

Aggregate (`skill.go`, `version.go`, `file.go`, `errors.go`, `repository.go`):

```go
type Skill struct {
    ID              ids.SkillID
    GatewayID       ids.GatewayID
    Code            string            // == frontmatter name, immutable after create
    DisplayName     string
    Description     string            // denormalized from the pinned version frontmatter
    Enabled         bool
    PinnedVersionID *ids.SkillVersionID
    Labels          map[string]string // free-form admin taxonomy (team, domain, tier)
    CreatedAt, UpdatedAt time.Time
}

type VersionState string
const (
    VersionPending  VersionState = "pending"
    VersionApproved VersionState = "approved"
    VersionRejected VersionState = "rejected"
)

type SkillVersion struct {
    ID          ids.SkillVersionID
    SkillID     ids.SkillID
    Version     int
    State       VersionState
    Frontmatter map[string]any // verbatim parsed YAML; only name/description validated
    Description string
    Digest      string         // sha256 over the canonical file manifest (see §4)
    TotalBytes  int64
    Source      *Source        // {Type: upload|git|catalog, GitURL, GitRef, Commit}
    Scan        *ScanResult    // {Verdict, Engine, EngineVersion, ScannedAt, Digest}
    Review      *Review        // {ReviewedBy, ReviewedAt, Note}
    CreatedBy   string
    CreatedAt   time.Time
}

type SkillFile struct {
    Path   string // relative, '/'-separated, validated (no "..", no leading '/', no nested SKILL.md)
    Mime   string
    Size   int64
    Digest string // sha256 of the file bytes
    // Content loaded lazily via the repository (never held on list paths)
}
```

Domain validation (all in the aggregate, handlers stay thin):

- `SKILL.md` present at the root; frontmatter parses as YAML; `name` (== `Code`)
  and `description` non-empty. **No other frontmatter fields are validated or
  interpreted** — the folder is stored verbatim so future agentskills.io fields
  pass through (spec-drift resilience).
- Path safety: reject `..` segments, absolute paths, empty segments, symlink
  entries in uploaded archives, and any `SKILL.md` below the root (skills do not
  nest — SEP-2640 constraint).
- Size caps (config, `pkg/config`, env-driven like everything else):
  `SKILL_MAX_VERSION_BYTES` (default 2 MiB), `SKILL_MAX_FILE_COUNT` (default 200),
  `SKILL_MAX_FILE_BYTES` (default 1 MiB). Text-first: binary mimes rejected above
  a small threshold unless `assets/`-pathed.
- State machine transitions return domain errors (`ErrVersionNotPending`,
  `ErrVersionNotApproved`, `ErrSkillNotPinned`, `ErrPinnedVersionRemoval`, …).

Repository ports (segregated, consumer-defined, `//go:generate mockery`):

```go
type Repository interface {
    Save(ctx context.Context, s *Skill) error
    Get(ctx context.Context, gatewayID ids.GatewayID, id ids.SkillID) (*Skill, error)
    GetByCode(ctx context.Context, gatewayID ids.GatewayID, code string) (*Skill, error)
    List(ctx context.Context, gatewayID ids.GatewayID) ([]*Skill, error)
    Delete(ctx context.Context, gatewayID ids.GatewayID, id ids.SkillID) error

    SaveVersion(ctx context.Context, v *SkillVersion, files []SkillFileContent) error
    GetVersion(ctx context.Context, id ids.SkillVersionID) (*SkillVersion, error)
    ListVersions(ctx context.Context, skillID ids.SkillID) ([]*SkillVersion, error)
    UpdateVersionState(ctx context.Context, v *SkillVersion) error

    ListFiles(ctx context.Context, versionID ids.SkillVersionID) ([]SkillFile, error)
    ReadFile(ctx context.Context, versionID ids.SkillVersionID, path string) ([]byte, SkillFile, error)
}

// Reader is the data-plane view (also implemented by the runtimeconfig snapshot repo).
type Reader interface {
    ResolvePinned(ctx context.Context, gatewayID ids.GatewayID, skillIDs []ids.SkillID) ([]*ResolvedSkill, error)
    ReadPinnedFile(ctx context.Context, skillID ids.SkillID, path string) ([]byte, SkillFile, error)
}

// ResolvedSkill is what the data plane needs: skill + pinned version metadata +
// file manifest, no content.
type ResolvedSkill struct {
    Skill   *Skill
    Version *SkillVersion
    Files   []SkillFile
}
```

## 3. Storage — Postgres migration

`pkg/infra/database/migrations/2026XXXXXXXXXX_add_skills.go`, same
`RegisterMigration` pattern as `20260609200000_add_mcp_registry_and_toolkit.go`:

```sql
CREATE TABLE IF NOT EXISTS skills (
    id UUID PRIMARY KEY,
    gateway_id UUID NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    display_name TEXT,
    description TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    pinned_version_id UUID,
    labels JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (gateway_id, code)
);

CREATE TABLE IF NOT EXISTS skill_versions (
    id UUID PRIMARY KEY,
    skill_id UUID NOT NULL REFERENCES skills(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','approved','rejected')),
    frontmatter JSONB NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    digest TEXT NOT NULL,
    total_size_bytes BIGINT NOT NULL,
    source JSONB,
    scan JSONB,
    review JSONB,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (skill_id, version)
);

CREATE TABLE IF NOT EXISTS skill_files (
    version_id UUID NOT NULL REFERENCES skill_versions(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    digest TEXT NOT NULL,
    content BYTEA NOT NULL,
    PRIMARY KEY (version_id, path)
);

ALTER TABLE skills ADD CONSTRAINT skills_pinned_version_fk
    FOREIGN KEY (pinned_version_id) REFERENCES skill_versions(id);

ALTER TABLE consumers ADD COLUMN IF NOT EXISTS skill_policy JSONB;
ALTER TABLE roles     ADD COLUMN IF NOT EXISTS skill_policy JSONB;
```

Rationale for BYTEA-in-Postgres over object storage: versions are capped at
2 MiB text-first content, approval demands byte-exact serving of what was
reviewed, and it keeps DB-less snapshotting and backup/restore trivial. Revisit
only if caps ever need to grow by orders of magnitude.

## 4. Digests (the identity everything keys on)

- **Per-file digest:** `sha256(file bytes)`, hex.
- **Version digest:** `sha256` over the canonical manifest — files sorted by
  path, each contributing `"{path}\n{file-digest}\n"`. Deterministic, covers the
  whole tree (the SEP discussion's main criticism of SKILL.md-only digests), and
  stable across storage backends.
- **Archive determinism:** the `.tar.gz` form (§8) is generated with sorted
  entries, zeroed mtimes and uid/gid, so the archive bytes — and therefore any
  client-side archive digest — are reproducible for a given version digest.

These digests are: the sync manifest integrity field, the SEP-2640 manifest
`digest` values, the key for scan attestations in `_meta`, and the trigger for
client-side content-bound approval (digest rotation under a stable name).

## 5. Admin API (control plane, `:8080`)

Handlers in `pkg/api/handler/http/skill/` (one file per handler + `request/`
DTOs, swagger annotations — same layout as `pkg/api/handler/http/registry/`).
Routes in `admin_router.go` under the gateway group, guarded by
`RequireGatewayAccess(middleware.ResourceSkills)` (new resource constant):

| Method | Path | Handler / behavior |
|---|---|---|
| POST | `/v1/gateways/:gateway_id/skills` | Create skill + ingest v1. Body: multipart zip, inline `files[]` JSON, or `{git_url, git_ref, subdir}` |
| GET | `/v1/gateways/:gateway_id/skills` | List (filters: `enabled`, `label`, `state`) |
| GET | `/v1/gateways/:gateway_id/skills/:id` | Get with versions summary + grants count |
| PUT | `/v1/gateways/:gateway_id/skills/:id` | Mutable metadata only: `display_name`, `labels`, `enabled` |
| DELETE | `/v1/gateways/:gateway_id/skills/:id` | Delete (rejected while granted to any consumer/role unless `?force=true`, which detaches) |
| POST | `/v1/gateways/:gateway_id/skills/:id/versions` | Ingest a new version (same sources as create) |
| GET | `/v1/gateways/:gateway_id/skills/:id/versions` | List versions (state, digest, reviewer, sizes) |
| GET | `/v1/gateways/:gateway_id/skills/:id/versions/:version_id` | Version detail + file manifest |
| GET | `/v1/gateways/:gateway_id/skills/:id/versions/:version_id/files/*path` | Raw file download (review UX) |
| POST | `/v1/gateways/:gateway_id/skills/:id/versions/:version_id/review` | `{action: "approve"\|"reject", note}` — **interactive identity required** |
| POST | `/v1/gateways/:gateway_id/skills/:id/pin` | `{version_id}` — must be approved; repins atomically |
| POST | `/v1/gateways/:gateway_id/consumers/:id/skills/:skill_id` | Attach grant (mirrors `AttachRegistry`) |
| DELETE | `/v1/gateways/:gateway_id/consumers/:id/skills/:skill_id` | Detach grant |
| POST | `/v1/gateways/:gateway_id/roles/:role_id/skills/:skill_id` | Attach grant to role |
| DELETE | `/v1/gateways/:gateway_id/roles/:role_id/skills/:skill_id` | Detach from role |
| GET | `/v1/skills-catalog` | Phase 3: curated embedded catalog (mirrors `/v1/mcp-servers-catalog`, `AdminAuth` + `RequireInteractiveIdentity()`) |

Use cases in `pkg/app/skill/` (one interface per use case): `Ingestor`
(upload/git/catalog → validate → digest → `pending` version), `Reviewer`
(state transition + reviewer identity from the admin auth context), `Pinner`,
`Finder`, `Updater`, `Deleter`, `GrantService` (attach/detach with referential
validation), `ManifestBuilder` (§8).

Enterprise controls on review:

- The review endpoint runs behind `RequireInteractiveIdentity()` — machine
  credentials can ingest (CI pipelines publishing skills) but **cannot approve**.
- Optional separation of duties: `SKILL_REVIEW_FORBID_SELF_APPROVAL=true` rejects
  a review whose identity equals `CreatedBy`.
- Git ingestion records `{git_url, git_ref, commit}` in `Source` for provenance;
  the fetch happens on the admin plane with the same egress posture as catalog
  sync, and is optional (feature-flagged off in air-gapped deployments).

## 6. Consumer & role attachment — `SkillPolicy`

The existing `Toolkit` is keyed by `ids.RegistryID`
(`pkg/domain/consumer/toolkit.go`), so skills — which are gateway-owned, not
upstream-owned — get their own policy struct rather than a fourth toolkit kind
(this supersedes the earlier proposal sketch):

```go
// pkg/domain/consumer/skill_policy.go
type SkillGrant struct {
    SkillID ids.SkillID `json:"skill_id"`
}

type SkillPolicy struct {
    All        bool         `json:"all,omitempty"`         // wildcard: every enabled+pinned skill of the gateway
    Grants     []SkillGrant `json:"grants,omitempty"`
    HelperTool *bool        `json:"helper_tool,omitempty"` // expose the load_skill fallback tool (default true)
}

type MCPPolicy struct {
    Toolkit  Toolkit      `json:"toolkit"`
    FailMode FailMode     `json:"fail_mode,omitempty"`
    Skills   *SkillPolicy `json:"skills,omitempty"`
}
```

- Validation in `MCPPolicy.Validate`: grant IDs unique, non-nil; the app-layer
  `GrantService` additionally verifies each skill belongs to the same gateway.
- **Closed by default:** `Skills == nil` ⇒ no skill surface at all. Existing
  consumers are untouched (compatibility guarantee).
- `Consumer.Validate` already restricts `MCP` to `TypeMCP` consumers; skills
  inherit that for free.
- **Role-based mode:** `role.MCPPolicies` aliases `consumer.MCPPolicy`, so
  `SkillPolicy` rides along. `RoleScoper` (`pkg/app/mcp/role_scope.go`) unions
  grants across matched roles (set-union of `SkillID`s; `All` if any role sets
  it) — additive, consistent with toolkit union semantics.
- `RoutableConsumer` (`pkg/app/consumer/consumer_data.go`) gains
  `Skills []*skilldomain.ResolvedSkill`, hydrated by the consumer data loader
  (and by the runtimeconfig snapshot in DB-less mode) from the effective grants:
  enabled skills, pinned + approved versions only, metadata + file manifest, no
  content.

## 7. Data plane — SEP-2640 on the virtual MCP server (`:8082`)

All SEP specifics are isolated in one adapter file pair
(`pkg/app/mcp/skills.go` + `pkg/api/handler/http/mcp/skills_rpc.go`) so spec
churn (the extension is Extensions Track and has already had one breaking
revision) touches exactly one seam.

### 7.1 SkillProvider (app layer)

```go
// pkg/app/mcp/skills.go
type SkillProvider interface {
    List(ctx context.Context, rc *appconsumer.RoutableConsumer, cursor string) ([]SkillEntry, string, error)
    Get(ctx context.Context, rc *appconsumer.RoutableConsumer, uri string) (*SkillEntry, error)
    Read(ctx context.Context, rc *appconsumer.RoutableConsumer, uri string) (json.RawMessage, bool, error)
    Resources(rc *appconsumer.RoutableConsumer) []Resource
    Instructions(rc *appconsumer.RoutableConsumer) string
    Fingerprint(rc *appconsumer.RoutableConsumer) []string
}
```

Backed by `skill.Reader` plus a `cache.TTLMap` for file content
(`cache.SkillContentTTLName`), invalidated by the existing config-sync signal on
any skill mutation (same mechanism registries/consumers use today).

### 7.2 URI namespace and routing

Governed skills live at `skill://{code}/{path}` on the virtual server.
`composer.ReadResource` is extended: URIs with the `skill://` scheme are offered
to the `SkillProvider` first; on not-found they fall through to upstream
federation unchanged (an upstream MCP server may legitimately serve its own
`skill://` resources — e.g. a SEP-2640 upstream — and those keep working; a
governed code shadows an upstream skill of the same code, deterministic and
documented). `resources/list` output is the upstream federation **plus** the
provider's entries for granted skills.

### 7.3 New RPC methods

`RPCGateway.dispatch` (`pkg/api/handler/http/mcp/rpc_dispatcher.go`) gains two
cases, gated on the consumer having any effective skill grants (otherwise
`ErrMethodNotFound`, preserving today's surface exactly):

- `skills/list` → paginated entries. Rate-limit check first (like every method),
  then `plugins.PreResponseDiscovery` over the marshaled listing — the same
  indirect-prompt-injection scan `tools/list` gets today.
- `skills/get` → one entry by URI; `-32602` for a URI that is not a governed
  skill (per SEP).

Entry shape (SEP-2640 v1):

```json
{
  "name": "refund-workflow",
  "title": "Refund workflow",
  "description": "Process customer refunds per policy",
  "uri": "skill://refund-workflow/SKILL.md",
  "frontmatter": { "name": "refund-workflow", "description": "…", "…": "verbatim" },
  "resources": [
    { "uri": "skill://refund-workflow/SKILL.md",            "digest": "sha256:…" },
    { "uri": "skill://refund-workflow/references/POLICY.md","digest": "sha256:…" }
  ],
  "_meta": {
    "io.modelcontextprotocol.skills/verification": {
      "digest": "sha256:…",
      "verdict": "clean",
      "verifier": "trustguard",
      "verifierVersion": "…",
      "verifiedAt": "2026-08-27T00:00:00Z"
    },
    "ai.neuraltrust.trustgate/governance": {
      "version": 4,
      "approvedAt": "2026-08-20T00:00:00Z",
      "pinDigest": "sha256:…"
    }
  }
}
```

`_meta` policy: the scan attestation uses the Working-Group-reserved neutral
prefix `io.modelcontextprotocol.skills/` and is **keyed to the digest it
vouches for** (never to name or URI — binding to a key rather than bytes
re-imports the ambiguity the digest exists to solve). TrustGate-specific
governance facts ride under our own reverse-domain prefix
`ai.neuraltrust.trustgate/` so they can never be confused with spec-defined
fields. Reviewer identities are **not** exposed on the data plane (PII stays in
the admin API/audit log); `approvedAt` and version number are.

### 7.4 initialize: capability, instructions, fingerprint

`handleInitialize` (`pkg/api/handler/http/mcp/mcp_handler.go`):

- When the consumer has effective grants, add
  `"extensions": {"io.modelcontextprotocol/skills": {}}` to `capabilities`.
- Append a bounded skills index to `instructions` (name + one-line description +
  `SKILL.md` URI per skill, capped at 50 entries / 4 KiB, then a pointer to
  `skills/list`) — the SEP-blessed zero-client-code discovery path.
- `surfaceFingerprint` additionally folds in
  `skill:{skillID}@{pinDigest}` per granted skill, so clients that cache the
  tool/skill surface re-list after a repin, exactly like a registry change today.

### 7.5 `load_skill` fallback tool

For pre-SEP, tool-only harnesses. Appended by the composer's `ListTools` when
`SkillPolicy.HelperTool` resolves true (default) and grants exist:

```json
{ "name": "load_skill",
  "description": "Load an approved skill's SKILL.md instructions into context. Skills available: <name — description, …>",
  "inputSchema": { "type": "object",
    "properties": { "name": { "type": "string" } }, "required": ["name"] } }
```

Handled in `CallTool` before upstream federation (reserved name; an upstream
tool named `load_skill` is shadowed while the policy enables the helper —
documented). The result embeds the skill's base URI and file list so the model
can fetch supporting files via `resources/read`. Calls flow through
`plugins.PreRequest` / `PreResponse` like any tool call — meaning trustguard,
rate limiting, and `per_tool_rate_limiter` policies apply to skill loads with
zero new plugin work.

### 7.6 Telemetry

`mcpRequestAttrs` classifies `skills/list` as `discovery` and
`skills/get`/`resources/read` of `skill://` URIs as operation `skill`, with the
skill code and digest annotated on the span (new `span.SetMCPSkill(code, digest,
version)`), so per-skill usage, latency and denial metrics come out of the
existing o11y pipeline. Policy denials reuse `codePolicyBlocked` / HTTP 200
semantics (transport-safe, like toolkit denials today).

## 8. HTTP sync manifest (disk-discovery channel)

Routes on the MCP plane (`pkg/server/router/mcp_router.go`), registered
**before** the `app.Get("/*")` method-not-allowed catch-all, behind the same
middleware chain as `/{slug}/mcp` (`MCPAuthMiddleware`: mTLS > bearer > API key;
metrics middleware; gateway rate-limit check in the handler):

| Method | Path | Response |
|---|---|---|
| GET | `/:slug/skills` | Manifest JSON (below). `ETag` = manifest digest; honors `If-None-Match` → 304 |
| GET | `/:slug/skills/:code` | Single-skill entry (files + digests) |
| GET | `/:slug/skills/:code/files/*path` | Raw bytes, stored mime type, `ETag` = file digest |
| GET | `/:slug/skills/:code/archive.tar.gz` | Deterministic gzip tar of the pinned version (atomic multi-file fetch) |

Manifest schema — the agentskills.io discovery index shape with integrity
fields, so future SEP/agentskills tooling parses it:

```json
{
  "$schema": "https://schemas.agentskills.io/discovery/0.2.0/schema.json",
  "generated_at": "2026-08-27T00:00:00Z",
  "consumer": "acme-eng",
  "skills": [
    {
      "name": "refund-workflow",
      "type": "skill-md",
      "description": "Process customer refunds per policy",
      "url": "/acme-eng/skills/refund-workflow/files/SKILL.md",
      "version": 4,
      "digest": "sha256:…",
      "archive_url": "/acme-eng/skills/refund-workflow/archive.tar.gz",
      "files": [
        { "path": "SKILL.md", "size": 1832, "digest": "sha256:…" },
        { "path": "references/POLICY.md", "size": 9120, "digest": "sha256:…" }
      ]
    }
  ]
}
```

The documented reference sync (docs page + example script, ~30 lines of
curl+jq): fetch manifest → diff against a lockfile
(`.cursor/skills/managed/.trustgate-lock.json`) → download changed files to a
temp dir → verify digests → atomic rename into the managed subtree → delete
lockfile entries absent from the manifest. Triggers per the strategies section
of `exploration.md` (session-start hook, devcontainer boot, CI, MDM).

## 9. DB-less mode (config-sync snapshots)

`pkg/runtimeconfig` snapshot data gains a `Skills` section per gateway: for each
granted skill, the `ResolvedSkill` (skill + pinned version metadata + file
manifest) **and file contents** — bounded by the 2 MiB/version cap, and only
pinned+approved versions of granted skills ship in snapshots (pending/rejected
versions and ungranted skills never leave the control plane). The snapshot
repository implements `skill.Reader`, so the data plane is storage-agnostic.
Any skill mutation emits the existing config-sync signal, which also flushes the
data-plane TTL caches.

## 10. Curated seed catalog (phase 3)

Mirrors `seed/mcp-catalog/` exactly:

- `seed/skills-catalog/` — one folder per curated skill (the real
  `SKILL.md` + files), plus `index.json` (code, display name, category,
  description, relevance) and `embed.go` with `//go:embed`.
- `pkg/domain/catalog/skill.go` + `pkg/app/catalog/skills.go`
  (`SkillCatalog.List/GetByCode`) + handler + `GET /v1/skills-catalog` route.
- "Install from catalog" = the ingest use case with `Source{Type: "catalog"}` —
  the seed content is copied into a normal tenant `SkillVersion`, which then goes
  through the same review/pin flow (a platform-curated skill is still
  tenant-approved; enterprises get provenance without losing control). A
  `cmd/skills-catalog-probe` analog validates the seed in CI like
  `cmd/mcp-catalog-probe` does.

## 11. Security model

| Control | Mechanism |
|---|---|
| Content integrity | Byte-exact storage; per-file + per-version sha256; deterministic archives; ETags |
| What was approved is what is served | Pin references an immutable version; serving reads only the pinned version; digest exposed everywhere |
| Who can approve | Interactive identity required; optional self-approval ban; reviewer + timestamp recorded |
| Prompt-injection surface | trustguard scan at ingestion (verdict stored on the version, stamped in `_meta` keyed to digest); `PreResponseDiscovery` on `skills/list`; `PreRequest/PreResponse` on `load_skill`; skill reads are plugin-wrapped |
| No implicit execution | The gateway never executes skill content. SEP-2640 requires hosts not to auto-run hook/script declarations from MCP-served skills; our docs state the boundary: TrustGate governs what content reaches agents, not what the agent host executes |
| Ingestion hardening | Path-traversal/absolute-path/symlink rejection, nested-SKILL.md rejection, size/file-count caps, decompression-bomb bound on zip ingest |
| Tenant isolation | Skills are gateway-scoped like registries; grants validated same-gateway; consumer auth (mTLS/bearer/API key) gates every data-plane byte |
| Least exposure | Closed by default (`Skills == nil`); pending/rejected/unpinned versions unreachable from the data plane; reviewer PII never leaves the admin plane |
| Audit | Admin-plane audit events: `skill_created`, `skill_version_ingested`, `skill_version_reviewed`, `skill_pinned`, `skill_grant_attached/detached`, with actor identity — same audit pipeline as existing admin mutations. Data-plane fetches attributable per principal via MCP telemetry |

## 12. Wiring & affected areas

| Area | Change |
|---|---|
| `pkg/domain/ids/ids.go` | `SkillKind`, `SkillVersionKind` in the `Kind` union |
| `pkg/domain/skill/` | **New** aggregate, ports, errors, tests |
| `pkg/domain/consumer/{mcp_policy,skill_policy}.go` | `SkillPolicy` on `MCPPolicy` + validation |
| `pkg/domain/role/role.go` | Inherits via `MCPPolicies` (no structural change) |
| `pkg/infra/database/migrations/` | `add_skills` migration (§3) |
| `pkg/infra/repository/skill/` | **New** Postgres repo (pgx, same style as registry repo) |
| `pkg/app/skill/` | **New** use cases: ingest, review, pin, find, update, delete, grants, manifest |
| `pkg/app/consumer/consumer_data.go` | `RoutableConsumer.Skills` hydration |
| `pkg/app/mcp/skills.go` | **New** `SkillProvider` (SEP entries, digests, `_meta`, instructions, fingerprint) |
| `pkg/app/mcp/{composer,composer_resources}.go` | `skill://` interception, resource merge, `load_skill` binding |
| `pkg/app/mcp/role_scope.go` | Union of `SkillPolicy` across roles |
| `pkg/api/handler/http/skill/` | **New** admin handlers + request DTOs + swagger |
| `pkg/api/handler/http/mcp/{rpc_dispatcher,mcp_handler}.go` | `skills/list`, `skills/get`, capability, instructions, fingerprint |
| `pkg/api/handler/http/mcp/skills_sync_handler.go` | **New** manifest/file/archive handlers |
| `pkg/server/router/{admin_router,mcp_router}.go` | Route registration |
| `pkg/container/modules/skill.go` | **New** dig module; view providers for segregated ports |
| `pkg/runtimeconfig/` | Skill snapshot section + snapshot `skill.Reader` |
| `pkg/config/` | Size caps, review policy flags, git-ingest toggle |
| `seed/skills-catalog/`, `pkg/app/catalog/`, `cmd/skills-catalog-probe` | Phase 3 |
| `frontend/` | Skills view (list/detail/review/pin/attach), mirroring the MCP registries view |
| `tests/functional/skill_*.go` | E2E per phase (§13) |

## 13. Testing

- **Domain unit:** frontmatter/path/size validation, state machine, digest
  determinism (golden vectors), `SkillPolicy` validation, role union.
- **App unit (mocked ports):** ingest (zip/git/catalog), review transitions +
  self-approval ban, pin rules, manifest builder, `SkillProvider` entry/`_meta`
  construction, instructions bounding.
- **Functional (modeled on `tests/functional/mcp_*.go`):**
  1. ingest → approve → pin → attach → `skills/list` shows the entry with
     correct digests → `resources/read` returns byte-identical content.
  2. Sync manifest: ETag/304, file download digest match, archive determinism
     (two fetches, identical bytes).
  3. Negative: pending version invisible; unpinned skill invisible; ungranted
     consumer sees no capability, no methods, no routes; wrong-gateway grant
     rejected; oversized ingest rejected; traversal zip rejected.
  4. Role-based consumer receives the union of role grants.
  5. `load_skill` respects `HelperTool=false`; plugin chain fires on skill reads.
  6. SEP client compatibility: fast-agent (or the reference TS client) installs
     a governed skill end-to-end with digest verification passing.
- All `-race`-clean; `make fmt lint test` gates.

## 14. Rollout & compatibility

Phases ship independently (each additive, each revertible by dropping its
routes/module/migration):

1. **Phase 1 — governance core + sync channel:** §2–§6, §8, §9, audit,
   frontend list/review/pin/attach.
2. **Phase 2 — SEP-2640 exposure:** §7 complete.
3. **Phase 3 — curated catalog + scanning:** §10, trustguard ingestion scan +
   `_meta` verification stamp, adoption metrics dashboard.

Compatibility: consumers without `SkillPolicy` observe zero change in
`initialize`, `tools/list`, or any other surface (verified by a functional
test); pre-SEP MCP clients see governed skills as ordinary resources; skills
remain portable agentskills.io folders, byte-identical to what was ingested.

> Implementers: this repo enforces **NO CODE COMMENTS** (strict, pre-commit;
> swagger annotations exempt). Conventional commits; 400-line PR budget — the
> phase/area boundaries above are also intended PR boundaries.
