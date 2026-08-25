---
type: feat
changelog: "Add enterprise governance for Agent Skills: tenant skill registry with immutable versions and approval workflow, consumer/role allowlisting, and distribution over the existing MCP plane plus an authenticated HTTP sync manifest."
---

# Proposal: Enterprise Agent Skills governance

## Intent

Enterprises govern MCP servers through TrustGate (curated catalog → per-gateway
registry → consumer/role toolkit → authenticated data plane with policies and
telemetry) but have no equivalent for Agent Skills, even though skills steer the same
credentialed agents and can bundle executable scripts. Anthropic and Cursor each offer
skill provisioning locked to their own surface; no vendor-neutral control point exists.
TrustGate should be that control point: one registry of reviewed, versioned,
allowlisted skills served to any agent through the gateway. See `exploration.md` for
the full investigation.

## Proposed usage flow

### Platform/security admin (control plane, `:8080`)

1. **Ingest** a skill into a gateway: upload the folder (multipart/zip) or import from
   a Git URL+ref. TrustGate validates the `SKILL.md` frontmatter, enforces the size
   cap, computes a content hash, and stores an **immutable version** in state
   `pending`.
2. **Review & approve**: a reviewer inspects the stored content (optionally gated by an
   ingestion-time trustguard scan) and transitions the version to `approved` or
   `rejected`. Approved content can never be mutated — only superseded.
3. **Enable & pin**: enabling a skill on a gateway pins exactly one approved version.
   Updates repoint the pin after the new version passes review; rollback repoints back.
4. **Scope**: add `skill` entries to consumer/role toolkits (wildcards supported, as
   with tools/prompts/resources). No entry, no exposure — same closed-by-default
   semantics the MCP toolkit already has.

### Agent / developer (data plane, `:8082`, existing consumer auth)

Agents load skills by scanning local directories for `SKILL.md` files at startup; the
gateway does not change that contract. TrustGate is the governed *source* those files
are materialized from, not a new discovery mechanism the agent must learn.

- **HTTP sync channel (primary)** — for disk-discovery runtimes (Cursor, Claude Code):
  `GET /{consumer_slug}/skills` returns a manifest (codes, pinned versions, content
  hashes, file lists) and per-file/archive downloads, behind the same
  `MCPAuthMiddleware`. A thin sync step — a curl script, devcontainer `postCreate`,
  a CI step for cloud agents, or dotfiles/MDM on managed laptops — diffs hashes
  against local state, writes the approved skill folders verbatim into
  `.cursor/skills/` / `.claude/skills/`, and deletes revoked ones. The agent then
  discovers plain `SKILL.md` files exactly as it does today; it never talks to the
  gateway. Revocations and pin changes propagate on the next sync (run it at session
  start — the same moment agents rescan skills — to keep the staleness window to one
  session).
- **MCP channel (primary for custom agents, additive for closed runtimes)** — the
  consumer endpoint also exposes `list_skills` (names + descriptions only),
  `load_skill` (full `SKILL.md`), and `skill://{code}/{path}` resources. Metadata
  preload never depends on the model: either the loop calls `list_skills` once at
  session boot (deterministic bootstrap code), or the gateway embeds the allowed
  skills' names/descriptions in the `initialize.instructions` field, which most
  harnesses — including closed ones — append to the system prompt automatically.
  The model only invokes `load_skill` when it deems a skill relevant, mirroring how
  native disk skills load the body via a file-read tool call (the standard's
  progressive disclosure). No filesystem needed (well suited to ephemeral/serverless
  agents). Remaining limitation for closed harnesses (Cursor, Claude Code): without
  disk sync they rely on honoring `initialize.instructions` for discovery; disk sync
  stays the primary channel for them. Rule of thumb: closed runtimes that scan disk
  → HTTP sync; loops you control → MCP.
- Every fetch on either channel is attributable (principal, skill, version, hash)
  through the existing telemetry/metrics plane; plugins (rate limiting, trustguard)
  run on skill reads like any other MCP call.

## Viability

**Viable, and cheaper than the MCP feature was.** Auth, consumer routing, toolkit
allowlisting, role scoping, plugin enforcement, telemetry, config-sync/DB-less
snapshots, and the admin catalog pattern all exist and are reused as-is. The genuinely
new work is one aggregate (skill + immutable versions + content storage), its admin
CRUD, and a virtual provider inside the Composer — no new protocol, no new server
plane, no new auth model. The main risks are product-shaped, not architectural (see
Risks).

## Scope

### In Scope (phased)

- **Phase 1 — registry + HTTP sync (standalone value):** `pkg/domain/skill/` aggregate
  (`Skill`, immutable `SkillVersion` with content hash and state machine
  `pending → approved|rejected`), Postgres storage with per-version size cap, ingest
  via upload and Git-import, admin CRUD under `/v1/gateways/:gw/skills`, per-gateway
  enable+pin, toolkit `skill` entry kind, authenticated
  `GET /{consumer_slug}/skills` manifest + file download on the MCP plane.
- **Phase 2 — MCP-native exposure:** virtual skills provider in the Composer
  (`list_skills` / `load_skill` tools, `skill://` resources), toolkit-filtered,
  plugin-wrapped, telemetered.
- **Phase 3 — curated catalog + scanning:** `seed/skills-catalog/` embedded seed with
  `GET /v1/skills-catalog` (mirroring `seed/mcp-catalog/`), trustguard-based content
  scan at ingestion and/or on read, adoption metrics.

### Out of Scope

- Executing or sandboxing bundled skill scripts (they run on the agent host; mitigated
  by review, scanning, hashes — documented limitation).
- Marketplace/third-party submission workflows and skill signing/attestation.
- Auto-sync clients beyond a documented reference sync flow.

## Capabilities

### New Capabilities

- `skills-governance`: gateway-hosted registry of reviewed, versioned, allowlisted
  Agent Skills, distributed vendor-neutrally over the existing MCP plane and an
  authenticated HTTP manifest.

### Modified Capabilities

- `mcp-toolkit`: toolkit entries gain a fourth kind, `skill`, with existing wildcard
  and role-union semantics.

## Approach

New top-level hexagonal domain, not an overload of `Registry` (a registry models a
connection to an upstream; a skill is content we host — see exploration Q4). Standard
layering: `pkg/domain/skill` → `pkg/app/skill` (ingest, review, pin, manifest) →
`pkg/api/handler/http/skill` + `admin_router.go` → `pkg/infra/repository/skill` +
migration → `pkg/container/modules/skill.go`. Data-plane exposure extends
`pkg/app/mcp` (Composer virtual provider) and `mcp_router.go` (manifest route);
DB-less mode gets skill snapshots through the existing config-sync mechanism.
Functional tests modeled on `tests/functional/mcp_*.go` covering
ingest → approve → pin → allowlist → serve, including the negative paths (pending
version not served, toolkit-excluded skill invisible, hash stability).

### Compatibility guarantees (standards-based, nothing breaks)

- **Artifact fidelity:** skills are stored and served byte-identical (hash-verified) in
  the agentskills.io format — no proprietary frontmatter, wrapper, or rewriting.
  A skill governed through the gateway remains portable to any other distribution.
- **Disk channel feeds native discovery:** the sync writes ordinary files into the
  directories Cursor/Claude Code already scan. If the sync never runs, the agent
  starts exactly as today (minus those skills); there is no failure mode that breaks
  a session.
- **MCP channel uses only core protocol primitives:** tools, resources, and
  `initialize.instructions` are all in the MCP spec. Clients that ignore
  `instructions` degrade gracefully (no skill index, no error).
- **Closed by default:** skill tools/resources appear in a consumer's surface only
  when its toolkit gains `skill` entries. Existing consumers observe zero change in
  `tools/list` until an admin opts in — the same semantics the toolkit already
  applies to tools/prompts/resources.
- **No new client requirements:** consumer auth (API key/OAuth/mTLS), roles, plugins,
  and telemetry are reused as-is; agents need support nothing beyond what they
  already use to reach the gateway.

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Agents ignore the MCP channel (disk-based discovery dominates) | Med | Phase 1 ships the HTTP sync manifest first; MCP channel is additive |
| Skill scripts execute outside gateway enforcement | High (inherent) | Review + scan + immutable hashes; document the boundary explicitly |
| Content storage growth (assets-heavy skills) | Low | Text-first size cap per version; reject oversized/binary payloads |
| Agent Skills spec evolves (new frontmatter fields) | Med | Store the folder verbatim; validate only `name`/`description`; hash the bytes |
| Review workflow too heavy for small teams | Med | Single-transition state machine; auto-approve policy flag per gateway can come later |

## Rollback Plan

Additive throughout. Phase boundaries are independently revertible: drop the skill
tables/migration, remove the `skill` toolkit kind (unknown kinds already fail
validation), unregister the Composer virtual provider and the manifest route. No
existing MCP/LLM behavior changes.

## Dependencies

- Existing MCP plane (`ServerMCP`, `MCPAuthMiddleware`, Composer, toolkit, RoleScoper).
- Postgres (new tables) + config-sync snapshots for DB-less mode.
- Git ingestion needs outbound fetch from the admin plane (same posture as catalog
  sync); optional.
- trustguard for scanning (Phase 3 only).

## Success Criteria

- [ ] Ingesting a valid skill folder creates an immutable `pending` version with a
      stable content hash; invalid frontmatter or oversized payloads are rejected.
- [ ] Only `approved` + pinned versions are ever served; repointing the pin is the only
      update path and old versions remain retrievable for audit.
- [ ] A consumer without a `skill` toolkit entry sees no skills on either channel.
- [ ] `GET /{consumer_slug}/skills` manifest hashes match served bytes; sync is
      idempotent.
- [ ] `list_skills` returns names/descriptions only; `load_skill` and `skill://`
      resources return full content, with plugins and telemetry applied.
- [ ] Role-based consumers get the union of role skill allowlists (RoleScoper parity).
- [ ] `-race`-clean unit + functional tests pass.
