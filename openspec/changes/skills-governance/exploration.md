## Exploration: Enterprise governance of Agent Skills

### What is a "skill" and why govern it

Agent Skills are a published open standard ([agentskills.io](https://agentskills.io)): a
directory containing a `SKILL.md` (YAML frontmatter with `name` + `description`, then
Markdown instructions) plus optional `scripts/`, `references/` and `assets/`. Agents
pre-load only name/description of every installed skill and pull the full body on
demand (progressive disclosure). The format is supported today by Claude
(Claude.ai/Code/API), Cursor (`.cursor/skills/`, `.agents/skills/`, plus
`.claude/`/`.codex/` compatibility paths), and other agent runtimes.

Skills are **executable-adjacent content**: they steer agents that hold credentials and
shell access, and can bundle scripts the agent runs. Enterprises therefore need the same
controls they already demand for MCP servers — a curated catalog, review/approval,
version pinning, per-team allowlists, and audit — but for a *static, versioned artifact*
rather than a live protocol endpoint.

### Industry state (validation that the pattern is established)

- **Anthropic** ships a Skills API (`/v1/skills`) with workspace-wide provisioning,
  versioning, and (Enterprise) automated scanning of uploaded skills for malicious
  content. Their enterprise guide prescribes an internal registry (purpose, owner,
  version, review date), Git-backed storage, and re-review on update.
- **Cursor** distributes skills to teams via plugins in private team marketplaces with
  installation modes (Default Off / Default On / Required), Organization Group access
  control (SCIM), and a skills-adoption analytics endpoint. There is **no** standalone
  skills allowlist comparable to their MCP allowlist — governance is plugin-level.
- Neither vendor offers a **vendor-neutral** control point: Anthropic's registry only
  serves Claude surfaces; Cursor's only serves Cursor. A gateway-level skill registry
  that any agent can consume (Claude Code, Cursor, custom SDK agents) is an open gap —
  the same gap TrustGate already fills for MCP.

### Current state in TrustGate

The MCP governance stack is the template. Four layers, all reusable:

| Layer | MCP implementation | Reusable for skills? |
|-------|--------------------|----------------------|
| Curated platform catalog | `seed/mcp-catalog/enterprise-servers.json` embedded via `//go:embed`, domain `pkg/domain/catalog/mcp_server.go`, app `pkg/app/catalog/mcp_servers.go`, `GET /v1/mcp-servers-catalog` (admin, interactive-only) | Yes — same seed+embed+read-only-endpoint pattern |
| Tenant connection/instance | `Registry{Type: MCP}` with `MCPTarget` JSONB (`pkg/domain/registry/`), CRUD under `/v1/gateways/:gw/registries`, catalog `code` as join key, security canonicalization (`mcp_catalog_auth.go`) | Yes — pattern fits; skills additionally need **content storage + immutable versions**, which registries don't have |
| Consumer/role allowlist | `Consumer.MCP.Toolkit` (`pkg/domain/consumer/toolkit.go`): per-registry allowlist of `tool`/`prompt`/`resource` entries, wildcards, `expose_as`; `RoleScoper` unions role policies | Yes — toolkit already has an entry-kind enum; a `skill` kind is a natural extension |
| Data plane + enforcement | MCP plane `:8082` (`ServerMCP`), consumer slug routing, `MCPAuthMiddleware` (mTLS/bearer/API key), `Composer` federating upstreams, `PluginRunner` on `tools/call`, telemetry | Yes — critically, MCP **resources and prompts are already federated**; skills can ride this plane with zero new protocol |

Nothing skill-shaped exists today: no domain, no storage, no endpoints. `A2A` exists
only as a reserved consumer type. Several seed MCP servers *expose* skill-loading tools
(`load_skill`, `cio_skills_*`), which confirms agents in the wild already fetch skills
through MCP.

### Key design questions and answers

**Q1 — Where does skill content live?** Unlike MCP registries (a URL + auth), a skill is
the content itself. Options: (a) store the folder in Postgres as versioned blobs, (b)
store only a Git ref and fetch on demand, (c) both. Recommendation: **(a) for v1** —
immutable version rows with a content hash give the strongest governance story
(what was approved is exactly what is served); Git-import is an *ingestion* path, not
the serving path. Size is bounded by construction (skills are text-first; enforce a
per-version size cap, reject binaries above it).

**Q2 — How do agents consume governed skills?** The hard constraint: today's agent
harnesses discover skills by scanning local directories for `SKILL.md` files at
startup and preloading their name/description into the system prompt. No mainstream
harness pulls skills from a remote endpoint natively. So the gateway must feed that
disk contract rather than replace it. Two channels, in priority order:

1. **HTTP sync channel (primary — feeds the disk contract):** a read-only endpoint on
   the MCP plane (`GET /{consumer_slug}/skills` manifest with codes, pinned versions,
   content hashes, and file lists + per-file/archive download, same
   `MCPAuthMiddleware`) lets a thin sync step (curl script, devcontainer `postCreate`,
   CI step for cloud agents, dotfiles/MDM on laptops) materialize the approved set
   verbatim into `.cursor/skills/`/`.claude/skills/` and delete revoked entries. The
   agent then finds ordinary `SKILL.md` files and never talks to the gateway. Hashes
   make sync idempotent and tamper-evident; revocation propagates on the next sync,
   so running it at session start bounds staleness to one session.
2. **MCP channel (additive for closed runtimes, primary for custom agents):** expose
   approved skills on the existing consumer endpoint as MCP resources
   (`skill://{code}/SKILL.md`, `skill://{code}/{path}`) plus two virtual gateway tools
   (`list_skills`, `load_skill`), with the same auth, toolkit filtering, plugins, and
   telemetry. The tool result is plain markdown the model consumes as context, but a
   closed harness (Cursor, Claude Code) will not auto-preload MCP-served skill
   metadata the way it does for disk skills — the model must decide to call the tool.
   That limitation disappears when the developer controls the loop; see the recipe
   below.

**Integration recipe per agent type:**

- **Closed disk-scanning runtimes (Cursor, Claude Code):** channel 1. The sync step
  writes plain `SKILL.md` folders where the runtime already looks; the agent never
  talks to the gateway.
- **Frameworks that implement the agentskills.io standard (e.g. Claude Agent SDK):**
  also channel 1 — point the SDK's skill directory at the sync target.
- **Fully custom loops:** channel 2, over the same MCP connection the agent already
  holds for tools. At session boot the loop calls `list_skills` (names + descriptions
  only, pre-filtered by the consumer/role allowlist) and injects that metadata into
  the system prompt; `load_skill` is already advertised in `tools/list`, so the model
  pulls the full `SKILL.md` on demand and reads linked files as `skill://` resources.
  This reproduces the standard's progressive-disclosure behavior in a few lines of
  bootstrap code, needs no filesystem (a better fit for ephemeral/serverless agents),
  and every load passes through plugins and telemetry. A custom loop *may* instead
  sync to a temp directory via channel 1, but it would still have to implement the
  metadata preload itself, so the MCP path is usually less code.

Rule of thumb: closed runtimes that scan disk → HTTP sync; loops you control → MCP.

**Q3 — What is the approval workflow?** Keep it minimal and reuse existing shapes:
skill versions are immutable and start `pending`; an admin transitions them to
`approved` (or `rejected`); only `approved` versions are servable; the gateway-level
enablement (the registry analog) **pins one approved version**. Updating = ingest new
version → review → repoint the pin. Rollback = repoint to the previous approved
version. Content scanning (prompt-injection / malicious-script heuristics) fits the
existing plugin architecture as a `pre_response`-style check on `load_skill`/resource
reads, or as an ingestion-time check — NeuralTrust's trustguard is the obvious engine.

**Q4 — New top-level domain or overload `Registry`?** New domain. `Registry` models a
*connection to an upstream*; a skill is *content we host*. Overloading `MCPTarget` with
blob semantics would contaminate the registry aggregate. The per-gateway "enabled skill
with pinned version" object is small and skill-specific.

### Affected areas (if we proceed)

| Area | Impact |
|------|--------|
| `pkg/domain/skill/` | New aggregate: `Skill`, `SkillVersion` (immutable, hash), `SkillFile`, approval state machine, repository ports |
| `pkg/infra/repository/skill/` + migration | New tables `skills`, `skill_versions`, `skill_files` (or JSONB files column); per-version size cap |
| `pkg/app/skill/` | Use cases: ingest (upload/Git-import), review transitions, pin/enable per gateway, manifest builder |
| `pkg/api/handler/http/skill/` + `admin_router.go` | Admin CRUD + `GET /v1/skills-catalog` (curated seed, later phase) |
| `pkg/domain/consumer/toolkit.go` | New entry kind `skill` (alongside `tool`/`prompt`/`resource`) |
| `pkg/app/mcp/` (Composer) | Virtual skills provider: `resources/list|read` entries + `list_skills`/`load_skill` tools, toolkit-filtered |
| `pkg/server/router/mcp_router.go` | `GET /{slug}/skills` manifest + file download, behind `MCPAuthMiddleware` |
| `pkg/container/modules/` | New `skill.go` wiring module |
| `seed/skills-catalog/` (phase 3) | Curated skill catalog seed + embed, mirroring `seed/mcp-catalog/` |
| `tests/functional/` | Skill ingest→approve→pin→serve E2E, modeled on `mcp_*.go` |

### What we deliberately did not explore

- Skill *execution* sandboxing (bundled scripts run on the agent host, not the gateway;
  out of TrustGate's enforcement reach — mitigated by review + scanning + hashes).
- Marketplace-style third-party submission flows.
- Signing/attestation (content hash in the manifest covers integrity for v1; sigstore
  could layer on later).
