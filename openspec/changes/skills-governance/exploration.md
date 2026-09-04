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

**Q2 — How do agents consume governed skills?** The deployed base: agent harnesses
discover skills by scanning local directories for `SKILL.md` files at startup and
preloading their name/description into the system prompt. That disk contract must be
fed, not replaced. But remote consumption is no longer hypothetical: **SEP-2640
("Skills over MCP", extension `io.modelcontextprotocol/skills`)** standardizes serving
skills over MCP, shipped as part of the 2026-07-28 MCP spec revision, and adoption has
started — ChatGPT's MCP-server plugin flow imports skills per SEP-2640 (broadly
available since Aug 2026), fast-agent supports the `skills/list`/`skills/get` flow
with digest verification, GitHub's MCP server and official SDKs (TypeScript, PHP) have
implementations, and Anthropic has prototyped host support in Claude Code. See the
dedicated SEP-2640 section below. Two channels, in priority order:

1. **HTTP sync channel (primary — feeds the disk contract):** a read-only endpoint on
   the MCP plane (`GET /{consumer_slug}/skills` manifest with codes, pinned versions,
   content hashes, and file lists + per-file/archive download, same
   `MCPAuthMiddleware`) lets a thin sync step (curl script, devcontainer `postCreate`,
   CI step for cloud agents, dotfiles/MDM on laptops) materialize the approved set
   verbatim into `.cursor/skills/`/`.claude/skills/` and delete revoked entries. The
   agent then finds ordinary `SKILL.md` files and never talks to the gateway. Hashes
   make sync idempotent and tamper-evident; revocation propagates on the next sync,
   so running it at session start bounds staleness to one session.
2. **MCP channel — implement SEP-2640, not ad-hoc tools:** the consumer's virtual MCP
   server declares the `io.modelcontextprotocol/skills` capability and serves the
   standard binding: `skills/list` / `skills/get` for discovery (entries carry the
   verbatim frontmatter plus a `{uri, digest}` resource manifest), every skill file
   addressable as a `skill://{code}/{path}` resource via plain `resources/read`, and
   optional archive form for atomic multi-file delivery — all behind the same auth,
   toolkit filtering, plugins, and telemetry. SEP-conformant hosts (ChatGPT import
   today; Claude Code prototyped) merge MCP-served skills into their native skill
   registry, which shrinks the closed-harness gap over time. For harnesses that
   predate the extension, the gateway can keep a thin `load_skill` helper tool as a
   compatibility fallback — to such clients, SEP skills are just ordinary resources
   anyway (the extension adds no new protocol requirements for them). The SEP also
   blesses the server-`instructions` pointer we relied on: a server MAY direct the
   agent to skill URIs from `initialize.instructions` with no discovery machinery.

**Integration recipe per agent type:**

- **Closed disk-scanning runtimes (Cursor, Claude Code):** channel 1. The sync step
  writes plain `SKILL.md` folders where the runtime already looks; the agent never
  talks to the gateway.
- **Frameworks that implement the agentskills.io standard (e.g. Claude Agent SDK):**
  also channel 1 — point the SDK's skill directory at the sync target.
- **SEP-2640-conformant hosts (ChatGPT import today, more coming):** channel 2 with
  zero custom code — the host sees the `io.modelcontextprotocol/skills` capability on
  the consumer's virtual MCP server, calls `skills/list`, and merges the entries into
  its native skill registry alongside filesystem skills.
- **Fully custom loops:** channel 2, over the same MCP connection the agent already
  holds for tools. Concretely: an MCP consumer already presents itself to the agent
  as one virtual MCP server at `POST /{consumer_slug}/mcp`, whose `tools/list` is the
  toolkit-filtered union of the upstream registries. The gateway additionally answers
  the SEP-2640 surface itself — no upstream involved, no new endpoint, auth, or
  client:

  ```
  today:                        with skills (SEP-2640):
    initialize                    initialize  → capabilities.extensions
    tools/list → upstream tools                 ["io.modelcontextprotocol/skills"]
    tools/call                    skills/list → governed skill entries (gateway-served)
    resources/*  → upstream       skills/get  → one entry + {uri, digest} manifest
                                  resources/read skill://{code}/… (gateway-served)
  ```

  "Loading a skill" for an LLM just means getting the `SKILL.md` markdown into its
  context; a `resources/read` result achieves that identically to a disk read. The
  invocation pattern mirrors native disk skills exactly — this is the standard's
  progressive disclosure, not a gateway artifact:

  | | Native disk skills | Gateway-served skills (SEP-2640) |
  |---|---|---|
  | Metadata in system prompt | harness preloads it when scanning directories | bootstrap calls `skills/list` once, or zero calls via `initialize.instructions` (spec'd pointer) |
  | Full `SKILL.md` body | file-read tool call when the model deems it relevant | `resources/read skill://…/SKILL.md` (or a `load_skill` helper tool) when relevant |
  | Linked files | further file reads on demand | sibling `skill://` resource reads on demand |

  Metadata preload does not require the model to act: either the loop calls
  `skills/list` deterministically at session boot (one programmatic MCP request,
  pre-filtered by the consumer/role allowlist; official SDKs ship `list_skills` /
  `read_skill_uri` wrappers) and injects the result into the system prompt, or —
  cheaper — the gateway points at skill URIs from `initialize.instructions`, which
  SEP-2640 explicitly defines as a discovery mechanism and most harnesses append to
  the system prompt automatically. The model only ever *chooses* to read a skill,
  exactly as it chooses to read a `SKILL.md` from disk.

  This path needs no filesystem (a better fit for ephemeral/serverless agents), and
  every load passes through plugins and telemetry. A custom loop *may* instead sync
  to a temp directory via channel 1 (the only option if it uses no MCP at all), but
  it would still have to implement the metadata preload itself, so the MCP path is
  usually less code.

Rule of thumb: closed runtimes that scan disk → HTTP sync; SEP-2640 hosts and loops
you control → MCP.

**Sync strategies (channel 1).** Two axes: what triggers the sync, and how it
materializes files safely.

*Triggers, in recommended order:*

1. **Agent session-start hook (default):** Cursor and Claude Code support session
   hooks (Cursor can even distribute team hooks centrally, with `failClosed`). Sync
   runs exactly when the agent is about to rescan skills, bounding staleness and
   revocation lag to one session; strict mode can block session start on sync
   failure.
2. **Ephemeral-environment boot:** devcontainer `postCreateCommand`, cloud-agent
   install/start scripts, or a Dockerfile layer — for pods/CI where the filesystem
   starts empty, sync is just provisioning.
3. **Gateway-push via Git (inverted flow):** a job commits/PRs approved skills into
   target repos' `.cursor/skills/`; distribution becomes a normal `git pull`. Zero
   client tooling, git-versioned history, and the update PR is itself a visible
   review point. Trade-offs: revocation lag equals merge+pull cadence, and a
   consumer→repo mapping must be maintained.
4. **Background cron/daemon** on long-lived laptops (staleness bounded to the
   interval; complements the hook as a safety net).
5. **MDM/dotfiles** for user-scoped skills (`~/.claude/skills/`) on managed machines.

*Materialization (what keeps the sync safe):*

- **Declarative reconciliation:** the manifest is the desired state — diff hashes,
  download changes, delete entries absent from the manifest. Idempotent by
  construction.
- **Bounded ownership:** the sync manages only a designated subtree (e.g.
  `.cursor/skills/managed/`) plus a lockfile recording what it wrote (codes,
  versions, hashes). Deleting revoked skills can never touch the developer's
  personal skills, and hash drift in the lockfile flags local tampering for
  re-download.
- **Atomic writes:** download to a temp dir, verify hashes against the manifest,
  rename into place — the agent never observes a half-written skill.
- **Scope separation:** distinct consumers for project-scoped (repo directory) and
  user-scoped (`~/`) skills, mirroring the agents' own scoping model.

The reference implementation can be a ~30-line curl+jq script or a
`trustgate skills sync` subcommand; Phase 1 commits only to documenting the
reference flow, not to maintaining a client.

### Skills over MCP — SEP-2640, the standard binding for channel 2

**What it is.** [SEP-2640 "Skills Extension"](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2640)
(Extensions Track, developed by the MCP Skills Over MCP Working Group, extension id
`io.modelcontextprotocol/skills`) defines how Agent Skills are served over MCP. The
skill *format* stays delegated to agentskills.io; the SEP is a pure transport binding.
A v1 shipped with the 2026-07-28 MCP spec revision; earlier drafts used a
`skill://index.json` well-known resource, superseded by protocol methods. Current
surface:

- **Capability:** servers declare `capabilities.extensions["io.modelcontextprotocol/skills"]`
  at `initialize`.
- **Discovery:** paginated `skills/list` (entries mirror the `SKILL.md` frontmatter
  verbatim and carry a complete `{uri, digest}` resource manifest) and `skills/get`
  (one entry by URI — works for skills that are served but deliberately unlisted).
  Enumeration is optional: a URI is always directly readable, and hosts must not
  treat an empty listing as proof of absence.
- **Reading:** every skill file is an ordinary MCP resource,
  `skill://<skill-path>/<file-path>` (final path segment must equal the frontmatter
  `name`; `SKILL.md` explicit in the URI), read via standard `resources/read`.
  Optional `.tar.gz`/`.zip` archive form delivers a multi-file skill atomically.
- **Integrity:** SHA-256 digests in the manifest; clients like fast-agent verify
  every downloaded file against its declared digest before writing local copies.
  Digest rotation under a stable name is the defined trigger for revoking a
  persisted approval ("content-bound approval").
- **Instructions pointer:** a server may direct agents to skill URIs from
  `initialize.instructions` — spec'd, no discovery machinery needed.
- **Security posture:** skill content is untrusted model input; hosts must never
  auto-execute anything a skill declares (hooks, scripts) without explicit opt-in;
  provenance should be shown per server.

**Adoption (as of Aug 2026).** OpenAI's ChatGPT plugin flow imports skills from MCP
servers per SEP-2640 (announced broadly available 2026-08-04); fast-agent implements
the `skills/list`/`skills/get` flow as an integrity-checked installer; GitHub's MCP
server, the official TypeScript and PHP SDKs, and host prototypes for gemini-cli,
goose, and codex exist; Anthropic has prototyped Claude Code host support internally.
Status caveat: the SEP is still formally in the Extensions Track review process and
the July revision broke early index.json adopters — churn is real, so the binding
should live in one adapter layer.

**Why this matters for TrustGate specifically:**

1. **Phase 2 becomes "implement SEP-2640", not "invent tools".** The Composer's
   virtual skills provider should answer `skills/list`/`skills/get` and serve
   `skill://` resources; a `load_skill` helper tool remains only as a fallback for
   pre-SEP, tool-only harnesses.
2. **Instant client ecosystem.** A conformant TrustGate consumer endpoint is
   immediately consumable by ChatGPT's importer, fast-agent, and every host that
   adopts the extension — no TrustGate-specific client code.
3. **The digest model matches ours.** SEP manifests carry per-file SHA-256 digests;
   our immutable hashed versions map straight onto them, and "content-bound
   approval" is exactly our pin semantics seen from the client side.
4. **A spec'd slot for governance metadata.** The Working Group reserved the
   `io.modelcontextprotocol.skills/` `_meta` prefix as a neutral attachment point
   where *relaying gateways* can stamp provenance or verification metadata (e.g. a
   scan verdict keyed to the digest) as skills pass through — the gateway role is
   explicitly anticipated by the spec discussion, including proposals for signed
   scan attestations keyed by skill digest.
5. **Governance is deliberately out of the SEP's scope.** The spec settles transport
   and integrity but explicitly leaves approval, allowlisting, and verification to
   the ecosystem — which is precisely the layer TrustGate provides (toolkit
   filtering, roles, review workflow, plugins, audit).

**Q3 — What is the approval workflow?** Keep it minimal and reuse existing shapes:
skill versions are immutable and start `pending`; an admin transitions them to
`approved` (or `rejected`); only `approved` versions are servable; the gateway-level
enablement (the registry analog) **pins one approved version**. Updating = ingest new
version → review → repoint the pin. Rollback = repoint to the previous approved
version. Content scanning (prompt-injection / malicious-script heuristics) fits the
existing plugin architecture as a `pre_response`-style check on skill
`resources/read`/`skills/*` calls, or as an ingestion-time check — NeuralTrust's
trustguard is the obvious engine. SEP-2640's reserved
`io.modelcontextprotocol.skills/` `_meta` prefix gives the scan verdict a
standards-blessed place to travel with the skill entry, keyed to its digest.

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
