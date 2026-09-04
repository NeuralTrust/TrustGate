# Tasks: Enterprise Agent Skills governance

Implementation breakdown per `design.md`. Each numbered group is an intended PR
(≤400 lines each; split further where noted). Phases are independently shippable.

## Phase 1 — governance core + sync channel

### 1.1 Domain aggregate
- [ ] `pkg/domain/ids/ids.go`: add `SkillKind`, `SkillVersionKind` to the `Kind` union + aliases
- [ ] `pkg/domain/skill/`: `Skill`, `SkillVersion`, `SkillFile`, `Source`, `ScanResult`, `Review`
- [ ] Frontmatter parse/validation (`name`==code, `description` required, rest verbatim)
- [ ] Path safety validation (traversal, absolute, nested `SKILL.md`, symlinks)
- [ ] Version state machine + domain errors
- [ ] Digest computation (per-file + canonical version manifest) with golden-vector tests
- [ ] Repository ports (`Repository`, `Reader`) + `//go:generate mockery`
- [ ] Unit tests

### 1.2 Storage
- [ ] Migration `add_skills` (tables `skills`, `skill_versions`, `skill_files`; `consumers.skill_policy`, `roles.skill_policy` columns)
- [ ] `pkg/infra/repository/skill/`: pgx repository implementing both ports
- [ ] `pkg/config`: `SKILL_MAX_VERSION_BYTES`, `SKILL_MAX_FILE_COUNT`, `SKILL_MAX_FILE_BYTES`, `SKILL_REVIEW_FORBID_SELF_APPROVAL`, `SKILL_GIT_INGEST_ENABLED`
- [ ] Repository integration tests

### 1.3 App use cases
- [ ] `pkg/app/skill/ingestor.go`: zip upload + inline files ingestion → pending version
- [ ] Git ingestion (feature-flagged) with `{git_url, git_ref, commit}` provenance
- [ ] `reviewer.go`: approve/reject with identity capture + optional self-approval ban
- [ ] `pinner.go`, `finder.go`, `updater.go`, `deleter.go`
- [ ] `grants.go`: attach/detach for consumers and roles with same-gateway validation
- [ ] Unit tests (mocked ports)

### 1.4 Consumer/role policy
- [ ] `pkg/domain/consumer/skill_policy.go`: `SkillPolicy`, `SkillGrant`, validation
- [ ] Wire into `MCPPolicy` + `Consumer.Validate` (MCP-type-only inherited)
- [ ] Consumer/role repositories: persist `skill_policy` JSONB
- [ ] `RoutableConsumer.Skills` hydration in the consumer data loader
- [ ] `role_scope.go`: union of skill grants across roles + tests

### 1.5 Admin API
- [ ] `pkg/api/handler/http/skill/`: create/list/get/update/delete handlers + DTOs + swagger
- [ ] Version handlers: ingest/list/get/file-download
- [ ] Review handler (`RequireInteractiveIdentity`), pin handler
- [ ] Grant attach/detach handlers (consumer + role)
- [ ] `admin_router.go`: routes under gateway group + `middleware.ResourceSkills`
- [ ] Audit events for all mutations
- [ ] `make swagger` / `make openapi` regeneration

### 1.6 Sync channel (data plane)
- [ ] `pkg/app/skill/manifest.go`: manifest builder (agentskills discovery shape + digests)
- [ ] Deterministic `.tar.gz` archive builder + reproducibility test
- [ ] `pkg/api/handler/http/mcp/skills_sync_handler.go`: manifest / entry / file / archive with ETag + 304
- [ ] `mcp_router.go`: GET routes before the catch-all, behind `MCPAuthMiddleware` + metrics
- [ ] Gateway rate-limit check + telemetry events per fetch

### 1.7 Wiring, snapshots, E2E
- [ ] `pkg/container/modules/skill.go` + registration in `modules.All`
- [ ] Config-sync signal on skill mutations; TTL cache (`cache.SkillContentTTLName`)
- [ ] `pkg/runtimeconfig`: skill snapshot section + snapshot `skill.Reader`
- [ ] Functional tests: lifecycle E2E, manifest/ETag/digest, negative paths, role union
- [ ] Reference sync script + docs page (`docs/skills/`)

### 1.8 Frontend
- [ ] Skills view: list/detail, version review (file browser), pin, consumer/role attach
  (mirrors the MCP registries view)

## Phase 2 — SEP-2640 exposure

### 2.1 SkillProvider
- [ ] `pkg/app/mcp/skills.go`: entries with verbatim frontmatter + `{uri, digest}` manifests,
  `_meta` stamps (`io.modelcontextprotocol.skills/verification`, `ai.neuraltrust.trustgate/governance`),
  bounded instructions, fingerprint fragments
- [ ] Unit tests including `_meta`-keyed-to-digest invariant

### 2.2 Protocol surface
- [ ] `rpc_dispatcher.go`: `skills/list` (paginated + `PreResponseDiscovery`), `skills/get` (`-32602` on non-skill URI)
- [ ] `mcp_handler.go`: capability declaration, instructions append, fingerprint extension
- [ ] `composer_resources.go`: `skill://` interception with upstream fall-through; resource merge
- [ ] `composer.go`: `load_skill` reserved binding honoring `HelperTool`
- [ ] `mcpRequestAttrs` + span attrs (`SetMCPSkill`)
- [ ] Functional: SEP client E2E (digest verification), no-grants zero-change test, helper-tool toggle, plugin chain on skill reads

## Phase 3 — curated catalog + scanning

- [ ] `seed/skills-catalog/` + `embed.go` + `index.json` + starter curated skills
- [ ] `pkg/domain/catalog/skill.go`, `pkg/app/catalog/skills.go`, list handler, `GET /v1/skills-catalog`
- [ ] Install-from-catalog ingestion path (`Source{Type: "catalog"}`)
- [ ] `cmd/skills-catalog-probe` seed validator (CI)
- [ ] trustguard ingestion scan → `ScanResult` on version → `_meta` verification stamp
- [ ] Adoption metrics (per-skill fetch/load counts) surfaced via existing metrics pipeline
- [ ] Frontend: catalog browse + install
