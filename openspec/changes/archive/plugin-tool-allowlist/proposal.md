# Proposal: Tool allowlist plugin (pre-request tool-array access control) — RUN-706

## Why

Operators need to restrict which tools a consumer or gateway may expose to the
model **before** the upstream provider sees the request. Today this only exists
in the EE `tool_permission` plugin (exact-match `white_list`/`deny_list`, no
globs, no empty-array policy). This change introduces a first-class TrustGate
`pre_request` plugin that absorbs and generalises it — parallel to
`model_allowlist`, but acting on the `tools[]` array instead of the model field.

- Linear: **RUN-706** ("Plugin: Tool allowlist"). Absorbs the EE
  `tool_permission` plugin.

## What changes

- New `pre_request` plugin, slug **`tool_allowlist`**, package
  `pkg/infra/plugins/toolallowlist/` (mirrors `modelallowlist`; borrows
  `pertoolratelimit` decode/strip/graft plumbing).
- Config: `allow_tools` (glob whitelist), `deny_tools` (glob denylist),
  `on_empty_after_filter` (`reject` | `strip_tools_field` | `pass_through_empty`,
  default `reject`), and an inert informational `scope` field.
- **Glob** via `path.Match`-style matching (`*`, `?`, `[...]`), validated at
  config time; matched against the canonical tool **name**
  (`adapter.CanonicalRequest.Tools[].Name`), decoded with
  `adapter.Registry.DecodeRequestFor`.
- **Filter order**: client `tools[]` → apply `allow_tools` whitelist (if set) →
  apply `deny_tools` after (deny overrides allow) → if empty, apply
  `on_empty_after_filter` → forward filtered request.
- **Empty-after-filter behaviours**: `reject` → `403` with the
  `no_tools_allowed` JSON (`Result{StopUpstream, StatusCode, Body}`);
  `strip_tools_field` → delete `tools`/`tool_choice`/`parallel_tool_calls`;
  `pass_through_empty` → keep `tools: []` but still drop the dangling
  `tool_choice`/`parallel_tool_calls`.
- **Modes**: `MandatoryStages = SupportedStages = [StagePreRequest]`;
  `SupportedModes = [ModeEnforce, ModeObserve]`. Observe never mutates/rejects —
  only `SetExtras`.
- **Telemetry**: `data.go` trace struct via `event.SetExtras` +
  `appplugins.SetDecision`.

## Scope

### In scope
- `allow_tools`/`deny_tools` glob filtering of the canonical tool array.
- Three `on_empty_after_filter` behaviours + provider-agnostic `403` body.
- Body rewrite via `Result.RequestBody` (graft for partial strip; explicit
  key-deletion for empty-array cases).
- Catalog metadata, DI wiring, unit + functional tests (OpenAI + Anthropic).

### Out of scope (non-goals)
- **Raw Bedrock-Converse inbound bodies** — the adapter does not parse
  `toolConfig.tools` and `bedrock` is not a supported source format. Covered:
  any request whose `SourceFormat` is a supported canonical format
  (OpenAI/Anthropic/Gemini/Mistral/…), including those routed to a Bedrock
  backend.
- **`scope`-driven partitioning** — effective scope derives from `Policy.Global`
  (AGENT.md §14.6); the config field is informational only.
- Matching on tool description/schema (name only).

## Capabilities

### New Capabilities
- `tool-allowlist`: pre-request access control over the LLM request `tools[]`
  array — glob allow/deny filtering and an empty-after-filter policy
  (reject / strip / pass-through-empty).

### Modified Capabilities
- None.

## Affected areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/plugins/toolallowlist/` | New | `plugin.go`, `config.go`, `data.go` + tests. Mirror `modelallowlist`, no comments. |
| `pkg/container/modules/plugins.go` | Modified | Register `toolallowlist.New(p.Adapters)` in `newPluginRegistry`. |
| `pkg/app/plugins/catalog_metadata.go` | Modified | Add `tool_allowlist` metadata + `SettingsSchema` (mandatory or `catalog_test` fails). |
| `pkg/app/plugins/catalog_test.go` | Modified | Extend per-slug schema assertions if slug-enumerated. |
| `tests/functional/plugin_tool_allowlist_test.go` | New | allow/deny/empty across OpenAI + Anthropic. |

## Risks & mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Canonical model is lossy (`parallel_tool_calls` absent). | High | Partial strip uses `graftChangedFields` (preserves unknown keys); empty cases delete the three keys explicitly; golden test that a no-strip pass is byte-stable. |
| Body rewrite dropped by `mergeIsolated` in a parallel same-priority `pre_request` batch (Headers+Metadata only). | Med | Document as a known limitation (same as budget §14.2). `reject` via `StopUpstream` still applies; single-plugin batch preserves rewrites. |
| Deny-after-allow diverges from EE (whitelist no longer shadows denylist). | Med | Intentional; documented as a migration note. |
| `scope` field misread as functional. | Low | Catalog description marks it informational (like `pertoolratelimit`/`tool_call_validation`). |
| 403 on requests that never had tools. | Low | No-op gracefully when body empty, format unresolved, decode fails, or no tools present; empty-after-filter only fires when the request started with a non-empty array. |

## Migration from EE (`tool_permission`)

- `allow_tools` ← `white_list`, `deny_tools` ← `deny_list`.
- **Behaviour change**: EE let a non-empty `white_list` fully shadow `deny_list`;
  here `deny_tools` is applied **after** `allow_tools`, so a denied tool is
  removed even if allowed. Adjust migrated configs accordingly.
- EE only ever stripped (its empty-array cleanup = `strip_tools_field`); it never
  rejected. The new default is `on_empty_after_filter: reject` — set
  `strip_tools_field` to preserve EE behaviour exactly.
- EE matched exact strings; patterns now support globs — exact tool names still
  match literally.

## Rollback plan

Additive and self-contained. Rollback = remove `pkg/infra/plugins/toolallowlist/`,
revert the `tool_allowlist` catalog metadata entry and the
`newPluginRegistry` registration. No existing plugin or config is affected;
policies that don't reference `tool_allowlist` are unchanged.

## Success criteria

- [ ] `allow_tools` glob whitelist drops non-matching tools; `deny_tools`
      removes matching tools after allow (deny wins).
- [ ] `reject` returns `403` with the `no_tools_allowed` JSON body.
- [ ] `strip_tools_field` deletes `tools`/`tool_choice`/`parallel_tool_calls`.
- [ ] `pass_through_empty` forwards `tools: []` without a dangling `tool_choice`.
- [ ] Partial strip preserves non-canonical fields (`parallel_tool_calls`) via graft.
- [ ] No-op (no error/403) when body empty, format unresolved, decode fails, or
      no tools present.
- [ ] `observe` mode never mutates/rejects — only emits telemetry.
- [ ] Every registered slug (incl. `tool_allowlist`) has catalog metadata
      (`catalog_test` green).
