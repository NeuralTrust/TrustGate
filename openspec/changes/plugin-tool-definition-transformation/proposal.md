# Proposal: Tool definition transformation plugin — RUN-707

## Why

Operators need a **soft steering + governance layer** over the `tools[]` array
that a client sends, applied before the upstream model ever sees it. Today the
gateway can *gate* tool access (the allowlist / `strip_tool_from_request`
behaviour of `per_tool_rate_limiter`) and *hard-enforce* tool-call arguments on
the response leg (the planned **Tool call argument validation** plugin), but it
cannot **reshape** the tool catalogue on the request leg: tighten a tool's JSON
schema, rewrite a misleading description, or inject an operator-defined tool the
client never declared.

This plugin fills that gap. It rewrites tool schemas and descriptions and
injects new tool definitions so operators can:

- constrain a tool's parameters (e.g. pin an enum, mark a field required, drop a
  dangerous property) without trusting the client to send a tight schema;
- normalize or annotate tool descriptions to steer model behaviour;
- inject a standard tool (e.g. a safety/observability tool) into every request.

It is deliberately the **soft** half of a pair: it *steers* the model by editing
what the model sees, but it does **not** guarantee the model obeys. The **hard
enforcement** counterpart is **Tool call argument validation**, which inspects
the model's actual tool calls on the response leg. Schema tightening here makes
correct behaviour *more likely*; argument validation makes incorrect behaviour
*rejectable*. The two are complementary and operators are expected to pair them.

- Linear: **RUN-707** (this change). Team Runtime, project "Create TrustGate
  Plugins".

## What changes

- **New plugin package** `pkg/infra/plugins/tooltransform/`, slug
  `tool_definition_transformation`, stage **`pre_request` only**, mode
  **`enforce` only**. It mirrors `per_tool_rate_limiter` almost line-for-line:
  decode the request body via the provider adapter `Registry` into the
  provider-neutral `adapter.CanonicalRequest`, mutate `canonical.Tools`,
  re-encode, graft only the changed `tools` field back onto the original raw
  body, and return the new body via `Result.RequestBody`.
- **`transform_tools[]`** — each entry has a tool-name glob plus a
  `schema_patch` (RFC 7386 JSON merge patch over the tool's parameter schema)
  and/or a `description_override`. All matching entries apply, in declaration
  order, cumulatively, to each surviving tool.
- **`inject_tools[]`** — full function-tool objects added to the request after
  transforms. v1 maps `function{name, description, parameters}` →
  `CanonicalTool{Name, Description, Schema}`.
- **`on_conflict`** — `gateway_wins | client_wins | reject`, resolving a
  collision between an injected tool name and the post-transform surviving tool
  set **and** already-injected names.
- **`scope`** — informational config field (enum `consumer | global`); effective
  scope is derived from `Policy.Global`, consistent with `per_tool_rate_limiter`
  and `tool_call_validation`.
- **Registration**: one line in `newPluginRegistry`
  (`pkg/container/modules/plugins.go`, needs only `*adapter.Registry`) plus a
  catalog metadata entry in `pkg/app/plugins/catalog_metadata.go` (group
  "Other", name "Tool Definition Transformation").
- **Observability**: an event-extras trace payload (`event.SetExtras`) mirroring
  the sibling plugins, recording which tools were transformed/injected and the
  conflict outcome.

## Scope

### In scope

- Rewriting matching tools' parameter schema (RFC 7386 merge patch) and/or
  description on the request leg.
- Injecting operator-defined function tools with `gateway_wins | client_wins |
  reject` collision handling.
- Provider-agnostic operation across every format the adapter `Registry`
  supports (OpenAI completions + responses, Anthropic, Gemini, Bedrock,
  Mistral), same coverage as `per_tool_rate_limiter`.
- Glob tool-name matching via stdlib `path.Match` with the `/`→sentinel trick.
- Informational `scope` field, enum-validated.
- A `reject` envelope identical to the issue contract:
  `400 { "error": { "type": "tool_name_reserved", "name": "<tool>" } }`.

### Out of scope (non-goals)

- **Access gating / allowlisting** — deciding *whether* a tool may be present.
  That is the Tool allowlist plugin (and `per_tool_rate_limiter`'s strip
  behaviour). This plugin only operates on tools that survive earlier stages.
- **Hard argument enforcement** — guaranteeing the model's tool calls conform to
  the patched schema. That is **Tool call argument validation** on the response
  leg. Schema patching here is steering, not enforcement.
- **Executing injected tools** — injected tools are *definitions* the model may
  call; the gateway does not implement them. The executor (or a paired Tool call
  argument validation plugin) must handle the injected tool, or the model will
  emit calls nothing answers.
- **Provider-exotic fidelity on injected tools** — v1 preserves
  `{name, description, parameters}` only; provider-specific extras (e.g.
  Anthropic `cache_control`, OpenAI `strict`) on injected tools are dropped (see
  Risks). Acceptable for config-authored tools.
- **Response-leg behaviour** — single stage `pre_request`; no `post_response`.

## Config schema (final)

```json
{
  "scope": "consumer",
  "transform_tools": [
    {
      "tool": "search_*",
      "schema_patch": {
        "properties": {
          "include_archived": { "enum": [false] },
          "internal_only": null
        },
        "required": ["query"]
      },
      "description_override": "Search public documents only."
    }
  ],
  "inject_tools": [
    {
      "type": "function",
      "function": {
        "name": "safety_check",
        "description": "Run a safety gate before answering.",
        "parameters": {
          "type": "object",
          "properties": { "reason": { "type": "string" } },
          "required": ["reason"]
        }
      }
    }
  ],
  "on_conflict": "reject"
}
```

- `scope` — optional; enum `consumer | global`; informational only (effective
  scope from `Policy.Global`). Validated when present.
- `transform_tools[].tool` — glob (`path.Match` semantics: `*`, `?`, `[...]`);
  pattern validity checked in `ValidateConfig`.
- `transform_tools[].schema_patch` — RFC 7386 merge patch applied to the tool's
  parameter schema (`CanonicalTool.Schema`). JSON `null` **removes** a key;
  nested objects recurse; scalars/arrays replace.
- `transform_tools[].description_override` — replaces `CanonicalTool.Description`.
- `inject_tools[]` — OpenAI-style `{type:"function", function:{name,
  description, parameters}}`; `parameters` is an arbitrary JSON-Schema object.
- `on_conflict` — `gateway_wins | client_wins | reject`; required when
  `inject_tools` is non-empty (default `reject`).

## Behavior

`pre_request` only; `enforce` only. When `in.Request` is nil/empty, the body is
not decodable for the active wire format, or `canonical.Tools` is empty **and**
there is nothing to inject, the plugin no-ops (mirrors `pertoolratelimit` early
returns).

Order within a single request (this plugin's internal pipeline):

1. **Decode** — resolve the wire format (`req.SourceFormat` then `req.Provider`,
   the `wireFormat()` helper) and `registry.DecodeRequestFor(body, format)` →
   `*CanonicalRequest`.
2. **Transform** — for each surviving tool, apply **all** matching
   `transform_tools` entries in declaration order: `description_override` sets
   the description (last writer wins); `schema_patch` merge-patches
   `CanonicalTool.Schema` cumulatively (RFC 7386, null deletes).
3. **Inject** — map each `inject_tools` entry to a `CanonicalTool` and append.
   On a name collision against the post-transform tool set **or** an
   already-injected name, apply `on_conflict`:
   - `gateway_wins` → the injected tool **replaces** the same-named existing tool;
   - `client_wins` → the injected tool is **dropped** (existing tool kept);
   - `reject` → return `*appplugins.PluginError{StatusCode: 400, Type:
     "tool_name_reserved", Body: <marshaled envelope>}` and stop.
4. **Re-encode + graft** — `ad.EncodeRequest(canonical)`, then graft only the
   changed `tools` field back onto the **original raw body**
   (`graftChangedFields` pattern) so provider-specific top-level fields survive.
   Return `Result{RequestBody: body}`. The executor writes `req.Body =
   res.RequestBody`; the forwarder forwards it upstream.

### Reject envelope

`reject` returns the exact issue contract. The proxy's `pluginErrorResult` passes
`PluginError.Body` **verbatim** (confirmed: the renderer does not re-wrap a set
body), so `Body` must contain the full nested envelope:

```json
{ "error": { "type": "tool_name_reserved", "name": "safety_check" } }
```

with HTTP status `400` and `PluginError.Type = "tool_name_reserved"`.

### "After Tool allowlist"

The issue's "runs AFTER Tool allowlist" is achieved purely by **policy
`priority` ordering** within the `pre_request` stage (`StagePlan` sorts by
`pol.Priority` ascending). There is no hardcoded inter-plugin stage order and no
Tool allowlist plugin in the repo yet; operators give this policy a higher
priority number than the allowlist/strip policy so transforms only ever see
surviving tools. This is operator guidance, not a code dependency.

## Provider / canonical approach

The plugin never hand-parses provider JSON. It operates on
`adapter.CanonicalRequest.Tools []CanonicalTool{Name, Description, Schema
map[string]interface{}}`, which every registered adapter populates uniformly
(OpenAI `function.parameters`, Anthropic `input_schema`, Gemini/Bedrock/Mistral
equivalents). `Schema` is the decoded JSON-Schema parameters object as a generic
map — exactly the shape RFC 7386 merge patch operates on, with no extra marshal
round-trip. Provider coverage therefore equals the adapter `Registry` coverage,
with no per-provider branching in this plugin.

## Scope handling

`scope` is accepted and enum-validated but **informational**. Effective scope is
derived from `Policy.Global` via `RuntimeScope.Subject()` (global+gatewayID or
consumer+consumerID), matching `per_tool_rate_limiter` and `tool_call_validation`.
A consumer-scoped policy still overrides a same-slug global per the standard
composition rule.

## Registration & catalog

| Touch point | Change |
|---|---|
| `pkg/container/modules/plugins.go` | Add `tooltransform.New(p.Adapters)` to the catalog slice in `newPluginRegistry` (only `*adapter.Registry` needed — no Redis, no pricing). |
| `pkg/app/plugins/catalog_metadata.go` | Hand-authored `SettingsSchema`: `transform_tools[]` (array of objects: `tool` string, `schema_patch` object/map, `description_override` string), `inject_tools[]` (array of objects), `on_conflict` enum, `scope` enum. Stages read from the plugin. The `per_tool_rate_limiter` entry is the array-of-objects template. |
| `pkg/app/plugins/catalog_test.go` | Extend coverage for the new slug/schema. |

## Observability

Mirror the sibling plugins' event-extras pattern (`event.SetExtras(data)` with a
plugin-specific struct, as `PerToolRateLimiterData`). The trace payload records
at minimum:

- the resolved wire format / provider;
- per-transformed-tool: the matched glob, whether the description was overridden,
  whether a schema patch applied;
- injected tool names and, per injection, the `on_conflict` outcome
  (`replaced | dropped | rejected`);
- effective scope dimension/subject.

This makes silent schema tampering auditable in the event stream (see Risks).

## Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| **Silent schema tampering** — operators rewrite tool schemas/descriptions invisibly to the client; debugging "why did the model behave differently" is hard. | Med | Emit full event extras (transformed tool names, patched flags, injected names + conflict outcome) so every mutation is auditable. Document that this plugin rewrites client tool definitions. |
| **False sense of security** — schema patching is *steering*, not *enforcement*; the model can ignore a tightened schema. | High | Frame explicitly as the soft half; non-goal: hard arg enforcement. Document that hard guarantees require pairing with **Tool call argument validation** on the response leg. |
| **Injected-tool executor dependency** — an injected tool the model calls has no implementation; calls go unanswered. | Med | Document that injected tools must be handled by the executor or paired with Tool call argument validation. v1 ships definitions only. |
| **Injected-tool fidelity through canonical** — round-trip preserves only `name/description/schema`; provider-exotic fields dropped. | Med | v1 accepts config-authored `{name,description,parameters}` fidelity; document the limitation; raw-graft fidelity is a follow-up (exploration Approach 3). |
| **Glob ambiguity** for overlapping `transform_tools` (e.g. `search_*` and `search_logs`). | Med | Settled contract: apply **all** matching entries in declaration order, cumulatively (last `description_override` wins). Documented and tested. |
| **Parallel-batch body rewrites** — two `pre_request` plugins both returning `RequestBody`: last applied wins, silently discarding the other. | Med | Run this plugin in its own (non-parallel) priority batch; document that operators must not group it in a parallel `pre_request` batch with another body-rewriting plugin. |
| **Non-tool / undecodable requests.** | Low | No-op cleanly when tools are empty and nothing is injected, or when the format is unknown/undecodable (mirror `pertoolratelimit`). |
| **RFC 7386 null-removal correctness.** | Low | Implement and explicitly test null⇒delete, nested recursion, scalar/array replace per the issue's RFC 7386 note. |

## Capabilities

### New Capabilities

- None at the openspec spec level — this is a new plugin documented in spec.md
  within this change.

### Modified Capabilities

- None.

## Affected areas

| Area | Impact | Description |
|---|---|---|
| `pkg/infra/plugins/tooltransform/` | New | Plugin package: small files — `plugin.go` (orchestration), `config.go`, `transform.go`, `inject.go`, `mergepatch.go` (in-package RFC 7386, ~20 lines, no new dep), glob (reuse `path.Match`), `data.go` (trace), plus unit tests. |
| `pkg/container/modules/plugins.go` | Modified | Register the plugin (one line; only `p.Adapters`). |
| `pkg/app/plugins/catalog_metadata.go` (+ `catalog_test.go`) | Modified | Hand-authored `SettingsSchema` for the new slug. |
| `tests/functional/` | New | Functional-tagged test mirroring `plugin_per_tool_rate_limiter_test.go`: send a request with `tools[]`, assert the upstream-received body was patched/injected, assert `reject` → 400 with the exact envelope. |

## Test strategy

Table-driven unit tests (`go test -race ./...`, tests next to the code):

- **Provider round-trip** — for each registered format (OpenAI completions +
  responses, Anthropic, Gemini, Bedrock, Mistral): decode a request with tools,
  apply a transform + an injection, re-encode, assert the grafted body carries
  the mutated tools and preserves untouched top-level fields.
- **Merge patch (RFC 7386)** — set scalar, set nested object (recurse),
  replace array, **delete key on `null`**, patch against a missing schema.
- **Glob matching** — `*`/`?`/`[...]` cases, `search_*` vs `send_email`,
  multiple overlapping entries applied cumulatively in declaration order, last
  `description_override` wins; invalid pattern rejected in `ValidateConfig`.
- **`on_conflict` matrix** — collision against an existing client tool and
  against an already-injected name, for each of `gateway_wins` (replace),
  `client_wins` (drop), `reject` (error); no-collision injection appends.
- **Reject body** — assert `PluginError{StatusCode:400, Type:
  "tool_name_reserved"}` and `Body` equals the exact
  `{"error":{"type":"tool_name_reserved","name":"<tool>"}}` bytes.
- **No-op paths** — empty tools + no injection, undecodable body, unknown format,
  missing/invalid config (`ValidateConfig`).
- **Catalog** — `catalog_test.go` covers the new slug's schema and stages.
- **Functional** — end-to-end policy-routed test asserting the upstream body and
  the 400 reject path.

## Rollback plan

Additive and self-contained. The plugin is a new package gated by an explicit
policy; removing the `newPluginRegistry` line, the catalog metadata entry, and
the package reverts the change with zero impact on existing traffic or other
plugins. No schema migrations, no shared-state changes.

## Success criteria

- [ ] `transform_tools` patches matching tools' schema (RFC 7386, null-removal
      included) and overrides descriptions across all registered providers.
- [ ] All matching `transform_tools` entries apply cumulatively in declaration
      order.
- [ ] `inject_tools` append new tools; `on_conflict` resolves collisions as
      `gateway_wins | client_wins | reject`.
- [ ] `reject` returns `400` with the exact
      `{"error":{"type":"tool_name_reserved","name":"<tool>"}}` body.
- [ ] `scope` is enum-validated and informational; effective scope from
      `Policy.Global`.
- [ ] Plugin no-ops on empty/undecodable/non-tool requests.
- [ ] Registered in `newPluginRegistry` and the catalog (group "Other").
- [ ] Event extras record transformed/injected tools and conflict outcomes.
