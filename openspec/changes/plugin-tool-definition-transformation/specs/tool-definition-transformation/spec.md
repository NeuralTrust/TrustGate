# Spec for Tool Definition Transformation (tool_definition_transformation plugin)

New `pre_request`-only, `enforce`-only plugin (slug
`tool_definition_transformation`). It operates on the provider-neutral
`adapter.CanonicalRequest.Tools` so behavior is identical across all
adapter-supported providers (OpenAI completions + responses, Anthropic, Gemini,
Bedrock, Mistral). It transforms surviving tools, then injects operator-defined
tools, and grafts only the changed `tools` field back onto the original raw body.
It runs AFTER the Tool allowlist purely via policy `priority` ordering; it never
gates access.

## ADDED Requirements

### Requirement: Stage and mode

The plugin MUST support and mandate only the `pre_request` stage and MUST support
only the `enforce` mode. It MUST NOT run on the response leg.

#### Scenario: Pre-request enforce only
- GIVEN a policy binding this plugin
- WHEN stage/mode are resolved
- THEN `pre_request` MUST be mandatory and supported, `enforce` the only mode
- AND no `post_response` behavior is registered

### Requirement: Schema patch transform

For each surviving tool, the plugin MUST apply `schema_patch` as an RFC 7386 JSON
merge patch over `CanonicalTool.Schema`: a JSON `null` value MUST delete that key,
nested objects MUST recurse, and scalars/arrays MUST replace the existing value.

#### Scenario: Patch sets and replaces values
- GIVEN a tool `search_docs` matched by glob `search_*` with `schema_patch` setting `properties.include_archived.enum` to `[false]`
- WHEN the transform runs
- THEN the tool's schema MUST contain the patched `enum`
- AND sibling schema keys MUST be preserved

#### Scenario: Null removes a property
- GIVEN `schema_patch` with `properties.internal_only` set to `null`
- WHEN the transform runs
- THEN the `internal_only` property MUST be removed from the tool's schema

### Requirement: Description override transform

When a matching `transform_tools` entry has `description_override`, the plugin
MUST replace `CanonicalTool.Description` with that value.

#### Scenario: Description replaced
- GIVEN a matched tool and `description_override:"Search public documents only."`
- WHEN the transform runs
- THEN the tool's description MUST equal that string

### Requirement: Cumulative matching and glob semantics

Tool-name matching MUST use `path.Match` glob semantics (`*`, `?`, `[...]`). ALL
matching `transform_tools` entries MUST apply to a tool in declaration order:
schema patches accrue cumulatively, and the last `description_override` wins.
A tool matched by no entry MUST be left untouched.

#### Scenario: Multiple matching entries accrue
- GIVEN entries `search_*` and `search_logs` both matching tool `search_logs`
- WHEN transforms run in declaration order
- THEN both schema patches MUST apply cumulatively
- AND the last entry's `description_override` MUST win

#### Scenario: No match leaves tool unchanged
- GIVEN a tool `send_email` and only a `search_*` entry
- WHEN transforms run
- THEN `send_email` MUST be unchanged

### Requirement: Tool injection after transforms

The plugin MUST append `inject_tools[]` AFTER all transforms. Each entry's
`function{name, description, parameters}` MUST map to
`CanonicalTool{Name, Description, Schema}` (v1 fidelity = these three fields
only). Injected tools MUST be real definitions the model can call.

#### Scenario: Injected tool visible to model
- GIVEN `inject_tools` containing `safety_check` and a request with one client tool
- WHEN the plugin runs
- THEN the upstream `tools[]` MUST contain both the (transformed) client tool and `safety_check`
- AND injection MUST occur only after transforms have been applied

### Requirement: Conflict resolution on injection

A collision is an injected name equal to a post-transform surviving tool name OR
to an already-injected name. `on_conflict` (default `gateway_wins`) MUST resolve
it: `gateway_wins` MUST replace the same-named existing tool with the injected
one; `client_wins` MUST drop the injected tool and keep the existing one;
`reject` MUST return HTTP `400` and stop, with `PluginError.Type =
"tool_name_reserved"` and a body EXACTLY equal to
`{"error":{"type":"tool_name_reserved","name":"<tool>"}}`.

#### Scenario: gateway_wins replaces existing
- GIVEN a client tool `lookup` and an injected tool `lookup` with `on_conflict:gateway_wins`
- WHEN injection runs
- THEN the injected `lookup` MUST replace the client `lookup`

#### Scenario: client_wins drops injected
- GIVEN the same collision with `on_conflict:client_wins`
- WHEN injection runs
- THEN the injected tool MUST be dropped and the client tool kept

#### Scenario: reject returns exact 400 envelope
- GIVEN a collision with `on_conflict:reject` on tool `safety_check`
- WHEN injection runs
- THEN the request MUST be rejected `400` with body `{"error":{"type":"tool_name_reserved","name":"safety_check"}}`

#### Scenario: Injected-vs-injected collision
- GIVEN two `inject_tools` entries with the same name
- WHEN injection runs under each `on_conflict`
- THEN `gateway_wins` MUST keep the later, `client_wins` MUST keep the earlier, `reject` MUST 400 with that name

### Requirement: Provider neutrality and field preservation

The plugin MUST produce identical transform/inject results regardless of provider
wire format, operating only on `CanonicalRequest.Tools`. After re-encoding it
MUST graft only the changed `tools` field back onto the original raw body so
provider-specific top-level fields are preserved.

#### Scenario: Same behavior across shapes
- GIVEN equivalent requests in OpenAI and Anthropic shapes with the same logical tools
- WHEN the same config runs
- THEN the resulting tool set MUST be equivalent for both
- AND untouched top-level fields (e.g. provider-specific request options) MUST survive verbatim

### Requirement: No-op and passthrough

The plugin MUST forward the request unchanged (200, no body rewrite) when there
are no tools and nothing to inject, or when no `transform_tools` match and there
are no `inject_tools`. It MUST no-op cleanly when the body is empty/nil or
undecodable for the active wire format.

#### Scenario: No matching transforms and no injection
- GIVEN tools present but no entry matches and `inject_tools` is empty
- WHEN the plugin runs
- THEN the body MUST be forwarded unchanged with no rewrite

#### Scenario: Undecodable or empty body
- GIVEN a nil/empty or undecodable request body
- WHEN the plugin runs
- THEN it MUST no-op and forward the original body

### Requirement: Scope handling

The `scope` config field MUST be informational only; when present it MUST be
validated against `{consumer, global}`. Effective scope MUST be derived from
`Policy.Global`, not from config.

#### Scenario: Effective scope from policy
- GIVEN `scope:"consumer"` in config and a global policy
- WHEN the plugin resolves scope
- THEN the effective scope MUST follow `Policy.Global`, treating `scope` as informational

### Requirement: Configuration validation

`ValidateConfig` MUST reject: a `scope` outside `{consumer, global}`; an
`on_conflict` outside `{gateway_wins, client_wins, reject}`; an `inject_tools`
entry with an empty `function.name`; and an invalid `transform_tools[].tool`
glob pattern.

#### Scenario: Invalid values rejected
- GIVEN any of an invalid `scope`, unknown `on_conflict`, empty injected name, or invalid glob
- WHEN `ValidateConfig` runs
- THEN it MUST fail for that configuration

### Requirement: Observability

On transform, inject, and reject the plugin MUST record event extras
(`event.SetExtras`) mirroring sibling plugins, including at minimum the resolved
wire format, per-transformed-tool flags (matched glob, description overridden,
schema patched), injected tool names with each `on_conflict` outcome
(`replaced | dropped | rejected`), and the effective scope dimension/subject.

#### Scenario: Extras recorded on mutation
- GIVEN a request that transforms one tool and injects another
- WHEN the plugin completes
- THEN event extras MUST list the transformed tool flags and the injected name with its outcome

#### Scenario: Extras recorded on reject
- GIVEN a `reject` collision
- WHEN the plugin rejects
- THEN event extras MUST record the rejected injected tool name and `rejected` outcome
