# Delta for Tool allowlist (tool_allowlist plugin) — RUN-706

This change adds a new `pre_request` plugin, slug `tool_allowlist`, that performs
access control over the LLM request `tools[]` array before the upstream provider
sees the request. It absorbs and generalises the EE `tool_permission` plugin:
glob allow/deny filtering of canonical tool names plus an empty-after-filter
policy. Matching is on the canonical tool name and is provider-agnostic across
all supported source formats (OpenAI/Anthropic/Gemini/Mistral/…). Effective
scope is always derived from `Policy.Global`; the config `scope` field is
informational only.

## ADDED Requirements

### Requirement: Plugin stages and modes

The plugin SHALL run only at the `pre_request` stage and SHALL declare it as both
a mandatory and a supported stage. The plugin SHALL support the `enforce` and
`observe` modes. Under `enforce` the plugin MAY mutate the forwarded request body
or reject the request. Under `observe` the plugin SHALL NOT mutate the request
body and SHALL NOT reject the request; it SHALL only record telemetry.

#### Scenario: Enforce filters and may reject
- GIVEN mode `enforce` and a config that filters the request `tools[]` to empty with `on_empty_after_filter:reject`
- WHEN a request with a non-empty `tools[]` is processed
- THEN the request MUST be rejected with 403 and the upstream MUST NOT be called

#### Scenario: Observe never mutates or rejects
- GIVEN mode `observe` and a config that would otherwise reject or strip tools
- WHEN a request with a non-empty `tools[]` is processed
- THEN the request body MUST be forwarded unchanged AND the request MUST NOT be rejected
- AND the telemetry decision MUST still be recorded

### Requirement: Configuration validation

`ValidateConfig` SHALL reject invalid configurations. At least one of
`allow_tools` or `deny_tools` SHALL be set (non-empty). Every glob pattern in
`allow_tools` and `deny_tools` SHALL be a valid `path.Match` pattern. The
`on_empty_after_filter` value SHALL be one of `reject`, `pass_through_empty`, or
`strip_tools_field`; an empty/absent value SHALL default to `reject`. The `scope`
field is a free-form informational string and SHALL NOT affect validation outcome
or runtime behaviour.

#### Scenario: At least one list required
- GIVEN a config with neither `allow_tools` nor `deny_tools` set
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Invalid glob pattern rejected
- GIVEN a config whose `allow_tools` or `deny_tools` contains a pattern that `path.Match` reports as malformed (e.g. `"[a-"`)
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Invalid on_empty_after_filter rejected
- GIVEN a config with `on_empty_after_filter:"drop"`
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Empty on_empty_after_filter defaults to reject
- GIVEN a config with `allow_tools` set and `on_empty_after_filter` absent or empty
- WHEN `ValidateConfig` runs
- THEN it MUST pass AND the effective behaviour MUST be `reject`

#### Scenario: Scope field is inert
- GIVEN two otherwise identical valid configs differing only in `scope` (e.g. `"consumer"` vs `"global"` vs unset)
- WHEN each is validated and executed against the same request
- THEN validation MUST pass for all AND the filtering outcome MUST be identical

### Requirement: Tool name glob matching

Filtering SHALL match against the canonical tool name
(`adapter.CanonicalRequest.Tools[].Name`), decoded via the adapter registry, so
the same config applies uniformly across OpenAI, Anthropic, Gemini, and Mistral
source formats. Patterns SHALL be evaluated with `path.Match` semantics,
supporting `*`, `?`, and `[...]`. A tool name matches a list when it matches any
pattern in that list. An exact tool name (no wildcards) SHALL match literally.

#### Scenario: Wildcard matches canonical name
- GIVEN `allow_tools:["search_*"]` and a request whose canonical tools are `search_web` and `calculate`
- WHEN filtering runs
- THEN `search_web` MUST be kept AND `calculate` MUST be removed

#### Scenario: Provider-agnostic matching
- GIVEN the same `allow_tools:["get_weather"]` config
- WHEN one request arrives in OpenAI format (tool under `tools[].function.name`) and another in Anthropic format (top-level `tools[].name`), each exposing a `get_weather` tool
- THEN both MUST normalise to the canonical name `get_weather` AND be kept

#### Scenario: Character-class and single-char globs
- GIVEN `deny_tools:["admin_?","db_[rw]*"]`
- WHEN a request exposes `admin_x`, `db_read`, and `report`
- THEN `admin_x` and `db_read` MUST be removed AND `report` MUST be kept

### Requirement: Allow-only filtering

When `allow_tools` is non-empty and `deny_tools` is empty, the plugin SHALL keep
only the tools whose canonical name matches at least one `allow_tools` pattern and
SHALL remove all others.

#### Scenario: Keep only allowed tools
- GIVEN `allow_tools:["search_*","calculate"]` and request tools `search_web`, `calculate`, `delete_db`
- WHEN filtering runs
- THEN the surviving set MUST be exactly `search_web` and `calculate`

### Requirement: Deny-only filtering

When `deny_tools` is non-empty and `allow_tools` is empty, the plugin SHALL start
from the full client tool set and SHALL remove every tool whose canonical name
matches any `deny_tools` pattern, keeping the rest.

#### Scenario: Remove denied tools
- GIVEN `deny_tools:["delete_*"]` and request tools `search_web`, `delete_db`, `delete_file`
- WHEN filtering runs
- THEN `delete_db` and `delete_file` MUST be removed AND `search_web` MUST be kept

### Requirement: Allow then deny precedence

The filter pipeline SHALL apply `allow_tools` first and `deny_tools` second.
Starting from the client `tools[]`: if `allow_tools` is non-empty, keep only the
tools matching an allow pattern; then remove any remaining tool matching a
`deny_tools` pattern. Deny SHALL be evaluated after allow, so deny overrides allow
and a denied tool is removed even if it was allowed. This intentionally differs
from the EE `tool_permission` plugin, where a non-empty `white_list` shadowed
`deny_list` entirely.

#### Scenario: Deny removes an allowed tool
- GIVEN `allow_tools:["search_*"]` and `deny_tools:["search_internal"]` with request tools `search_web`, `search_internal`, `calculate`
- WHEN filtering runs
- THEN `search_web` MUST be kept; `search_internal` MUST be removed (denied after allow); `calculate` MUST be removed (not allowed)

#### Scenario: Migration ordering note from EE
- GIVEN an EE config migrated as `allow_tools` ← `white_list` and `deny_tools` ← `deny_list`, with a tool present in both lists
- WHEN filtering runs under this plugin
- THEN the tool MUST be removed (deny wins), whereas the EE plugin would have kept it (whitelist shadowed denylist)

### Requirement: Partial filter preserves surviving request

When filtering removes some tools but at least one tool survives, the plugin SHALL
forward the request body carrying only the surviving tools and SHALL preserve all
other fields of the original body, including fields the canonical model does not
represent (e.g. `parallel_tool_calls`). The rewrite SHALL use field-graft
semantics so only the changed top-level keys are applied back onto the original
body.

#### Scenario: Surviving tools forwarded, other fields intact
- GIVEN a request with tools `search_web`, `delete_db`, a `tool_choice`, and `parallel_tool_calls:true`, and `deny_tools:["delete_*"]`
- WHEN filtering removes `delete_db` but keeps `search_web`
- THEN the forwarded body MUST contain only `search_web` in `tools[]`
- AND `tool_choice` and `parallel_tool_calls:true` MUST be preserved unchanged

#### Scenario: No-change pass is byte-stable
- GIVEN a request whose tools all survive filtering
- WHEN the plugin processes it
- THEN the forwarded body MUST be byte-identical to the original (graft applies no changes)

### Requirement: Empty-after-filter only fires on non-empty input

The `on_empty_after_filter` policy SHALL apply only when the request STARTED with
a non-empty `tools[]` array that filtered down to empty. A request that began with
no tools SHALL NOT trigger any `on_empty_after_filter` behaviour.

#### Scenario: Pre-existing empty tools is not a filter result
- GIVEN a request with an empty or absent `tools[]` array and `on_empty_after_filter:reject`
- WHEN the plugin processes it
- THEN the request MUST be forwarded unchanged AND MUST NOT be rejected

### Requirement: Empty-after-filter reject

When the filtered tool set is empty (from a non-empty input) and
`on_empty_after_filter` is `reject` (the default), the plugin under `enforce`
SHALL reject the request with HTTP status 403, SHALL NOT call the upstream, and
SHALL return a JSON body of the shape
`{ "error": { "type": "no_tools_allowed", "requested": [...], "allowed_after_filter": [] } }`,
where `requested` lists the canonical names of the originally requested tools and
`allowed_after_filter` is an empty array. The response `Content-Type` SHALL be
`application/json`.

#### Scenario: Reject with no_tools_allowed body
- GIVEN `allow_tools:["search_*"]`, `on_empty_after_filter:reject`, mode `enforce`, and request tools `delete_db`, `calculate`
- WHEN filtering yields an empty set
- THEN the response MUST be 403 with `Content-Type: application/json`
- AND the body MUST be `{ "error": { "type": "no_tools_allowed", "requested": ["delete_db","calculate"], "allowed_after_filter": [] } }`
- AND the upstream provider MUST NOT be called

### Requirement: Empty-after-filter strip_tools_field

When the filtered tool set is empty (from a non-empty input) and
`on_empty_after_filter` is `strip_tools_field`, the plugin SHALL forward the
request with the `tools`, `tool_choice`, and `parallel_tool_calls` keys removed
from the body. This reproduces the EE cleanup and avoids upstream 400s caused by a
dangling `tool_choice` with no tools.

#### Scenario: Strip all three tool-related keys
- GIVEN a request with `tools`, `tool_choice`, and `parallel_tool_calls` set, and `on_empty_after_filter:strip_tools_field` where filtering empties the tool set
- WHEN the request is forwarded
- THEN the forwarded body MUST NOT contain `tools`, `tool_choice`, or `parallel_tool_calls`
- AND all other fields MUST be preserved

### Requirement: Empty-after-filter pass_through_empty

When the filtered tool set is empty (from a non-empty input) and
`on_empty_after_filter` is `pass_through_empty`, the plugin SHALL forward the
request with `tools` set to an empty array (`tools: []`) and SHALL remove the
dangling `tool_choice` and `parallel_tool_calls` keys.

#### Scenario: Keep empty tools array, drop choice keys
- GIVEN a request with non-empty `tools`, a `tool_choice`, and `parallel_tool_calls`, with `on_empty_after_filter:pass_through_empty` where filtering empties the tool set
- WHEN the request is forwarded
- THEN the forwarded body MUST contain `tools: []`
- AND it MUST NOT contain `tool_choice` or `parallel_tool_calls`
- AND all other fields MUST be preserved

### Requirement: No-op safety

The plugin SHALL forward the request unchanged and SHALL NOT reject when any of
the following holds: the request body is empty, the wire format cannot be resolved,
the body fails to decode into a canonical request, or the request had no tools to
begin with. None of these cases SHALL produce a 403.

#### Scenario: Empty body forwarded unchanged
- GIVEN a request with an empty body
- WHEN the plugin runs
- THEN the body MUST be forwarded unchanged AND MUST NOT be rejected

#### Scenario: Unresolved wire format forwarded unchanged
- GIVEN a request whose source/target wire format cannot be resolved
- WHEN the plugin runs
- THEN the body MUST be forwarded unchanged AND MUST NOT be rejected

#### Scenario: Undecodable body forwarded unchanged
- GIVEN a request body that fails canonical decoding
- WHEN the plugin runs
- THEN the body MUST be forwarded unchanged AND MUST NOT be rejected

#### Scenario: No tools present forwarded unchanged
- GIVEN a request that resolves to a canonical request with no tools
- WHEN the plugin runs
- THEN the body MUST be forwarded unchanged AND MUST NOT be rejected

### Requirement: Telemetry decision recording

For every processed request, in both `enforce` and `observe`, the plugin SHALL
record a telemetry trace via the event extras containing at least: `provider`,
`tools_requested` (canonical names requested), `tools_allowed` (surviving names),
`tools_removed` (filtered-out names), `action` (e.g. forward / partial-strip /
strip-field / pass-through-empty / reject / noop), `on_empty` (the configured
policy), and a `decision` reflecting the plugin mode.

#### Scenario: Telemetry on partial filter
- GIVEN a request where `delete_db` is removed and `search_web` survives
- WHEN the plugin records telemetry
- THEN the trace MUST report `tools_requested` including both names, `tools_allowed:["search_web"]`, `tools_removed:["delete_db"]`, and the corresponding `action`

#### Scenario: Telemetry in observe mirrors enforce decision
- GIVEN mode `observe` and a config that would reject under `enforce`
- WHEN the plugin runs
- THEN the trace MUST record the would-be `action` and `decision` without the request being mutated or rejected

## Non-requirements (limitations)

These are explicitly out of scope for this change and SHALL NOT be implemented as
requirements:

- **Raw Bedrock-Converse inbound bodies**: requests whose source wire format is a
  raw Bedrock Converse body (`toolConfig.tools`) are not parsed by the adapter and
  are not covered. Requests whose `SourceFormat` is a supported canonical format
  (OpenAI/Anthropic/Gemini/Mistral/…) are covered, including those routed to a
  Bedrock backend.
- **Body rewrites under parallel same-priority `pre_request` batches**: when this
  plugin runs in a parallel same-priority `pre_request` batch, body rewrites
  (`RequestBody`) may be dropped by the isolated-clone merge, which preserves only
  headers and metadata. Reject via `StopUpstream` still applies. Single-plugin
  batches preserve the rewrite.
- **Scope-driven partitioning**: the `scope` config field is informational only;
  effective scope derives from `Policy.Global`.
- **Matching on tool description or schema**: matching is on the canonical tool
  name only.
