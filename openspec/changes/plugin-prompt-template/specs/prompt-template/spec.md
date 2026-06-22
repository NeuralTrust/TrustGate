# Delta for Prompt Template (prompt_template plugin)

This change adds a net-new `pre_request` infra plugin `prompt_template`. It
mutates the raw provider-native request body (`messages[]` / `system`) and
returns it via `Result.RequestBody`. A single instance MAY run Mode A
(context injection), Mode B (template reference), or both. Scope is derived
from the policy, never config. Runtime rejections return
`*appplugins.PluginError{StatusCode, Type}`. Out of scope in v1:
`consumer_attribute` source, `jinja2_subset` engine, partials,
`/v1/templates/{name}/render`, named-template admin CRUD.

## ADDED Requirements

### Requirement: Stage, modes, and observe behavior

The plugin MUST run only at `pre_request` and MUST support modes `enforce`
and `observe`. Under `enforce` it MUST apply the configured behavior
(inject, render, reject). Under `observe` it MUST evaluate and record its
decision (including would-be rejections and resolved variables) but MUST NOT
mutate the request body and MUST NOT reject the request.

#### Scenario: Enforce mutates and may reject
- GIVEN mode `enforce` and a config that injects a system message
- WHEN a request is processed
- THEN the rewritten body MUST be returned via `Result.RequestBody`

#### Scenario: Observe never mutates or rejects
- GIVEN mode `observe` and a condition that would reject under enforce (e.g. unresolved context variable with `on_missing_context_variable:error`)
- WHEN a request is processed
- THEN the request MUST NOT be rejected AND the body MUST NOT be mutated
- AND the decision MUST be recorded in plugin trace data

### Requirement: Configuration validation

`ValidateConfig` MUST run at admin time (via `pkg/app/policy/validate.go`)
and reject invalid config with a 4xx and a clear message. It MUST enforce:
`template_engine` in `{mustache, jinja2_subset}` defaulting to `mustache`,
rejecting `jinja2_subset` as "not yet supported in v1"; each
`inject_templates[]` entry has a valid `position`, `role`, `on_existing_system`
enum and non-empty `content`; `named_templates` have unique `name`, each with
unique `version` strings and `required_variables` whose `type`/`enum`/
`max_length` are well-formed; `context_variables[*].source` in
`{header, jwt_claim}`, rejecting `consumer_attribute` as "deferred/unsupported";
`on_missing_context_variable` and `on_missing_client_variable` enum values; and,
when `named_templates` are present, `default_label` MUST be a label of at least
one version.

#### Scenario: jinja2_subset rejected
- GIVEN `template_engine:"jinja2_subset"`
- WHEN `ValidateConfig` runs
- THEN it MUST fail with a "not yet supported in v1" message

#### Scenario: consumer_attribute source rejected
- GIVEN a context variable with `source:"consumer_attribute"`
- WHEN `ValidateConfig` runs
- THEN it MUST fail with a "deferred/unsupported" message

#### Scenario: Engine defaults to mustache
- GIVEN a config omitting `template_engine`
- WHEN `ValidateConfig` runs
- THEN it MUST pass with the engine defaulted to `mustache`

#### Scenario: Structural validation
- GIVEN duplicate `named_templates[].name`, a duplicate `version`, an empty inject `content`, a bad `on_existing_system`, or a `default_label` matching no version label
- WHEN `ValidateConfig` runs
- THEN it MUST fail for each case

### Requirement: Mode A context variable resolution

For each `inject_templates[]` entry the plugin MUST resolve `{{var}}`
placeholders from `context_variables{}`. Sources MUST be `header` (read the
named inbound header) or `jwt_claim` (read the named claim from the inbound
`Authorization` bearer token parsed UNVERIFIED). A missing/unparsable token or
absent header/claim is a missing context variable governed by
`on_missing_context_variable`: `error` MUST reject `500
template_variable_unresolved`; `empty_string` MUST substitute `""`;
`skip_injection` MUST drop that single injection and continue.

#### Scenario: Header and jwt_claim resolve
- GIVEN `tenant` from header `X-Tenant-Id:"acme"` and `user_role` from jwt claim `role:"admin"`
- WHEN content `"support for {{tenant}}, role {{user_role}}"` is rendered
- THEN it MUST render `"support for acme, role admin"`

#### Scenario: Missing variable with error
- GIVEN `on_missing_context_variable:"error"` and an absent header
- WHEN the entry is rendered
- THEN the request MUST be rejected 500 with `type:"template_variable_unresolved"`

#### Scenario: Missing variable with empty_string
- GIVEN `on_missing_context_variable:"empty_string"` and an absent claim
- WHEN the entry is rendered
- THEN the placeholder MUST be substituted with `""` and injection proceeds

#### Scenario: Missing variable with skip_injection
- GIVEN `on_missing_context_variable:"skip_injection"` and an unresolved variable
- WHEN the entry is processed
- THEN that injection MUST be skipped and other entries MUST still apply

### Requirement: Mode A injection and system collision

The rendered content MUST be injected at `position` (v1: `system`) with the
configured `role`. The system target MUST be selected by body shape: if the
body has a top-level `system` string field, the injection MUST operate on that
`system` string; otherwise it MUST insert/merge a system-role message in
`messages[]`. A single request is not expected to carry both forms and the
plugin MUST NOT specify simultaneous handling. When system content already
exists in the selected target, `on_existing_system` MUST govern: `merge` MUST
combine the rendered content with the existing system content (existing first,
injected appended, newline-separated) preserving a single system target;
`replace` MUST overwrite the existing system content with the rendered content.
When no system content exists in the selected target, the plugin MUST add it
regardless of `on_existing_system`.

#### Scenario: Merge into top-level system string
- GIVEN a body with top-level `system:"Be concise."` and `on_existing_system:"merge"`
- WHEN content `"You are support."` is injected
- THEN the `system` string MUST contain both, existing first then injected, newline-separated

#### Scenario: Merge into messages system message
- GIVEN a body with no top-level `system` field but a system-role message in `messages[]` and `on_existing_system:"merge"`
- WHEN content is injected
- THEN the existing system-role message MUST contain both, existing first then injected, as one system message

#### Scenario: Replace existing system
- GIVEN a body whose selected system target already has content and `on_existing_system:"replace"`
- WHEN content is injected
- THEN the selected system target content MUST be exactly the rendered content

#### Scenario: No existing system
- GIVEN a body with no top-level `system` field and no system-role message in `messages[]`
- WHEN content is injected
- THEN a new system-role message with the rendered content MUST be added to `messages[]`

### Requirement: Mode B reference detection and resolution

The plugin MUST scan for a `{template://<name>@<label>}` reference in inbound
`messages[].content` strings and in the top-level `system` string. When
`@<label>` is omitted it MUST fall back to `default_label`. It
MUST resolve the named template and the version carrying that label. An unknown
template name or unresolvable label MUST reject `400 template_not_found`. When
no reference is present, `allow_untemplated_requests:false` MUST reject `400
template_required`, and `true` MUST pass the request through unchanged.

#### Scenario: Label resolves to version
- GIVEN a `messages[].content` string `{template://support-bot@stable}` and `stable` labels version `v3`
- WHEN the reference is resolved
- THEN version `v3` content MUST be selected

#### Scenario: Reference detected in top-level system string
- GIVEN a top-level `system` string containing `{template://support-bot@stable}`
- WHEN references are scanned
- THEN the reference MUST be detected and resolved the same as in `messages[].content`

#### Scenario: Default label fallback
- GIVEN `{template://support-bot}` with no `@label` and `default_label:"stable"`
- WHEN resolved
- THEN the version labeled `stable` MUST be selected

#### Scenario: Unknown template or label
- GIVEN `{template://nope@v9}` matching no template/label
- WHEN resolved
- THEN the request MUST be rejected 400 with `type:"template_not_found"`

#### Scenario: Untemplated handling
- GIVEN no `{template://}` reference present
- WHEN `allow_untemplated_requests:false`
- THEN the request MUST be rejected 400 with `type:"template_required"`
- AND when `true` the request MUST pass through unchanged

### Requirement: Mode B client variable validation

The client MUST supply its variables in a top-level request body field named
`properties` (Kong-compatible). The plugin MUST validate the `properties` map
against the resolved version's `required_variables` and MUST strip `properties`
from the body before forwarding upstream. A missing required variable MUST
reject `400 template_variable_missing`. A present variable failing `type`,
`enum` membership, or `max_length` MUST reject `400 template_variable_invalid`.
A variable that is not required but absent MUST follow
`on_missing_client_variable`: `error` rejects `400 template_variable_missing`;
`empty_string` substitutes `""`.

#### Scenario: Missing required variable
- GIVEN `required_variables.persona` and a request whose `properties` omits `persona`
- WHEN `properties` is validated
- THEN the request MUST be rejected 400 with `type:"template_variable_missing"`

#### Scenario: Enum / type / length violation
- GIVEN `persona` with `enum:["friendly","formal"]` and a `properties.persona` value `"rude"`, or a value exceeding `max_length`, or a wrong type
- WHEN `properties` is validated
- THEN the request MUST be rejected 400 with `type:"template_variable_invalid"`

#### Scenario: Non-required missing with empty_string
- GIVEN a non-required placeholder absent from `properties` and `on_missing_client_variable:"empty_string"`
- WHEN `properties` is validated
- THEN the placeholder MUST be substituted with `""`

#### Scenario: properties stripped before forwarding
- GIVEN a request carrying a top-level `properties` field
- WHEN the body is rewritten for upstream
- THEN `properties` MUST be removed from the forwarded body

### Requirement: Mode B rendering and body substitution

The plugin MUST render the version `content` substituting variables where
client-supplied `properties` values take precedence over context variables.
When `escape_json_control_chars:true` it MUST escape JSON control characters in
substituted values. It MUST parse the rendered messages fragment as JSON and
the rendered template messages MUST replace the request `messages` array (Kong
semantics).

#### Scenario: Client value beats context value
- GIVEN a variable resolvable from both client `properties` and `context_variables`
- WHEN rendered
- THEN the client-supplied value MUST be used

#### Scenario: Control characters escaped
- GIVEN `escape_json_control_chars:true` and a value containing a newline/quote
- WHEN rendered into the JSON fragment
- THEN control characters MUST be escaped so the fragment parses as valid JSON

#### Scenario: Rendered messages replace the request array
- GIVEN a rendered messages fragment and a body with client messages
- WHEN substituted
- THEN the rendered template messages MUST replace the request `messages` array

### Requirement: Runtime error mapping

Each runtime rejection MUST return `*PluginError` with the exact `StatusCode`
and `Type`: `template_variable_unresolved` → 500;
`template_variable_missing` → 400; `template_variable_invalid` → 400;
`template_not_found` → 400; `template_required` → 400. The proxy surfaces
`{"error":"plugin_rejected","type":<Type>,...}`.

#### Scenario: Status and type pairing
- GIVEN each rejection condition above
- WHEN the plugin rejects
- THEN the returned `PluginError.StatusCode` and `.Type` MUST match the mapping exactly
