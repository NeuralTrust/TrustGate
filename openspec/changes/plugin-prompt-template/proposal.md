# Proposal: Prompt template plugin — RUN-702

## Why

Prompts today live inside application code: every client hard-codes its system
prompt, versioning is ad-hoc, and there is no central place to audit, swap, or
roll a prompt forward without a client deploy. RUN-702 moves prompt management
to the gateway as a plugin, decoupled from app code, with two complementary
patterns:

- **Mode A (context binding)** — the gateway injects a templated prompt into
  every matching request. Template variables resolve from request context
  (headers, JWT claims). The client may be entirely unaware.
- **Mode B (template reference)** — the client references a named, versioned
  template (`{template://support-bot@v3}`) and supplies a variables map; the
  gateway renders it and forwards the result upstream.

A single plugin instance can run either mode or both. Scope (consumer vs
global) is derived from the policy, not the config.

- Linear: **RUN-702** "Plugin: Prompt template".

## What changes

A net-new infra plugin `prompt_template` in `pkg/infra/plugins/prompttemplate/`,
running at `pre_request`, mutating the raw provider-native request body
(OpenAI-style `messages[]` / `system`) and returning it via `Result.RequestBody`
— the same body-rewrite channel proven by `model_allowlist`.

### Mode A — context injection
- For each entry in `inject_templates[]`, render its `content` using
  `context_variables{}` and inject it into the body at `position` (v1:
  `system`) with the configured `role`.
- `on_existing_system` controls collision behavior when a system message
  already exists: `merge` (combine) or `replace`.
- Unresolved context variable behavior is governed by
  `on_missing_context_variable`: `error` → reject `500
  template_variable_unresolved`; `empty_string` → substitute empty; or
  `skip_injection` → drop that injection.

### Mode B — template reference
- Detect `{template://<name>@<label>}` references in the inbound request.
- Resolve the named template + version by label (falling back to
  `default_label`); unknown name/label → reject `400 template_not_found`.
- Validate client-supplied variables against the version's
  `required_variables{type, enum, max_length}`: missing → `400
  template_variable_missing`; type/enum/length violation → `400
  template_variable_invalid`.
- Render the version `content` and substitute/prepend the resulting messages
  fragment into the body.
- If a request carries no template reference and
  `allow_untemplated_requests:false` → reject `400 template_required`.

### Config schema, validation, errors
- Config parsed via `pluginutil.Parse[config]`; admin-time validation in
  `ValidateConfig` (invoked from `pkg/app/policy/validate.go`) rejects bad
  config with 4xx.
- Runtime rejections return `*appplugins.PluginError{StatusCode, Type, ...}`
  with `Type` set to the spec error codes; the proxy surfaces
  `{"error":"plugin_rejected","type":<Type>,...}`.

### Catalog metadata & registration
- Register in `pkg/container/modules/plugins.go` (`newPluginRegistry` catalog
  slice + `reg.Register`).
- Hand-author UI/catalog metadata (`SettingsSchema`) in
  `pkg/app/plugins/catalog_metadata.go`.

## Config schema (v1)

```json
{
  "template_engine": "mustache",
  "context_variables": {
    "tenant": { "source": "header", "name": "X-Tenant-Id" },
    "user_role": { "source": "jwt_claim", "name": "role" }
  },
  "inject_templates": [
    {
      "id": "support-system",
      "position": "system",
      "role": "system",
      "content": "You are support for {{tenant}}. Caller role: {{user_role}}.",
      "on_existing_system": "merge"
    }
  ],
  "named_templates": [
    {
      "name": "support-bot",
      "versions": [
        {
          "version": "v3",
          "labels": ["stable", "default"],
          "content": "You are {{persona}} helping with {{topic}}.",
          "required_variables": {
            "persona": { "type": "string", "enum": ["friendly", "formal"] },
            "topic": { "type": "string", "max_length": 120 }
          }
        }
      ]
    }
  ],
  "allow_untemplated_requests": true,
  "on_missing_context_variable": "error",
  "on_missing_client_variable": "error",
  "default_label": "stable",
  "escape_json_control_chars": true
}
```

- `template_engine`: `mustache` (default, the only engine shipped in v1).
- `context_variables[*].source`: `header` | `jwt_claim` only in v1.
- `named_templates` are stored **inline** in plugin config; per-template
  versioning with movable labels (a label points at one version, repointable).

## Runtime error mapping

| Condition | Mode | StatusCode | PluginError.Type |
|-----------|------|-----------|------------------|
| Unresolved context variable, `on_missing_context_variable:error` | A | 500 | `template_variable_unresolved` |
| Missing client variable, `on_missing_client_variable:error` | B | 400 | `template_variable_missing` |
| Client variable fails type/enum/max_length | B | 400 | `template_variable_invalid` |
| Referenced template/label not found | B | 400 | `template_not_found` |
| No reference + `allow_untemplated_requests:false` | B | 400 | `template_required` |

## Scope decisions baked into v1

1. **`context_variables` sources = `header` and `jwt_claim` only.**
   `consumer_attribute` is **deferred** (see Non-goals): there is no consumer
   attribute store and the plugin has no access to the consumer object
   (`consumer.Consumer` exposes only `Name/Slug/Type/Headers`).
2. **`jwt_claim` reads the inbound `Authorization` bearer token UNVERIFIED**
   via `jwt.NewParser().ParseUnverified` (pattern at
   `pkg/app/oauth/proxy.go` / `pkg/api/middleware/auth_chain.go`). **Trust
   boundary:** the request is already authenticated by the auth middleware
   upstream of `pre_request`; the plugin only reads claims for substitution
   and never makes an auth decision, so signature re-verification is out of
   scope and unnecessary here. A missing/unparsable token is treated as a
   missing context variable and follows `on_missing_context_variable`.
3. **`named_templates` are inline in plugin config.** No admin CRUD, no DB
   migration, no `/v1/templates` endpoints in v1.
4. **`template_engine`: ship `mustache` only in v1.** `jinja2_subset` is
   accepted in the config schema but **rejected at `ValidateConfig`** with a
   clear "engine not yet supported" 4xx (lower-risk than shipping a partial
   sandbox). A sandboxed `jinja2_subset` engine is a follow-up.
5. **Body mutation operates on raw provider JSON** (`messages`/`system`),
   mirroring `model_allowlist`, returned via `Result.RequestBody`. Mode A
   injects/merges a system message at `position` per `on_existing_system`.
   Mode B renders the named version (resolved by label, `default_label`
   fallback), validates client properties against `required_variables`, and
   substitutes/prepends the rendered messages fragment.
6. **No code comments** except the Apache license header (repo policy
   `.agents/AGENT.md` §11).

## Non-goals / Out of scope (v1)

- **`consumer_attribute` variable source** — deferred; no consumer attribute
  store exists and the plugin cannot reach the consumer object. Follow-up once
  a consumer-attribute path exists.
- **`jinja2_subset` engine** — schema-accepted but rejected at validation in
  v1; sandboxed engine is a follow-up.
- **Partials / template includes** — out of scope per RUN-702.
- **`/v1/templates/{name}/render` endpoint** — out of scope per RUN-702.
- **Named-template admin CRUD / DB-backed template store** — templates are
  inline config only in v1.

## Impact / affected files

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/plugins/prompttemplate/` | New | `plugin.go` (orchestration), `config.go` (schema + `ValidateConfig`), `engine.go` (mustache render), `modeA.go` / `modeB.go` (injection / reference), `jwt.go` (unverified claim read), `data.go` (trace data), `*_test.go`. |
| `pkg/container/modules/plugins.go` | Modified | Add `prompttemplate.New` to the `newPluginRegistry` catalog slice + `reg.Register`. |
| `pkg/app/plugins/catalog_metadata.go` | Modified | Hand-author `SettingsSchema` (nested objects/arrays/maps for engine, context vars, inject/named templates, behavior flags) + name/description. |
| `go.mod` | Modified | Add a mustache library dependency (no existing templating code). |
| `tests/functional/`, plugin unit tests, `catalog_test.go` | New/Modified | Mode A injection/merge/replace, Mode B render/validate, all five error codes, engine validation, catalog schema. |

## Risks & mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Body rewrite dropped in a parallel `pre_request` batch (`Result.RequestBody` only survives single-plugin batch, like `model_allowlist`). | Med | Document that this plugin must not be grouped in a parallel `pre_request` batch when it rewrites the body. |
| Unverified JWT claim trust confusion. | Med | Documented trust boundary: claims used only for substitution, never for auth; auth middleware already validated the request. |
| Mustache library choice / sandboxing for untrusted client variables (Mode B). | Med | Values are substituted as data, not executed; `escape_json_control_chars` and `max_length` validation bound the surface; mustache is logic-less by design. |
| Schema breadth (nested arrays/maps) in catalog UI metadata. | Low | Mirror the nesting approach used by the budget plugin's `SettingsSchema`. |

## Rollback plan

Additive and self-contained. The plugin is a new, separately-registered
catalog entry that is inert unless a policy enables it. Rollback = remove the
`prompttemplate` package, drop the `reg.Register` line and catalog metadata
entry, and remove the mustache dependency. No migrations, no changes to
existing plugin behavior.

## Delivery note

This is a **large** change and will exceed the 400-line reviewer budget. It
must ship as **chained PRs**. Rough phasing hint (to be forecast precisely by
`sdd-tasks`):

1. Skeleton + config schema + `ValidateConfig` (mustache-only, jinja2 reject) +
   registration + catalog metadata.
2. Mustache engine + context-variable resolution (header + unverified
   jwt_claim).
3. Mode A injection (`position`/`role`/`on_existing_system` merge/replace) +
   `on_missing_context_variable` handling.
4. Mode B reference detection, label/version resolution, `required_variables`
   validation, rendering + body substitution + all client-side error codes.
5. Functional tests + catalog tests.

## Success criteria

- [ ] Mode A injects/merges/replaces a system message from header + jwt_claim
      context variables.
- [ ] Mode B resolves `{template://name@label}` by label with `default_label`
      fallback and renders with validated client variables.
- [ ] All five runtime error codes map to the correct status + `PluginError.Type`.
- [ ] `jinja2_subset` is rejected at `ValidateConfig` with a clear message.
- [ ] Plugin appears in the catalog with a usable settings schema.
- [ ] Deferred items (`consumer_attribute`, jinja2 engine, partials, render
      endpoint, admin CRUD) are explicitly documented as out of scope.
