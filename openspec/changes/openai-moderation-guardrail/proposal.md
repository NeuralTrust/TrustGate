# Proposal: OpenAI moderation guardrail plugin — RUN-717

## Why

TrustGate needs a content-safety guardrail that flags and blocks unsafe inbound
prompts and outbound model responses. The legacy gateway shipped a
`toxicity_openai` plugin backed by the OpenAI Moderations API, but it predates
the new TrustGate plugin SDK and carries several defects. RUN-717 re-implements
it from scratch as a first-class TrustGate plugin and fixes the legacy bugs.

Legacy implementation: `LegacyGateway/pkg/infra/plugins/toxicity_openai`
(`toxicity_openai.go`, 296 lines, + `data.go`). Defects it carries
(exploration.md §9):

1. **No HTTP timeout** — falls back to a bare `&http.Client{}`
   (`toxicity_openai.go:92-94`), so a hung OpenAI socket hangs the request.
2. **Dead `categories` field** — decoded but never used; only `thresholds`
   drove blocking.
3. **`action.type` validated but never used** — `ValidateConfig` requires
   `action.type` (`:127-129`) while `Execute` only reads `action.message`.
4. **Raw OpenAI error leakage** — non-200 responses are returned verbatim as
   `fmt.Errorf("OpenAI API returned error: %s", body)` (`:185-187`), surfacing
   the upstream provider body to the caller.
5. **No observe mode and no `pre_response` leg** — request-only, enforce-only.
6. **Single-result aggregation** — uses `Results[0]` only (`:234`), ignoring
   additional moderation results when multiple inputs are sent.

- Linear: **RUN-717** "Plugin: OpenAI moderation guardrail".

## What changes

A net-new infra plugin `openai_moderation` in
`pkg/infra/plugins/openaimoderation/`, modeled file-for-file on the existing
`trustguard` plugin (the closest analog: an external-HTTP read-only guardrail
that runs both `pre_request` and `pre_response` and supports enforce/observe —
exploration.md §2.1). It is read-only (`Mutates* = false`), returns a
pass-through `*plugins.Result{StatusCode: 200}` on allow, and returns a
`*appplugins.PluginError` (403 `content_flagged`) on block.

### The plugin

- **Slug** `openai_moderation`, **package** `openaimoderation` (snake_case slug,
  underscore-dropped package name, consistent with `trustguard` / `modelallowlist`
  / `prompttemplate`).
- `Name() = "openai_moderation"`; `SupportedStages = {pre_request, pre_response}`;
  `MandatoryStages = {}` (empty, so policy stages opt in);
  `SupportedModes = {enforce, observe}` (every plugin must support enforce —
  exploration.md §1.5).
- `Execute` flow (mirrors `trustguard/plugin.go:95-204`): parse config → gate on
  the requested stage via a `selectsStage` method (driven by the `stages`
  settings field, like trustguard's `Inspect`) → nil/empty-body guards →
  resolve provider format → decode body to canonical → extract text → call the
  moderations client → evaluate block rule → either return the 403
  `PluginError` (when blocking) or record extras + decision and return
  pass-through.

### Stage selection

Per decision: a `stages` settings field (array of `"pre_request"` /
`"pre_response"`, default both) gated through a `selectsStage(stage)` method,
exactly like trustguard's `inspect` (`trustguard/config.go:82-93`).
`SupportedStages` is the full `{pre_request, pre_response}` set;
`MandatoryStages` is empty. This matches the Linear config sample verbatim while
staying inside the SDK's `EffectiveStages` mechanism.

### Content extraction (TEXT-ONLY v1)

Text is extracted via the canonical adapter registry injected as
`p.Adapters *adapter.Registry` (exploration.md §4.1):
`ResolveAgentFormat(provider, sourceFormat, nil)` then
`DecodeRequestFor` / `DecodeResponseFor`. Request text = `System` + each
`Messages[].Content`; response text = `CanonicalResponse.Content` (same as
`trustguard/plugin.go:224-235`). The moderations `input` is built from the
extracted text only.

### Moderations client (fixes the no-timeout defect)

A `client.go` that POSTs to `{base_url}/v1/moderations` with body
`{"model": <model>, "input": [{"type":"text","text": "..."}]}` and parses the
Moderations response (`results[].flagged`, `results[].categories`,
`results[].category_scores` — exploration.md §9). It uses the pooled tuned
transport `providers.NewHTTPClientPool().Get("openai_moderation", timeout)`
(exploration.md §3) plus a per-call `context.WithTimeout` and
`http.NewRequestWithContext` — improving on trustguard's bare
`&http.Client{Timeout: ...}`. `io.LimitReader` bounds the response body and
`providers.DrainBody` cleans up error paths.

### Catalog metadata & registration

- Catalog metadata entry keyed by the slug in
  `pkg/app/plugins/catalog_metadata.go`, group `Guardrails` (already exists in
  `groupOrder`, no new group — exploration.md §5). Modeled on trustguard's
  entry (`catalog_metadata.go:1121-1157`).
- Registered once in `newPluginRegistry`
  (`pkg/container/modules/plugins.go:91-105`), appended to the `catalog` slice:
  `openaimoderation.New(p.Adapters, p.Cfg.OpenAIModeration, p.Logger)`.

### Config / env vars

`api_key` stays in policy settings (like trustguard / tool_call_validation).
Base URL + timeout come from env via a new `OpenAIModerationConfig{BaseURL, Timeout}`
in `pkg/config/config.go`, mirroring `TrustGuardConfig` (`config.go:244-247`,
`getTrustGuardConfig` `:485-490`, `defaultTrustGuardTimeout` `:98`):

| Env var | Default | Purpose |
|---|---|---|
| `OPENAI_MODERATION_BASE_URL` | `https://api.openai.com` | Moderations API base URL |
| `OPENAI_MODERATION_TIMEOUT` | `15s` | per-call HTTP timeout |

Model default `omni-moderation-latest` (a config field, not env). Documented in
`.env.example`.

## Config schema (v1)

```json
{
  "api_key": "sk-...",
  "model": "omni-moderation-latest",
  "stages": ["pre_request", "pre_response"],
  "categories": ["hate", "violence", "sexual"],
  "thresholds": { "hate": 0.7, "violence": 0.8 },
  "block_on_flagged": false,
  "action": { "message": "Content blocked by moderation policy." }
}
```

- `api_key` — string, **required** (mapstructure tag carries
  `// #nosec G101 -- config field name, not a credential`, as trustguard does).
- `model` — string, default `omni-moderation-latest`.
- `stages` — array of `pre_request` / `pre_response`, default both.
- `categories` — **allow-list**: when non-empty, only these categories are
  evaluated; when empty, all categories that have a configured threshold are
  evaluated (resolves legacy defect #2 — the dead field).
- `thresholds` — map<category → number (0..1)>. No built-in default threshold;
  an unconfigured category blocks only when `block_on_flagged=true` and OpenAI
  flagged it.
- `block_on_flagged` — boolean, default `false`. When true, a category OpenAI
  marked `flagged` within the evaluation set blocks even without a configured
  threshold.
- `action.message` — string, the block message. `action.type` is **dropped**
  (resolves legacy defect #3).

## Block / decision algorithm

Aggregate scores **max-per-category across ALL `results[]`** (resolves legacy
defect #6 — not just `results[0]`).

1. **Evaluation set** = `categories` allow-list if non-empty; otherwise the set
   of categories present in the moderation response.
2. **Violations**:
   - Any category in the evaluation set that has a configured threshold whose
     aggregated max score `>= threshold`; **plus**
   - if `block_on_flagged` is true, any category in the evaluation set that
     OpenAI marked `flagged`.
3. **Block iff** `len(violations) > 0 && appplugins.Blocks(in.Mode)` —
   `Blocks(mode) == mode != observe` (exploration.md §1.5). So observe mode
   never blocks; it records the decision and passes through.

On block, return `nil, blockError(...)` (a `*appplugins.PluginError`,
`StatusCode: 403`, `Type: "content_flagged"`) whose `Body` is set verbatim to:

```json
{
  "error": {
    "type": "content_flagged",
    "categories": [
      { "category": "hate", "score": 0.91, "threshold": 0.7 }
    ]
  }
}
```

`pluginErrorResult` (`plugin_runner.go:200-217`) uses `pe.Body` verbatim when
set, so this shape reaches the client unchanged (exploration.md §7).

## Fail-CLOSED behavior

On an OpenAI API/transport error or a non-2xx response:

- **Enforce** → return a generic **502** `*PluginError`
  (`Type: "moderation_unavailable"`, generic message, **no raw OpenAI body**);
  log the underlying detail via `slog`. This is fail-**closed** and is a
  deliberate divergence from trustguard, which fails *open* on transport errors
  — moderation is a safety control, so an unavailable moderator must not let
  unmoderated traffic through.
- **Observe** → never blocks: pass through and record the failure in event
  extras.
- **`pre_response` streaming** → skipped (we cannot inspect a streaming body in
  realtime), mirroring trustguard's `in.Response.Streaming` guard
  (`trustguard/plugin.go:142`).

This fixes legacy defect #4 (raw error leakage): the upstream body is logged,
never returned to the caller.

## DEVIATION from RUN-717: text-only v1, image moderation deferred

RUN-717 behavior #1 mentions `image_url` moderation. **v1 is TEXT-ONLY.** The
canonical adapter model exposes `CanonicalMessage.Content` as a flat string and
the OpenAI adapter's `contentToString` silently drops `image_url` parts
(exploration.md §4.2, `openai_adapter.go:158-182`). Moderating images would
require a new per-provider raw-JSON image extractor (OpenAI
`messages[].content[].image_url.url`, Anthropic `content[].source`, Bedrock
content blocks all differ), which would blow the 400-line PR budget. Images are
therefore an explicit **fast-follow** (see Non-goals). v1 reuses the canonical
text path only.

## Scope

### In scope (v1)
- New `openai_moderation` plugin (text-only) on `pre_request` + `pre_response`,
  enforce + observe.
- Pooled HTTP client + context deadline; fail-closed 502 mapping; generic error
  bodies.
- `categories` allow-list + `thresholds` + `block_on_flagged` block rule with
  max-per-category aggregation across all results.
- 403 `content_flagged` response body with violating categories/scores/thresholds.
- Event extras + decision recording (nil-checked).
- `OpenAIModerationConfig` env wiring + `.env.example`; catalog metadata;
  registration.

### Out of scope / Non-goals (v1)
- **Image/`image_url` moderation** — deferred fast-follow (per-provider raw
  image extraction).
- **Secret-reference credential manager** — `api_key` stays plaintext in policy
  settings, consistent with trustguard / tool_call_validation; aligning with a
  future credential manager is out of scope.
- **`post_request` / `post_response` legs** — not part of this guardrail.
- **Built-in default thresholds** — purely operator-configured.

## Event recording / metrics

`in.Event` is **nil-checked** (nil when traces disabled — exploration.md §8).
On the non-block path, record `appplugins.SetDecision(in.Event, in.Mode)` and
`Event.SetExtras(data)` with: `model`, per-category `category_scores`,
`max_score`, `max_score_category`, `flagged_categories
[{category,score,threshold}]`, `flagged_by_openai`, `decision`. Latency/status/
mode are already recorded by the executor around `Execute`
(`executor.go:142-168`), so they are not duplicated here.

## Impact / affected files

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/plugins/openaimoderation/plugin.go` | New | `Plugin`, `New`, interface methods, `Execute` orchestration (~230 LOC, mirrors trustguard 239). |
| `pkg/infra/plugins/openaimoderation/config.go` | New | `Settings` (mapstructure), `parseConfig`, `applyDefaults`, `validate`, `selectsStage` (~110 LOC). |
| `pkg/infra/plugins/openaimoderation/client.go` | New | Pooled moderations HTTP client + ctx deadline (~90 LOC). |
| `pkg/infra/plugins/openaimoderation/data.go` | New | Moderations req/resp JSON + event extras + `setExtras` (~90 LOC). |
| `pkg/infra/plugins/openaimoderation/extract.go` | New | Canonical text extraction (request + response legs) (~60 LOC). |
| `pkg/infra/plugins/openaimoderation/reject.go` | New | `blockError` → 403 `content_flagged` `*PluginError` (~60 LOC). |
| `pkg/infra/plugins/openaimoderation/*_test.go` | New | plugin/config/client/extract tests (table-driven, `-race`). |
| `pkg/app/plugins/catalog_metadata.go` | Modified | New `SettingsSchema` entry, group `Guardrails`. |
| `pkg/container/modules/plugins.go` | Modified | Register `openaimoderation.New(...)` in `newPluginRegistry` + module test. |
| `pkg/config/config.go` | Modified | `OpenAIModerationConfig{BaseURL,Timeout}` + getter + default const + field on `Config`. |
| `.env.example` | Modified | Document `OPENAI_MODERATION_BASE_URL` / `OPENAI_MODERATION_TIMEOUT`. |

**LOC estimate:** non-test plugin code ≈ 640 LOC (trustguard non-test is ~545
across the same five files; this adds `extract.go` and a slightly larger block
rule), plus tests (~600 LOC) and ~60 LOC of wiring (config + registration +
catalog + env). This **exceeds the 400-line reviewer budget and must ship as
chained PRs** (precise phasing forecast by `sdd-tasks`). Rough phasing hint:

1. Config + env wiring (`OpenAIModerationConfig`, `.env.example`) + plugin
   skeleton (`Settings`, `parseConfig`/`validate`/`selectsStage`, interface
   methods, registration, catalog metadata) — registers but always passes
   through.
2. Moderations client (`client.go`) + JSON shapes (`data.go`) + canonical text
   extraction (`extract.go`) + client/extract tests.
3. Block rule + `reject.go` 403 body + fail-closed 502 mapping + observe +
   `pre_response` + event extras/decision + plugin tests.

## Risks & mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Fail-closed 502 on an OpenAI outage blocks live traffic. | Med | Documented, deliberate (safety control); observe mode and not-enabling the plugin are escape hatches; tuned pooled transport + bounded timeout reduce hang risk. |
| `api_key` stored plaintext in policy settings. | Med | Consistent with existing plugins; `// #nosec G101` annotation; credential-manager alignment is a separate follow-up. |
| Text-only v1 silently lets image payloads through unmoderated. | Med | Explicit DEVIATION + deferred image fast-follow documented; operators are informed v1 is text-only. |
| Multi-result aggregation correctness. | Low | Max-per-category across all `results[]`, covered by table-driven tests. |
| Change exceeds 400-line PR budget. | High | Ship as chained PRs per the phasing hint above. |

## Rollback plan

Additive and self-contained. The plugin is a new, separately-registered catalog
entry that is inert unless a policy enables it. Rollback = remove the
`openaimoderation` package, drop the `reg.Register` line and the
`catalog_metadata.go` entry, and remove `OpenAIModerationConfig` + its getter
and the `.env.example` lines. No migrations; no changes to existing plugin
behavior.

## Success criteria

- [ ] Plugin registers and appears in the catalog under `Guardrails` with a
      usable settings schema.
- [ ] Runs on `pre_request` and `pre_response` per the `stages` field; supports
      enforce + observe.
- [ ] Blocks with 403 `content_flagged` (spec'd body) when a category in the
      evaluation set crosses its threshold, or (with `block_on_flagged`) is
      flagged by OpenAI; observe never blocks.
- [ ] Scores aggregated max-per-category across all `results[]`.
- [ ] OpenAI failure/non-2xx in enforce → generic 502 `moderation_unavailable`,
      no raw OpenAI body; detail logged via slog; streaming `pre_response`
      skipped.
- [ ] All five legacy defects fixed (timeout, dead `categories`, dead
      `action.type`, error leakage, missing observe/`pre_response`).
- [ ] No code comments (incl. Go doc comments) except the Apache license header;
      hexagonal layout; one-responsibility-per-file; `-race`-clean tests.
- [ ] Text-only DEVIATION and deferred image moderation documented as out of
      scope.
