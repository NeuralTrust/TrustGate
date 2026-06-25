# Proposal: Bedrock Guardrail plugin (RUN-719)

## Why

LegacyGateway's `bedrock_guardrail` (`pkg/infra/plugins/bedrock_guardrail`, client
`pkg/infra/bedrock/client.go`) applies an AWS Bedrock Guardrail (`ApplyGuardrail`)
to inbound prompts. It is being re-implemented — not ported verbatim — onto the new
TrustGate plugin SDK to fix a set of correctness, safety, and coverage defects and to
bring it in line with the canonical guardrail sibling (`azure_content_safety`).

Legacy defects this rework fixes:

1. **Client built per request** with a `muPool.Delete(clientKey)` `defer`-ed while the
   per-key lock is held — racing the single-flight guarantee. → cache and reuse one
   `*bedrockruntime.Client` per credential set across requests.
2. **Raw request JSON body** sent as guardrail content. → extract real prompt/response
   text per provider via the adapter registry.
3. **`fmt.Sprintf(conf.Actions.Message, msg)`** on the operator message — a format-string
   injection bug. → fixed message + structured JSON error body.
4. **Wrong v2 SDK action constant** (`REJECT`). → use `BLOCKED`
   (`GuardrailContentPolicyActionBlocked`).
5. **Partial policy coverage** (topic/content only). → inspect ALL assessments:
   topic, content, word, sensitive-information (PII), contextual-grounding; add PII
   `ANONYMIZED` masking.
6. **Content logged at `Info`** (full prompt). → never log content.
7. **PreRequest only, enforce only.** → add observe mode (`appplugins.Blocks(in.Mode)`)
   and PreResponse support.
8. Default guardrail version `"1"`. → default `DRAFT`.

## What changes

- **New plugin package** `pkg/infra/plugins/bedrockguardrail/` mirroring the
  `azure_content_safety` file layout (`plugin.go`, `config.go`, `client.go`, `data.go`,
  `reject.go`, plus `*_test.go`). Applies the guardrail to request content (PreRequest,
  `Source=INPUT`) and optionally response content (PreResponse, `Source=OUTPUT`), enforcing
  topic, content, word, sensitive-information (PII), and contextual-grounding policies
  configured on the guardrail in AWS.
- **Registration**: import and append `bedrockguardrail.New(p.Adapters, p.Logger)` to the
  `catalog` slice in `pkg/container/modules/plugins.go:newPluginRegistry`.
- **Catalog metadata**: add a `bedrock_guardrail` entry under `groupGuardrails` in
  `pkg/app/plugins/catalog_metadata.go` with a `SettingsSchema` (object field for
  `credentials`, enums for `pii_action`/`version`, strings for `guardrail_id`/`message`).
- **Functional test**: `tests/functional/plugin_bedrock_guardrail_test.go` mirroring the
  azure functional test (fake `ApplyGuardrail` seam).
- **`go.mod`**: no change — `bedrockruntime` v1.53.1, `config`, `sts` already present.

## Fixed design decisions (do not reopen)

1. **Stages**: declare `SupportedStages = {StagePreRequest, StagePreResponse}` and
   `MandatoryStages = {}` (empty). Stage selection is policy-level via the executor's
   `EffectiveStages` (`pkg/app/plugins/stages.go`). The issue's `stages` config array is
   **redundant and dropped** from the plugin Settings.
2. **PII anonymize body rewrite**: when `pii_action=anonymize` and Bedrock returns
   anonymized output, decode the provider body → replace the extracted text span (the
   last user turn for PreRequest; the response `Content` for PreResponse) with Bedrock's
   masked `Outputs[].Text` → re-encode via the adapter `EncodeRequest`/`EncodeResponse` →
   return through `Result.RequestBody` (PreRequest) or `Result.Body` + `StopUpstream:true`
   (PreResponse). Declare `MutatesRequestBody()` / `MutatesResponseBody()` true. If
   re-encode is unsupported/fails: enforce mode → block (fail closed); observe mode →
   record degraded + pass through (mirror `tool_call_validation`'s degraded pattern).
3. **`pii_action` (`block` | `anonymize`)** is a TrustGate-side reaction selector, NOT an
   AWS override: `block` → 403 when the sensitive-information policy fires; `anonymize` →
   use the masked output to rewrite + continue, falling back to block if Bedrock returned
   a `BLOCKED` (not anonymized) PII action.
4. **Config shape**: flat `message` field (NOT `action.message`), aligned with
   `azure_content_safety`. `credentials` stays a nested object (`aws_region`, `use_role`,
   `role_arn`, `session_name`, plus optional static `access_key_id`/`secret_access_key`/
   `session_token`). `pii_action` enum, `version` string (default `DRAFT`), `guardrail_id`
   string (required).
5. **Streaming**: pass through on `in.Response.Streaming` at PreResponse (mirror
   `tool_call_validation`). PreRequest still guards.
6. **Client caching**: a per-credential-set client cache (fingerprinted `sync.Map`,
   single-flight build, reused across requests) held inside the plugin package, behind a
   small mockable interface seam over `ApplyGuardrail` so unit tests inject a fake. Keep
   both auth paths: role assumption (`use_role` + `role_arn` via STS `AssumeRole`) and
   static-key auth. Default region fallback `us-east-1`.
7. **Registration + catalog metadata** as described under "What changes".
8. **AWS SDK** already in `go.mod` — no new deps.

## Behavior

- Extract real prompt/response text per provider (adapter registry), call `ApplyGuardrail`
  with guardrail id + version and the correct `Source` per stage; inspect ALL assessments;
  on a blocking action → 403; on anonymize PII → rewrite the body with masked output;
  record guardrail id/version, region, matched policy/type/action, latency, and decision
  on the event via `event.SetExtras(data)` + `appplugins.SetDecision(in.Event, in.Mode)`.
- **403 response shape** (returned verbatim via `PluginError.Body`):

```json
{ "error": { "type": "guardrail_blocked", "policy": "topic_policy", "name": "..." } }
```

## Scope / non-goals

- In scope: PreRequest + PreResponse (non-streamed), enforce + observe modes, all five
  guardrail policy families, PII `block` and `anonymize`, client caching, event recording.
- Non-goals: **streamed PreResponse** guarding (passed through, mirroring
  `tool_call_validation`); a shared `pkg/infra/bedrock` package or DI-injected client (the
  cache lives inside the plugin — no second consumer today); bounded cache eviction
  (unbounded `sync.Map` as in legacy); a central secret store seam (credentials live in
  policy Settings, same as azure `api_key`); `scope` (consumer/global) needs no extra
  state — the guardrail is stateless and scope is handled at policy level.

## Affected files

- `pkg/infra/plugins/bedrockguardrail/` (new): `plugin.go`, `config.go`, `client.go`,
  `data.go`, `reject.go`, `*_test.go`.
- `pkg/container/modules/plugins.go` — register the plugin.
- `pkg/app/plugins/catalog_metadata.go` — add `bedrock_guardrail` under `groupGuardrails`.
- `tests/functional/plugin_bedrock_guardrail_test.go` (new).
- `go.mod` — unchanged.

## Recommended approach

Approach 1 from the exploration: **mirror the `azure_content_safety` package structure 1:1
and port the legacy bedrock client wrapper into the plugin package with the per-credential
cache behind a small interface seam** (`guardrailClient.ApplyGuardrail`). Use the adapter
registry for text extraction and, for PII `anonymize`, re-encode the masked output back into
the provider body. Guard clauses mirror the siblings (pass through on nil request, nil
registry, empty provider, empty body, unresolved format, decode error/nil, or empty
extracted text). Follow `.agents/AGENT.md`: hexagonal layout, one-thing-per-file, and the
hard no-comments policy (no Go doc comments); apply `golang-pro` idioms (error wrapping,
context propagation, no data races, mockable seam).

## Risks / open questions

- **PII anonymize re-encoding is lossy** for multi-message canonical requests: mapping a
  single masked blob back requires the defined rule above (replace the last user turn /
  response content only). Confirm during design that the per-adapter encoders round-trip
  cleanly.
- **PreResponse body mutation only via `StopUpstream:true` + `Body`** (no non-stop
  response-body apply path) — acceptable, as `tool_call_validation` relies on it.
- **Double `ApplyGuardrail` cost/latency** when both stages are enabled (one INPUT + one
  OUTPUT call per request).
- **Verify the v2 SDK output `Source` constant** name for response content
  (`GuardrailContentSource` OUTPUT variant) during implementation.
