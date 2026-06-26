# Proposal: TrustGuard connector plugin — RUN-669

## Why

TrustGate can route, rate-limit, and reshape LLM traffic, but it has no
first-class way to consult NeuralTrust's external **TrustGuard** guardrail
service and **block** unsafe traffic in real time. Operators want a policy they
can attach to a gateway/consumer that forwards the request (and/or the response)
content to TrustGuard's `POST /v1/guard` endpoint and, when TrustGuard returns a
`block` verdict, short-circuits the request before it reaches the upstream model
or replaces the model's response with a 403.

This change adds that connector as a new guardrail plugin in the existing plugin
framework, modeled on the established external-guardrail pattern
(`tool_call_validation`, which calls an external LLM and blocks via a
`*PluginError`) and the raw external-HTTP-client pattern
(`pkg/infra/oauth/provider_client.go`).

- Linear: **RUN-669** — *Implement the TrustGuard connector in TrustGate*. Goal:
  add a guardrail plugin that calls `POST /v1/guard` and can BLOCK
  requests/responses based on TrustGuard's verdict.

## What changes

- **New plugin package** `pkg/infra/plugins/trustguard/`, slug / `PluginName`
  **`trustguard`**. Files (one use-case/DTO per file, Apache header on each):
  `plugin.go` (lifecycle + `Execute` orchestration), `config.go` (typed Settings
  + `ValidateConfig`/defaults), `client.go` (raw `net/http` TrustGuard client),
  `data.go` (request/response DTOs for `/v1/guard` + event-extras trace), plus
  table-driven `*_test.go` files.
- **Stages**: `MandatoryStages = {pre_request, pre_response}` and
  `SupportedStages = {pre_request, pre_response}`. Both stages are declared
  mandatory so a single per-policy `inspect` field can reliably gate behaviour
  inside `Execute` (the executor only invokes a plugin at its effective stages =
  Mandatory ∪ selected∩Supported; declaring both mandatory guarantees `Execute`
  is called on each leg and lets us gate internally rather than relying on stage
  selection).
- **Modes**: `SupportedModes = {enforce, observe}`. `enforce` blocks on a
  `block` verdict; `observe` is report-only (records the verdict, always
  passThrough).
- **Capability flags**: `MutatesRequestBody=false`, `MutatesResponseBody=false`,
  `MutatesMetadata=false`. v1 only blocks or reports; it does **not** apply
  TrustGuard's `transformed_payload`.
- **Body→text extraction** via the provider `adapter.Registry`
  (`ResolveAgentFormat` + `DecodeRequestFor` / `DecodeResponseFor`), mirroring
  `pkg/infra/plugins/tool_call_validation/plugin.go`. The decoded
  messages/content build the TrustGuard `input.input` string.
- **TrustGuard HTTP client**: a small raw-`net/http` client built in `New(...)`
  (`*http.Client{Timeout}`), `POST {base_url}/v1/guard`, headers
  `Authorization: Bearer <api_key>` and `Content-Type: application/json`,
  per-call `context.WithTimeout`, `io.LimitReader` on the response body, JSON
  decode — modeled on `oauth/provider_client.go`.
- **Config**: base URL + timeout come from env via `pkg/config`, injected through
  DI into the plugin's `New(...)`. New env vars **`TRUSTGUARD_BASE_URL`** (no
  default; empty ⇒ plugin disabled / passThrough + log) and
  **`TRUSTGUARD_TIMEOUT`** (default `15s`). An optional per-policy `base_url`
  Setting may override the env base URL.
- **Registration**: add `trustguard.New(...)` to the catalog slice in
  `newPluginRegistry` (`pkg/container/modules/plugins.go`) with its DI params,
  and a catalog metadata entry in `pkg/app/plugins/catalog_metadata.go`.
- **Observability**: emit event-extras (`event.SetExtras`) recording the
  resolved direction, the TrustGuard `status`/`trace_id`/`request_id`, findings
  count, and the decision (blocked / allowed / reported / failed-open).

## Scope

### In scope

- A configurable `trustguard` plugin that calls `POST {base_url}/v1/guard` on the
  request leg and/or the response leg, gated by the `inspect` Setting.
- Blocking in `enforce` mode when TrustGuard returns `status == "block"`:
  - **pre_request** → `*appplugins.PluginError` (HTTP 403) short-circuits before
    upstream;
  - **pre_response** (non-streaming) → `*appplugins.PluginError` (HTTP 403)
    replaces the client response.
- `observe` mode: never blocks; records the verdict and passes through.
- Fail-open on any TrustGuard transport error, timeout, or non-2xx status.
- Provider-agnostic content extraction via the adapter `Registry`.
- Streaming responses passed through untouched (cannot be inspected/blocked in
  realtime — see Streaming limitation).
- Env-driven base URL + timeout (`pkg/config`), with optional per-policy
  `base_url` override.
- Table-driven config + `Execute` tests against a fake TrustGuard
  (`httptest.NewServer`).

### Out of scope (non-goals)

- **Applying `transformed_payload`** — v1 does not rewrite request/response
  bodies from TrustGuard's `transform` verdict (`MutatesRequestBody=false`,
  `MutatesResponseBody=false`). `transform` and `report` are treated as allow.
- **Realtime blocking of streamed responses** — a streamed body is not buffered
  on the response leg, so it cannot be inspected/blocked in realtime.
- **`post_response` report-only** — inspecting the full streamed body after the
  fact is explicitly out of scope for v1.
- **`fail_closed` toggle** — v1 always fails open; a configurable fail-closed
  mode is future work.
- **Attachments / consumer tag/type / collector** — not populated on the proxy
  request context today; omitted from the TrustGuard request (future work).

## Plugin config schema (per-policy Settings)

```json
{
  "api_key": "tg_live_...",
  "inspect": "request_response",
  "base_url": "https://trustguard.internal/"
}
```

- `api_key` — **string, required**. Bearer token for TrustGuard
  (`Authorization: Bearer <api_key>`).
- `inspect` — **enum `request | response | request_response`, default
  `request_response`**. Selects which legs are inspected (see matrix).
- `base_url` — **string, optional**. Overrides `TRUSTGUARD_BASE_URL` for this
  policy. When neither is set, the plugin passes through and logs a warning.

`ValidateConfig` parses via `pluginutil.Parse[Settings]`, enforces required
fields, validates the `inspect` enum, applies the `request_response` default,
and (if present) validates `base_url`.

## Stage-and-direction matrix

| `inspect` value | `pre_request` (Execute) | `pre_response` (Execute) |
|---|---|---|
| `request` | call TrustGuard, `direction="input"` | passThrough |
| `response` | passThrough | call TrustGuard, `direction="output"` |
| `request_response` | call TrustGuard, `direction="input"` | call TrustGuard, `direction="output"` |

When the current `in.Stage` is not selected by `inspect`, `Execute` returns
passThrough immediately. `direction` is derived from `in.Stage`
(`pre_request → "input"`, `pre_response → "output"`).

## Blocking & fail-open semantics

**Blocking (enforce mode, `status == "block"`):**

- **pre_request**: return `*appplugins.PluginError{StatusCode: 403, ...}` whose
  `Body` conveys the guard verdict/findings. `runPreRequest` short-circuits
  before upstream is contacted.
- **pre_response** (non-streaming): return `*appplugins.PluginError{StatusCode:
  403, ...}`. `finalizeBody*` replaces the whole client response with the error;
  on a successful upstream response this rejection can also drive failover via
  the proxy's `pluginRejection` trigger.

**Observe mode**: never returns a `PluginError`. The verdict is recorded via
event-extras and the plugin passes through regardless of `status`.

**Allow verdicts**: `status` of `transform`, `report`, or empty (`""`) are
treated as allow in v1 — passThrough (with optional report-only logging).

**Fail-open (v1)**: on any TrustGuard transport error, context timeout, or
non-2xx HTTP status, the plugin logs a warning and passes through (never
blocks). Likewise, an empty/unset base URL passes through with a warning. A
`fail_closed` toggle is future work.

## Streaming limitation

In `pre_response`, when `in.Response.Streaming == true`, the plugin passes
through without calling TrustGuard. The proxy does not buffer streamed bodies on
the response leg (`mergeProviderResponse` leaves `Response.Body` unset for
streams; the full body is only available asynchronously in `post_response` after
bytes have already been sent to the client). Therefore a streamed response
**cannot be inspected or blocked in realtime**. Operators who require response
guarding on streamed traffic must either disable streaming for guarded routes or
await the future `post_response` report-only capability (out of scope here).
Request-leg (`pre_request`) inspection is unaffected by streaming.

## TrustGuard request/response contract

**Request body** (`POST {base_url}/v1/guard`):

```json
{
  "direction": "input",
  "protocol": "llm",
  "session_id": "<in.Request.SessionID>",
  "consumer_id": "<in.Request.ConsumerID>",
  "input": { "input": "<decoded request/response text>" },
  "attributes": {
    "content_type": "application/json",
    "model": {
      "name": "<in.Request.RequestedModel>",
      "provider": "<in.Request.Provider>"
    }
  }
}
```

- `direction` — from stage (`input` for pre_request, `output` for pre_response).
- `protocol` — derived from the resolved consumer `Type` (`LLM → "llm"`,
  `MCP → "mcp"`, `A2A → "a2a"`; defaults to `"llm"`).
- `session_id` — `in.Request.SessionID`.
- `consumer_id` — the real TrustGate consumer id (`in.Request.ConsumerID`).
- `input.input` — text decoded via the adapter `Registry`
  (`DecodeRequestFor` messages/system content on input; `DecodeResponseFor`
  content on output).
- `attributes.model.{name,provider}` — `in.Request.RequestedModel` /
  `in.Request.Provider`.
- **Omitted (future work)**: `attachments`, `attributes.consumer.{tag,type}`,
  `collector.type` — not available on the proxy request context today.

**Response body** (`/v1/guard`):

```json
{
  "status": "block",
  "transformed_payload": null,
  "findings": [],
  "trace_id": "...",
  "request_id": "..."
}
```

- `status` — `"block" | "transform" | "report" | ""`. v1 acts only on `"block"`.
- `transformed_payload` — ignored in v1.
- `findings[]` — surfaced in the block error body and event-extras.
- `trace_id`, `request_id` — recorded in event-extras for correlation.

## Files to add or change

| Area | Impact | Description |
|---|---|---|
| `pkg/infra/plugins/trustguard/plugin.go` | New | Plugin type, `New(...)` (builds `*http.Client`), `Name`/stages/modes/capabilities, `ValidateConfig`, `Execute` (stage×inspect gating, decode, call client, block/observe/fail-open). |
| `pkg/infra/plugins/trustguard/config.go` | New | Typed `Settings` (mapstructure tags), `parseConfig` (Parse → validate → defaults). |
| `pkg/infra/plugins/trustguard/client.go` | New | Raw `net/http` TrustGuard client (`POST /v1/guard`, Bearer auth, per-call timeout, `io.LimitReader`, JSON decode). |
| `pkg/infra/plugins/trustguard/data.go` | New | `/v1/guard` request/response DTOs + event-extras struct. |
| `pkg/infra/plugins/trustguard/*_test.go` | New | Table-driven config tests + `Execute` tests against `httptest.NewServer`. |
| `pkg/container/modules/plugins.go` | Modified | Import `trustguard` and add `trustguard.New(...)` to the `newPluginRegistry` catalog slice with DI params (config, adapters, logger). |
| `pkg/app/plugins/catalog_metadata.go` (+ `catalog_test.go`) | Modified | Catalog metadata entry (name, group, hand-authored `SettingsSchema`: `api_key`, `inspect` enum, optional `base_url`). |
| `pkg/config/*` | Modified | Add `TRUSTGUARD_BASE_URL` (no default) and `TRUSTGUARD_TIMEOUT` (default `15s`) env-only config, wired into DI. |
| Plugin docs | New/Modified | Document slug, config, stages, blocking/fail-open, streaming limitation (RUN-669 "connector documented"). |

## Risks & open / future work

| Risk / item | Notes |
|---|---|
| **Fail-open masks outages** | A TrustGuard outage silently allows traffic in v1. Mitigation: warning logs + event-extras `failed_open` flag for alerting. Future: `fail_closed` toggle. |
| **Streaming responses unguarded** | Realtime response blocking impossible for streams (documented). Future: `post_response` report-only or disable-streaming-when-guarded guidance. |
| **`transformed_payload` not applied** | v1 blocks/reports only; `transform` treated as allow. Future: apply transformed payload (would flip `MutatesRequestBody`/`MutatesResponseBody`). |
| **Missing attributes** | `attachments`, consumer `tag`/`type`, `collector.type` omitted (not on the proxy request context). Future: enrich via consumer lookup / attachment extraction. |
| **Empty session splits legs** | When `Request.SessionID` is empty (e.g. gateway session config disabled), TrustGuard mints a fresh session per `/v1/guard` call, so the request and response legs are not correlated in TrustGuard. The proxy data plane exposes no stable per-transaction id (the request-id middleware is admin-only). Blocking is unaffected (it decides per leg). Future: stamp a stable per-transaction session id in the proxy request context. |
| **Added latency** | Each guarded leg adds a synchronous TrustGuard round-trip. Mitigation: bounded per-call timeout (`TRUSTGUARD_TIMEOUT`); operators scope the policy. |
| **`consumer_id` semantics** | The `consumer_id` sent to TrustGuard is the real TrustGate consumer id (`Request.ConsumerID`), stamped in `stampConsumerScope`; it is not a plugin setting. |
| **Empty base URL** | No env default; an unconfigured base URL passes through with a warning rather than failing requests. |

## Acceptance criteria (mapped to RUN-669)

- [ ] **TrustGate configurable with a TrustGuard connector** — new `trustguard`
      plugin registered in `newPluginRegistry` + catalog metadata; per-policy
      Settings `api_key`, `inspect`, optional `base_url`; env
      `TRUSTGUARD_BASE_URL` / `TRUSTGUARD_TIMEOUT` via `pkg/config`.
- [ ] **Requests forwarded correctly** — `Execute` builds the `/v1/guard` body
      (direction, protocol, session_id, consumer_id, decoded `input`, model
      attributes) and POSTs with Bearer auth, per stage × `inspect`.
- [ ] **Responses handled** — `status=="block"` in `enforce` returns a 403
      `*PluginError` (short-circuit on pre_request, response-replace on
      pre_response); `observe` records but passes through; non-2xx/timeout/error
      fail open; streaming passes through.
- [ ] **Tests pass** — `go test -race` green: table-driven config tests and
      `Execute` tests (block, allow, streaming passthrough, observe, fail-open)
      against a fake TrustGuard `httptest.NewServer`.
- [ ] **Connector documented** — slug, config schema, stage/direction matrix,
      blocking/fail-open semantics, and streaming limitation documented.

## Rollback plan

Additive and self-contained. The plugin is a new package gated by an explicit
policy; removing the `newPluginRegistry` registration line, the catalog metadata
entry, the `pkg/config` env vars, and the package reverts the change with zero
impact on existing traffic or other plugins. No schema migrations, no
shared-state changes.
