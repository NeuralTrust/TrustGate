# Delta for TrustGuard (trustguard plugin)

This change adds a net-new guardrail plugin `trustguard` that consults the
external TrustGuard service (`POST {base_url}/v1/guard`) and can BLOCK traffic in
realtime. It declares `pre_request` and `pre_response` as mandatory+supported
stages, modes `enforce` and `observe`, and mutates nothing
(`MutatesRequestBody=MutatesResponseBody=MutatesMetadata=false`). Out of scope in
v1: applying `transformed_payload`, realtime blocking of streamed responses,
`post_response` report-only, a `fail_closed` toggle, and TrustGuard
`attachments` / `attributes.consumer.{tag,type}` / `collector.type`.

## ADDED Requirements

### Requirement: Configuration validation

`ValidateConfig` MUST reject invalid policy Settings. It MUST require a non-empty
`api_key` (string) and a non-empty `consumer_id` (string). It MUST accept
`inspect` only in `{request, response, request_response}`, defaulting to
`request_response` when omitted, and MUST reject any other value. `base_url` is
OPTIONAL; when present it MUST be validated as a URL and overrides the env base
URL for that policy.

#### Scenario: Required fields enforced
- GIVEN Settings missing `api_key` or with an empty `api_key`, or missing/empty `consumer_id`
- WHEN `ValidateConfig` runs
- THEN it MUST fail with a clear message naming the missing field

#### Scenario: Inspect enum and default
- GIVEN Settings with `inspect` omitted
- WHEN `ValidateConfig` runs
- THEN it MUST pass with `inspect` defaulted to `request_response`
- AND an `inspect` value outside the enum MUST be rejected

#### Scenario: Optional base_url validated
- GIVEN Settings with a malformed `base_url`
- WHEN `ValidateConfig` runs
- THEN it MUST fail; a well-formed `base_url` MUST pass and take precedence over the env base URL

### Requirement: Stage gating by inspect

The plugin MUST gate TrustGuard calls inside `Execute` by `inspect` × `in.Stage`.
`direction` MUST be derived from the stage: `pre_request → "input"`,
`pre_response → "output"`. When the current stage is not selected by `inspect`,
`Execute` MUST pass through immediately without calling TrustGuard.

#### Scenario: inspect=request
- GIVEN `inspect:"request"`
- WHEN `Execute` runs at `pre_request`
- THEN TrustGuard MUST be called with `direction:"input"`
- AND at `pre_response` the plugin MUST pass through without calling TrustGuard

#### Scenario: inspect=response
- GIVEN `inspect:"response"`
- WHEN `Execute` runs at `pre_response`
- THEN TrustGuard MUST be called with `direction:"output"`
- AND at `pre_request` the plugin MUST pass through without calling TrustGuard

#### Scenario: inspect=request_response
- GIVEN `inspect:"request_response"`
- WHEN `Execute` runs at each leg
- THEN TrustGuard MUST be called on `pre_request` (`input`) and on `pre_response` (`output`)

### Requirement: Enforce-mode blocking

In `enforce` mode, when TrustGuard returns `status == "block"`, the plugin MUST
block with HTTP 403 by returning a `*appplugins.PluginError{StatusCode:403}`
whose body conveys the guard verdict (status and findings). On `pre_request` the
block MUST short-circuit before the upstream model is contacted; on
`pre_response` (non-streaming) it MUST replace the client response. Any other
`status` (`transform`, `report`, or `""`) MUST be treated as allow (pass
through).

#### Scenario: Block on request leg
- GIVEN `enforce` mode and TrustGuard returns `status:"block"` at `pre_request`
- WHEN `Execute` runs
- THEN it MUST return a 403 PluginError before upstream is contacted, with findings in the body

#### Scenario: Block on response leg
- GIVEN `enforce` mode and a non-streaming response where TrustGuard returns `status:"block"` at `pre_response`
- WHEN `Execute` runs
- THEN it MUST return a 403 PluginError that replaces the client response

#### Scenario: Non-block verdicts allow
- GIVEN `enforce` mode and TrustGuard returns `transform`, `report`, or `""`
- WHEN `Execute` runs
- THEN the plugin MUST pass through without blocking

### Requirement: Observe-mode non-blocking

In `observe` mode the plugin MUST NOT return a `PluginError` and MUST NOT block,
even when TrustGuard returns `status == "block"`. It MUST record the verdict and
findings (e.g. via event-extras) and pass through.

#### Scenario: Observe records but never blocks
- GIVEN `observe` mode and TrustGuard returns `status:"block"`
- WHEN `Execute` runs
- THEN the request/response MUST pass through unblocked AND the decision/findings MUST be recorded

### Requirement: Streaming responses pass through

On `pre_response`, when `in.Response.Streaming == true`, the plugin MUST pass
through WITHOUT calling TrustGuard (a streamed body cannot be inspected or
blocked in realtime). This is a documented v1 limitation; `pre_request`
inspection MUST be unaffected by streaming.

#### Scenario: Streamed response not inspected
- GIVEN a `pre_response` leg with `Response.Streaming == true` (any mode)
- WHEN `Execute` runs
- THEN TrustGuard MUST NOT be called and the response MUST pass through

### Requirement: Fail-open behavior

The plugin MUST fail open: on any TrustGuard transport error, context timeout, or
non-2xx HTTP status, it MUST log a warning and pass through (never block),
regardless of mode. When the effective base URL is empty/unconfigured (no
per-policy `base_url` and no `TRUSTGUARD_BASE_URL`), the plugin MUST pass through
with a warning and MUST NOT call TrustGuard.

#### Scenario: Transport/timeout/non-2xx allows
- GIVEN TrustGuard is unreachable, times out, or returns a non-2xx status
- WHEN `Execute` runs in either mode
- THEN the plugin MUST log a warning and pass through without blocking

#### Scenario: Unconfigured base URL allows
- GIVEN no per-policy `base_url` and an empty `TRUSTGUARD_BASE_URL`
- WHEN `Execute` runs
- THEN the plugin MUST pass through with a warning and MUST NOT issue a request

### Requirement: TrustGuard request mapping

When calling TrustGuard, the plugin MUST build the `/v1/guard` body with:
`direction` from the stage; `protocol` constant `"llm"`; `session_id` from
`in.Request.SessionID`; `consumer_id` from config (NOT the proxy
`Request.ConsumerID`); `attributes.content_type` `"application/json"`;
`attributes.model.name` from `in.Request.RequestedModel` and
`attributes.model.provider` from `in.Request.Provider`; and `input.input` set to
the request/response text decoded via the provider adapter Registry (request
messages/system on input; response content on output). Attachments and consumer
`tag`/`type`/`collector` MUST NOT be sent in v1 (future work).

#### Scenario: Input-leg body mapping
- GIVEN a `pre_request` call with a decodable request body
- WHEN the TrustGuard body is built
- THEN `direction:"input"`, `protocol:"llm"`, `session_id`, config `consumer_id`, model name/provider, and `input.input` (decoded request text) MUST be populated; attachments/consumer/collector MUST be absent

#### Scenario: Output-leg body mapping
- GIVEN a `pre_response` non-streaming call with a decodable response body
- WHEN the TrustGuard body is built
- THEN `direction:"output"` and `input.input` MUST carry the decoded response text

### Requirement: Authentication

Every TrustGuard request MUST send `Authorization: Bearer <api_key>` (from
config) and `Content-Type: application/json`.

#### Scenario: Bearer auth header sent
- GIVEN a configured `api_key`
- WHEN the plugin POSTs to `/v1/guard`
- THEN the request MUST carry `Authorization: Bearer <api_key>` and a JSON content type
