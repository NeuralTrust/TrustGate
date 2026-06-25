# Spec for Bedrock Guardrail (bedrock_guardrail plugin)

New guardrail plugin (slug `bedrock_guardrail`, package
`pkg/infra/plugins/bedrockguardrail/`) that applies an AWS Bedrock
`ApplyGuardrail` policy to request content (PreRequest, `Source=INPUT`) and
response content (PreResponse, `Source=OUTPUT`). It enforces the guardrail's
topic, content, word, sensitive-information (PII), and contextual-grounding
policies in `enforce` and `observe` modes. Text is extracted per provider via
the adapter registry — never raw JSON. This re-implements LegacyGateway's
`bedrock_guardrail` on the TrustGate plugin SDK, mirroring `azure_content_safety`.

## ADDED Requirements

### Requirement: Stage and mode support

The plugin MUST declare `SupportedStages = {pre_request, pre_response}` and
`MandatoryStages = {}` (empty); stage selection MUST be policy-level. It MUST
support both `enforce` and `observe` modes. It MUST NOT define a `stages`
config field.

#### Scenario: Stages and modes resolved
- GIVEN a policy binding this plugin
- WHEN stages/modes are resolved
- THEN `pre_request` and `pre_response` MUST be supported and none mandatory
- AND both `enforce` and `observe` MUST be supported modes

### Requirement: Configuration schema

The Settings MUST expose `guardrail_id` (string, required), `version` (string,
default `DRAFT`), `pii_action` (enum `block | anonymize`), a flat `message`
(string), and a nested `credentials` object with `aws_region` (default
`us-east-1`), `use_role` (bool), `role_arn`, `session_name`, and optional static
`access_key_id`, `secret_access_key`, `session_token`. There MUST be no `stages`
field.

#### Scenario: Defaults applied
- GIVEN a config omitting `version` and `credentials.aws_region`
- WHEN config is parsed
- THEN `version` MUST default to `DRAFT` and `aws_region` to `us-east-1`

### Requirement: Configuration validation

`ValidateConfig` MUST reject a missing/empty `guardrail_id`, a `pii_action`
outside `{block, anonymize}`, and a missing `role_arn` when `use_role` is true.

#### Scenario: Missing guardrail id rejected
- GIVEN a config with no `guardrail_id`
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Role without ARN rejected
- GIVEN `use_role: true` and an empty `role_arn`
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Invalid pii_action rejected
- GIVEN `pii_action: "mask"`
- WHEN `ValidateConfig` runs
- THEN it MUST fail

### Requirement: Text extraction via adapter registry

The plugin MUST resolve the provider/source-format to an adapter format and
extract content via the registry: on PreRequest the decoded request prompt
(system + message turns) MUST be guarded; on PreResponse the decoded response
content MUST be guarded. It MUST NOT send raw request/response JSON to Bedrock.

#### Scenario: Prompt extracted on request
- GIVEN a PreRequest with a decodable provider body
- WHEN the plugin runs
- THEN the extracted prompt text MUST be sent with `Source=INPUT`

#### Scenario: Response content extracted on response
- GIVEN a PreResponse with a decodable provider body
- WHEN the plugin runs
- THEN the extracted response text MUST be sent with `Source=OUTPUT`

### Requirement: Mode behavior

In `enforce` mode the plugin MUST block (403) or mask on a blocking assessment.
In `observe` mode it MUST assess and record the outcome but MUST NOT block or
mutate the body. Blocking MUST be gated by `appplugins.Blocks(in.Mode)`.

#### Scenario: Observe never blocks
- GIVEN `observe` mode and a guardrail intervention
- WHEN the plugin runs
- THEN the request/response MUST pass through unchanged
- AND the decision MUST be recorded as `reported`

### Requirement: Assessment coverage

The plugin MUST inspect ALL guardrail assessments — topic, content, word,
sensitive-information, and contextual-grounding. A blocking action in any of
these MUST be able to trigger a block. Blocking actions MUST be detected using
the v2 SDK `BLOCKED` action constant (not `REJECT`).

#### Scenario: Any policy can block
- GIVEN an intervention whose blocking policy is word OR contextual-grounding
- WHEN the plugin runs in `enforce`
- THEN it MUST return 403 with that policy named

#### Scenario: No intervention passes
- GIVEN a guardrail `Action` of `NONE`
- WHEN the plugin runs
- THEN it MUST pass through and record `allowed`

### Requirement: PII handling

When the sensitive-information policy fires: with `pii_action: block` the plugin
MUST return 403; with `pii_action: anonymize` it MUST rewrite the body using
Bedrock's masked output and continue, but MUST fall back to block if Bedrock
returned a `BLOCKED` (not anonymized) PII action.

#### Scenario: PII block
- GIVEN `pii_action: block` and a sensitive-information intervention
- WHEN the plugin runs in `enforce`
- THEN it MUST return 403 with policy `sensitive_information`

#### Scenario: PII anonymize rewrites body
- GIVEN `pii_action: anonymize` and an `ANONYMIZED` PII result with masked output
- WHEN the plugin runs in `enforce`
- THEN the extracted text MUST be replaced with the masked output and forwarded
- AND the decision MUST be recorded as `anonymized`

#### Scenario: PII anonymize falls back to block
- GIVEN `pii_action: anonymize` but Bedrock returned a `BLOCKED` PII action
- WHEN the plugin runs in `enforce`
- THEN it MUST return 403

### Requirement: Block response shape

On block the plugin MUST return HTTP `403` via a `PluginError` whose body is
EXACTLY `{"error":{"type":"guardrail_blocked","policy":"<policy>","name":"<name>"}}`
with `Content-Type: application/json`. The operator `message` MUST NOT be format-
interpolated into the body.

#### Scenario: Exact 403 envelope
- GIVEN a topic-policy intervention in `enforce`
- WHEN the plugin blocks
- THEN the response MUST be 403 with body `{"error":{"type":"guardrail_blocked","policy":"topic_policy","name":"..."}}`

### Requirement: Body mutation

For PII `anonymize`, the plugin MUST mutate the upstream request body on
PreRequest (via `Result.RequestBody`) and the response body on PreResponse (via
`Result.Body` with `StopUpstream: true`), re-encoding the masked text through the
adapter. It MUST declare `MutatesRequestBody()` and `MutatesResponseBody()` true.
If re-encoding fails: `enforce` MUST block (fail closed); `observe` MUST record
degraded and pass through.

#### Scenario: Request body mutated on PreRequest
- GIVEN a PreRequest anonymize with masked output
- WHEN the plugin runs
- THEN it MUST return the re-encoded body via `RequestBody` without stopping upstream

#### Scenario: Response body mutated on PreResponse
- GIVEN a PreResponse anonymize with masked output
- WHEN the plugin runs
- THEN it MUST return the re-encoded body via `Body` with `StopUpstream: true`

#### Scenario: Re-encode failure fails closed in enforce
- GIVEN anonymize where re-encoding fails in `enforce`
- WHEN the plugin runs
- THEN it MUST block

### Requirement: Pass-through (no-op) conditions

The plugin MUST pass through unchanged (200, no mutation, no Bedrock call) when:
the request (or response on PreResponse) is missing, the body is empty, the
provider is empty, the format is unresolved, the body fails to decode, the
extracted text is empty, or the response is streaming (PreResponse).

#### Scenario: Empty or undecodable body
- GIVEN an empty or undecodable body
- WHEN the plugin runs
- THEN it MUST pass through without calling Bedrock

#### Scenario: Streaming response passes through
- GIVEN a PreResponse with `Streaming: true`
- WHEN the plugin runs
- THEN it MUST pass through without guarding

### Requirement: Event recording

When an event context is present the plugin MUST record extras with guardrail id,
version, region, stage, mode, decision (`blocked | anonymized | reported |
allowed | failed_closed`), and on a match the matched policy, type, action, and
name, plus `latency_ms`. It MUST call `appplugins.SetDecision(in.Event, in.Mode)`
and MUST NOT log prompt/response content.

#### Scenario: Extras recorded on block
- GIVEN an enforce block with non-nil event
- WHEN the plugin completes
- THEN extras MUST include guardrail id/version/region/stage/mode, decision `blocked`, the matched policy/type/action/name, and `latency_ms`

#### Scenario: Nil event tolerated
- GIVEN a nil event context
- WHEN the plugin runs
- THEN it MUST complete without error and record nothing

## Non-Goals

- Guarding **streamed** PreResponse output (passed through).
- Configuring the guardrail itself on the AWS side (managed in AWS).
- Integrating a central secret store (credentials live in policy Settings).
