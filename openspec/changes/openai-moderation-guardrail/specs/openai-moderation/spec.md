# Delta for OpenAI Moderation (openai_moderation plugin)

This change adds a net-new read-only guardrail infra plugin `openai_moderation`
backed by the OpenAI Moderations API. It runs on `pre_request` and/or
`pre_response`, supports modes `enforce` and `observe`, and is read-only
(`MutatesRequestBody`, `MutatesResponseBody`, `MutatesMetadata` all `false`). On
allow it returns a pass-through `*plugins.Result{StatusCode: 200}`; on block it
returns a `*appplugins.PluginError` (403 `content_flagged`). Content is extracted
provider-aware via the canonical adapter registry and is TEXT-ONLY in v1. Out of
scope in v1: `image_url` moderation, secret-reference credential management,
`post_request`/`post_response` legs, and built-in default thresholds.

## ADDED Requirements

### Requirement: Stage selection

The plugin MUST declare `SupportedStages = {pre_request, pre_response}` and
`MandatoryStages = {}` (empty). It MUST run only on a stage selected by the
`stages` settings field (an array of `pre_request` / `pre_response`), which
defaults to BOTH stages when omitted. When the current stage is not selected,
the plugin MUST pass through unchanged (no moderation call, no block) and MUST
NOT record a moderation decision.

#### Scenario: Default runs both stages
- GIVEN a config that omits `stages`
- WHEN a request is processed on `pre_request` and a response is processed on `pre_response`
- THEN moderation MUST run on both stages

#### Scenario: Unselected stage passes through
- GIVEN `stages:["pre_request"]`
- WHEN a response is processed on `pre_response`
- THEN the plugin MUST pass through unchanged AND MUST NOT call the moderations API

### Requirement: Mode enforce vs observe

The plugin MUST support modes `enforce` and `observe`. Under `enforce` a
violation MUST block. Under `observe` the plugin MUST evaluate the content,
record its decision and per-category scores on the event, and pass through
WITHOUT ever blocking. In BOTH modes, when a moderation call succeeds the plugin
MUST record per-category scores on the event (when the event is present).

#### Scenario: Enforce blocks on violation
- GIVEN mode `enforce` and content whose aggregated score crosses a configured threshold
- WHEN the request is processed
- THEN the plugin MUST block with a 403 `content_flagged` response

#### Scenario: Observe never blocks
- GIVEN mode `observe` and content whose aggregated score crosses a configured threshold
- WHEN the request is processed
- THEN the plugin MUST pass through unchanged AND MUST record the decision and per-category scores on the event

#### Scenario: Scores recorded in both modes
- GIVEN a successful moderation call in either `enforce` (allow path) or `observe`
- WHEN the decision is recorded
- THEN per-category scores MUST be recorded on the event when the event is present

### Requirement: Block decision and evaluation set

The plugin MUST compute an evaluation set: the `categories` allow-list when it is
non-empty; otherwise ALL categories present in the moderation response. It MUST
block if and only if at least one violation exists in the evaluation set AND the
mode blocks (`mode != observe`). A category in the evaluation set is a violation
when EITHER its aggregated max score is `>= its configured threshold`, OR
`block_on_flagged` is `true` and OpenAI marked that category `flagged`. A
category without a configured threshold blocks only via the `block_on_flagged`
path.

#### Scenario: Threshold crossed within evaluation set
- GIVEN `categories:["hate"]`, `thresholds:{"hate":0.7}`, and an aggregated `hate` score of `0.91`
- WHEN the block decision is computed in `enforce`
- THEN the request MUST be blocked

#### Scenario: Allow-list excludes a flagged category
- GIVEN `categories:["hate"]` and an aggregated `violence` score above any value, but no `hate` violation
- WHEN the block decision is computed
- THEN `violence` MUST NOT be evaluated AND the request MUST pass through

#### Scenario: Empty allow-list evaluates all response categories
- GIVEN an empty `categories` and `thresholds:{"violence":0.8}` with an aggregated `violence` score of `0.85`
- WHEN the block decision is computed in `enforce`
- THEN `violence` MUST be evaluated and the request MUST be blocked

#### Scenario: block_on_flagged blocks without a configured threshold
- GIVEN `block_on_flagged:true`, no configured threshold for `sexual`, and OpenAI marked `sexual` as `flagged` within the evaluation set
- WHEN the block decision is computed in `enforce`
- THEN the request MUST be blocked

#### Scenario: No violation passes through
- GIVEN no category in the evaluation set crosses its threshold and (`block_on_flagged:false` OR nothing flagged)
- WHEN the block decision is computed
- THEN the request MUST pass through unchanged

### Requirement: Multi-input score aggregation

When the moderations response contains multiple `results[]`, the plugin MUST
aggregate scores as the MAX score per category across ALL results. It MUST NOT
use only the first result.

#### Scenario: Max across results
- GIVEN two moderation results with `hate` scores `0.40` and `0.82`
- WHEN scores are aggregated
- THEN the aggregated `hate` score MUST be `0.82`

### Requirement: Block response body

On block, the plugin MUST return a `*PluginError` with `StatusCode` 403 and
`Type` `content_flagged` whose body is set verbatim to a JSON object of the
shape `{"error":{"type":"content_flagged","categories":[{"category","score","threshold"}]}}`,
listing each violating category with its aggregated score and configured
threshold. This body MUST reach the client unchanged.

#### Scenario: 403 content_flagged body
- GIVEN a `hate` violation with aggregated score `0.91` and threshold `0.7`
- WHEN the plugin blocks
- THEN the response MUST be 403 with body `{"error":{"type":"content_flagged","categories":[{"category":"hate","score":0.91,"threshold":0.7}]}}`

### Requirement: Fail-closed on moderation unavailability

On an OpenAI API/transport error, a non-2xx response, or a timeout: under
`enforce` the plugin MUST fail CLOSED and return a generic `*PluginError` with
`StatusCode` 502 and `Type` `moderation_unavailable`, carrying a generic message
and NO raw OpenAI body. Under `observe` the plugin MUST pass through and record
the failure on the event. In all cases the underlying detail MUST be logged via
`slog` and MUST NEVER be returned to the caller.

#### Scenario: Enforce returns generic 502
- GIVEN mode `enforce` and the moderations API returns a non-2xx response or times out
- WHEN the plugin handles the failure
- THEN it MUST return a 502 with `type:"moderation_unavailable"` AND MUST NOT include any raw OpenAI body

#### Scenario: Observe passes through on failure
- GIVEN mode `observe` and the moderations API errors
- WHEN the plugin handles the failure
- THEN the request MUST pass through unchanged AND the failure MUST be recorded on the event

#### Scenario: Detail is logged, never returned
- GIVEN any moderation failure in any mode
- WHEN the failure is handled
- THEN the underlying detail MUST be logged via `slog` AND MUST NOT appear in the caller-facing response

### Requirement: Streaming responses skipped

On `pre_response`, when the response is streaming the plugin MUST skip moderation
and pass through unchanged.

#### Scenario: Streaming response skipped
- GIVEN a streaming response on `pre_response`
- WHEN the plugin runs
- THEN it MUST pass through unchanged AND MUST NOT call the moderations API

### Requirement: Provider-aware text extraction (text-only v1)

The plugin MUST extract content provider-aware via the canonical adapter registry
(`ResolveAgentFormat` then `DecodeRequestFor` / `DecodeResponseFor`), covering
OpenAI/Anthropic/Bedrock/Gemini/Mistral/Groq/DeepSeek/Azure. On the request leg
the moderated text MUST be the canonical `System` plus each `Messages[].Content`;
on the response leg it MUST be the canonical response `Content`. v1 is TEXT-ONLY:
`image_url` moderation is an explicit NON-GOAL and MUST NOT be performed. The
moderations `input` MUST be built from extracted text only.

#### Scenario: Request text from system and messages
- GIVEN a provider request decoded to canonical with a `System` and two `Messages`
- WHEN text is extracted on `pre_request`
- THEN the moderated input MUST contain the system text and both message contents

#### Scenario: Response text from canonical content
- GIVEN a provider response decoded to canonical
- WHEN text is extracted on `pre_response`
- THEN the moderated input MUST be the canonical response `Content`

#### Scenario: Image parts not moderated in v1
- GIVEN a request containing `image_url` content parts
- WHEN text is extracted
- THEN only text MUST be moderated AND image parts MUST NOT be sent to the moderations API

### Requirement: Configuration validation

`ValidateConfig` MUST reject invalid configuration. It MUST require a non-empty
`api_key`. Every configured threshold MUST be a number in the inclusive range
`0..1`. Each entry of `stages` MUST be one of `pre_request` / `pre_response`, and
each entry of `categories` MUST be a recognized moderation category. Invalid
configuration MUST be rejected with a clear message.

#### Scenario: Missing api_key rejected
- GIVEN a config with no `api_key`
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Threshold out of range rejected
- GIVEN a threshold of `1.5` (or a negative value)
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Invalid stage or category rejected
- GIVEN a `stages` entry of `post_request` or an unrecognized `categories` entry
- WHEN `ValidateConfig` runs
- THEN it MUST fail

#### Scenario: Valid config accepted
- GIVEN a config with a non-empty `api_key`, thresholds in `0..1`, and valid `stages`/`categories`
- WHEN `ValidateConfig` runs
- THEN it MUST pass

### Requirement: Empty or undecodable input passes through

When the request/response body is nil or empty, cannot be decoded to canonical,
or yields no extractable text, the plugin MUST pass through unchanged WITHOUT
calling the moderations API and WITHOUT blocking.

#### Scenario: Empty body passes through
- GIVEN a nil or empty body on the selected stage
- WHEN the plugin runs
- THEN it MUST pass through unchanged AND MUST NOT call the moderations API

#### Scenario: No extractable text passes through
- GIVEN a body that decodes but yields no text (e.g. image-only content)
- WHEN the plugin runs
- THEN it MUST pass through unchanged AND MUST NOT call the moderations API
