# Payload Routing

The proxy exposes fixed routes per wire format, prefixed by the consumer's auto-generated slug. The path — never a header and never body inspection — determines the source format of the request, and the `model` field in the payload drives provider selection.

## Fixed proxy routes

A client points its SDK at `https://{gateway_slug}.gw.neuraltrust.ai/{consumer_slug}` and the SDK completes the path:

| Route | Source format |
| --- | --- |
| `/{consumer_slug}/v1/chat/completions` | OpenAI Chat Completions |
| `/{consumer_slug}/v1/responses` | OpenAI Responses |
| `/{consumer_slug}/v1/messages` | Anthropic Messages |
| `/{consumer_slug}/v1beta/models/{model}:generateContent` (and `:streamGenerateContent`) | Gemini |

Any other path returns `404`. An unknown `consumer_slug` also returns `404`.

### Consumer slug

The `slug` is an 8-character alphanumeric identifier (e.g. `X84Yhsy8`) generated server-side when the consumer is created. It is returned read-only in the consumer API responses and is globally unique. It is the only routing identifier: consumers no longer have a custom `path`.

## Cross-format adaptation

The source format comes from the path; the target format is the native format of the registry selected by routing. When they differ, the gateway adapts the request (source → target) and adapts the response — buffered or streamed — back to the source format. For example, an Anthropic-format request on `/v1/messages` routed to an OpenAI registry is sent upstream as OpenAI and the client receives an Anthropic-format response.

A body that does not match the format of the path fails with `400` when the adapter decodes it.

## Model reference syntax

The `model` field accepts three forms:

| Form | Example | Behavior |
| --- | --- | --- |
| Pinned | `@openai/gpt-5` | Pins the request to a registry of that provider, **bypassing load balancing and fallback**. The `@provider/` prefix is stripped before the upstream call; the provider receives the native model (`gpt-5`). Returns `403 model_not_allowed` when the provider is not associated to the consumer or the model is not allowed by its model policies. |
| Short | `gpt-5` | Allowed only when the model resolves to exactly one provider within the consumer's authorized candidates; load balancing and fallback apply normally. Returns `400 invalid_model` listing `@provider/model` alternatives when ambiguous. |
| Pool alias | `pool:fast-chat` | Selects the consumer's configured LB pool. The alias never reaches a provider: it is stripped and replaced by the selected member's default model. Unknown aliases return `400 invalid_model`. |

Values that do not match these forms — including `provider/model` without the `@` prefix — are treated as native model identifiers and passed through untouched. In particular, a Bedrock ARN such as `arn:aws:bedrock:...:inference-profile/eu.anthropic.claude-sonnet-4-v1:0` is never parsed as a routing reference.

For Gemini requests the model reference is taken from the path segment (`/v1beta/models/{model}:generateContent`) instead of the body.

## `modelId` (Bedrock) is not an input field

Bedrock is **not** a supported source wire format. `modelId` is a Bedrock-internal concept that only exists after the gateway adapts the payload to Bedrock's native format; it is never accepted from the inbound request. A request carrying `modelId` is rejected with `400 invalid_model`, so it can never reach the Bedrock client or bypass model allow-lists. Bedrock models are addressed with the `model` field (`@bedrock/anthropic.claude-sonnet-4`, or a native identifier such as an ARN).

## Enforcement order

1. The auth middleware parses the path: consumer slug → consumer lookup, fixed route → source format. Unknown routes or slugs return `404`.
2. The routing intent is parsed from `model` (or the Gemini path segment) and resolved against the consumer's authorized candidate set (`403`/`400` on violations).
3. A pinned intent (`@provider/model`) selects the provider's registry directly — no load balancing, no fallback. Short models and pool aliases go through LB and fallback as configured.
4. `@provider/` prefixes are rewritten to the native model and pool aliases are stripped before any provider adaptation.
5. The body is adapted from the source format to the target provider format.
6. `adapter.EnforceModel` validates the final native model against the selected registry's allow-list and injects the default model when the body has none.
7. The upstream response is adapted back to the source format before reaching the client.

The original requested model (`@openai/gpt-5`, `pool:fast-chat`, ...) and the final native model are both recorded on the LLM trace span (`RequestedModel` / `Model`) and in telemetry events (`requested_model` / `model`).
