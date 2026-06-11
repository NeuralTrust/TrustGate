# Universal Payload Routing

The proxy accepts a universal payload on every consumer path. Routing is driven exclusively by the `model` field in the request body; transport headers never grant access to upstream providers.

## Model reference syntax

The `model` field accepts three universal forms:

| Form | Example | Behavior |
| --- | --- | --- |
| Qualified | `openai/gpt-5` | Routes to a registry of that provider. The prefix is stripped before the upstream call; the provider receives the native model (`gpt-5`). Returns `403 model_not_allowed` when the provider or model is not authorized for the consumer. |
| Short | `gpt-5` | Allowed only when the model resolves to exactly one provider within the consumer's authorized candidates. Returns `400 invalid_model` listing qualified alternatives when ambiguous. |
| Pool alias | `pool:fast-chat` | Selects the consumer's configured LB pool. The alias never reaches a provider: it is stripped and replaced by the selected member's default model. Unknown aliases return `400 invalid_model`. |

Values that do not match these forms are treated as native model identifiers and passed through untouched. In particular, a provider part that is not a plain identifier (for example a Bedrock ARN such as `arn:aws:bedrock:...:inference-profile/eu.anthropic.claude-sonnet-4-v1:0`) is never parsed as `provider/model`.

## `modelId` (Bedrock)

`modelId` is a provider-native field, not universal routing syntax. It is never parsed for routing intent and reaches the Bedrock client untouched, where it is passed as the `ModelId` API parameter and stripped from the JSON body. Model allow-lists (`model_policies`) still apply to `modelId` values via enforcement.

## `X-Provider` header: source wire format only

`X-Provider` is an optional hint declaring the **wire format of the inbound request body** (`openai`, `anthropic`, `google`, `bedrock`, ...). It exists so the proxy can skip format auto-detection and adapt the body to the selected registry's native format.

It does **not**:

- select or authorize an upstream provider — only the payload `model` intent and the consumer's policies do;
- bypass model allow-lists;
- influence load balancing or fallback.

When the hint is absent, the format is auto-detected from the body. When present, it is trusted; a mismatch with the detected format is debug-logged.

## Enforcement order

1. The routing intent is parsed from `model` and resolved against the consumer's authorized candidate set (`403`/`400` on violations).
2. Qualified prefixes are rewritten to the native model and pool aliases are stripped before any provider adaptation.
3. The body is adapted from the source wire format to the target provider format.
4. `adapter.EnforceModel` validates the final native model against the selected registry's allow-list and injects the default model when the body has none.

The original requested model (`openai/gpt-5`, `pool:fast-chat`, ...) and the final native model are both recorded on the LLM trace span (`RequestedModel` / `Model`) and in telemetry events (`requested_model` / `model`).
