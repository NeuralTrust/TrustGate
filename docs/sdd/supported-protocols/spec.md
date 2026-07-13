# Spec: Supported Protocols (RUN-966)

Behaviour spec for the plugin protocol contract, attach-time validation, and
catalog exposure. Implementation-agnostic (WHAT, not HOW). Scenarios map to the
RUN-966 QA checklist (Q1–Q5).

QA checklist reference:
- **Q1** — LLM-only policy → MCP consumer is rejected
- **Q2** — MCP-only policy (`per_tool_rate_limiter`) → LLM consumer is rejected
- **Q3** — dual-protocol policy (`trustguard`, `cors`) works for both types
- **Q4** — global-policy attach behaviour confirmed and tested
- **Q5** — catalog API returns `supported_protocols` per plugin

---

## Requirements

### Requirement: Plugins declare supported protocols

Every built-in plugin MUST declare a non-empty set of supported protocols,
drawn from `{LLM, MCP}` (`A2A` reserved, assigned to no plugin), matching the
confirmed matrix.

Confirmed matrix (16 plugins):

| Supported protocols | Plugins |
|---|---|
| LLM + MCP | `cors`, `request_size_limiter`, `rate_limiter`, `trustguard` |
| MCP only | `per_tool_rate_limiter` |
| LLM only | `cost_cap`, `token_rate_limiter`, `model_allowlist`, `prompt_template`, `tool_definition_transformation`, `tool_allowlist`, `tool_call_validation`, `openai_moderation`, `bedrock_guardrail`, `azure_content_safety`, `semantic_cache` |

#### Scenario: Each plugin reports exactly its matrix protocols

- GIVEN a built-in plugin from the confirmed matrix
- WHEN its supported protocols are read
- THEN the set equals exactly the matrix row for that plugin
- AND no plugin reports `A2A`

### Requirement: Registry rejects invalid protocol declarations at startup

Plugin registration MUST fail when a plugin declares an empty or invalid
supported-protocol set, mirroring the existing stages/modes checks.

#### Scenario: Empty protocol set fails registration

- GIVEN a plugin whose supported-protocol set is empty
- WHEN it is registered at startup
- THEN registration fails and startup aborts

#### Scenario: Invalid protocol value fails registration

- GIVEN a plugin declaring a protocol outside `{LLM, MCP, A2A}`
- WHEN it is registered at startup
- THEN registration fails and startup aborts

### Requirement: Attach rejects protocol mismatch (consumer-scoped)

When a consumer-scoped policy is attached to a consumer, the system MUST reject
the attach with a `400` validation error if the consumer's type is not in the
policy plugin's supported protocols. The association MUST NOT be persisted.

#### Scenario: LLM-only policy to MCP consumer is rejected (Q1)

- GIVEN an `MCP` consumer and a consumer-scoped LLM-only policy (e.g. `cost_cap`)
- WHEN the policy is attached to the consumer
- THEN the attach is rejected with a `400` validation error naming the mismatch
- AND no association is written

#### Scenario: MCP-only policy to LLM consumer is rejected (Q2)

- GIVEN an `LLM` consumer and a consumer-scoped MCP-only policy (`per_tool_rate_limiter`)
- WHEN the policy is attached to the consumer
- THEN the attach is rejected with a `400` validation error
- AND no association is written

### Requirement: Attach allows compatible protocols

The system MUST allow attaching a consumer-scoped policy when the consumer's
type is in the plugin's supported protocols, including dual-protocol plugins.

#### Scenario: Matching single-protocol policy is allowed

- GIVEN an `LLM` consumer and a consumer-scoped LLM-only policy
- WHEN the policy is attached
- THEN the attach succeeds and the association is persisted

#### Scenario: Dual-protocol policy is allowed for either type (Q3)

- GIVEN a consumer-scoped dual-protocol policy (`trustguard` or `cors`)
- WHEN it is attached to an `LLM` consumer, and separately to an `MCP` consumer
- THEN both attaches succeed and the associations are persisted

### Requirement: Validation skipped for global policies

When the policy is global (`IsGlobal()`), the system MUST skip protocol
validation and allow the attach regardless of consumer type.

#### Scenario: Global LLM-only policy attaches to MCP consumer (Q4)

- GIVEN a global LLM-only policy and an `MCP` consumer
- WHEN the policy is attached
- THEN validation is skipped and the attach succeeds

### Requirement: Validation skipped for A2A consumers

When the consumer's type is `A2A`, the system MUST skip protocol validation
(reserved, not enforced). Only `LLM` and `MCP` consumers are actively validated.

#### Scenario: Any policy attaches to an A2A consumer

- GIVEN an `A2A` consumer and any consumer-scoped policy
- WHEN the policy is attached
- THEN validation is skipped and the attach succeeds

### Requirement: Pre-existing associations are not re-validated

Protocol validation MUST apply only to new attaches. Existing consumer↔policy
associations that violate the matrix MUST NOT be re-validated, mutated, or
removed.

#### Scenario: Existing mismatched association is untouched

- GIVEN an existing association that would fail current validation
- WHEN unrelated attaches or reads occur
- THEN the pre-existing association is left unchanged and no error is raised for it

### Requirement: Catalog exposes supported protocols

The plugin catalog API MUST return a `supported_protocols` field per plugin,
sourced from the plugin descriptor and matching the confirmed matrix.

#### Scenario: Catalog reports supported_protocols per plugin (Q5)

- GIVEN the plugin catalog is requested
- WHEN the response is read
- THEN each plugin entry includes `supported_protocols`
- AND each value matches that plugin's confirmed matrix row
