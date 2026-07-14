---
linear: RUN-993
type: feat
changelog: "Add regex_replace guardrail plugin that rewrites the request prompt OR the LLM response via RE2 regular expressions on exactly one leg."
---

# Proposal: Regex Replace plugin (RUN-993)

## Intent

Operators need targeted, deterministic text rewriting inside the gateway: mask emails, strip internal ids, normalize wording — on either the request prompt (before the LLM) or the LLM response (before the client). No existing plugin does provider-agnostic regex rewrite. This is a redaction/normalization transform, **not** an access gate.

## Scope

### In Scope

- New plugin package `pkg/infra/plugins/regex_replace/` (config, validation, Execute).
- Registration in the registry and catalog metadata (+ catalog test).
- Two legs, one per instance: `pre_request` prompt rewrite and `pre_response` response rewrite.
- Modes `enforce` (rewrite) and `observe` (telemetry only, no mutation).
- Unit tests + one functional test (request + response).

### Out of Scope

- Both legs in a single instance (use two instances).
- Non-regex transforms; semantic/LLM-based redaction.
- Streaming response rewrite (pass-through — documented limitation).
- Tool-call argument rewriting.

## Capabilities

### New Capabilities

- `regex-replace-plugin`: provider-agnostic RE2 rewrite of request prompt XOR LLM response, ordered chained rules, enforce/observe modes.

### Modified Capabilities

- None.

## Approach

Model on `pkg/infra/plugins/bedrockguardrail/` (operates on both legs). Register ONE descriptor with `SupportedStages=[pre_request, pre_response]`, `MandatoryStages=[]`. Required `target` (enum `request|response`) selects the leg; `Execute` no-ops on the non-matching stage.

Text is read provider-agnostically through the adapter `Registry`:
- Request: `DecodeRequestFor` → rewrite all `Messages[].Content` + top-level `System` → `EncodeRequest` → `Result{RequestBody}`.
- Response: `DecodeResponseFor` → rewrite `CanonicalResponse.Content` → `EncodeResponse` → `Result{Body, StopUpstream:true}` (the only supported response-rewrite mechanism; there is NO `Result.ResponseBody`).

`StopUpstream` short-circuits sibling `pre_response` plugins — documented caveat. When `in.Response.Streaming`, pass through unchanged (mirrors bedrock_guardrail).

Regex engine: Go stdlib `regexp` (RE2). `case_insensitive`→`(?i)`, `multiline`→`(?m)` compiled into the pattern. Replacement uses Go `$1`/`${name}` via `ReplaceAllString`. RE2 rejects backreferences/lookaround at `regexp.Compile`, so config validation catches unsupported patterns. Rules apply in declaration order and chain.

### Config contract

```
target: request|response        # required, mutually exclusive leg selector
rules:                          # required, non-empty, ordered
  - pattern: string            # required, must compile (RE2)
    replacement: string
    case_insensitive: bool     # optional
    multiline: bool            # optional
```

Modes: `enforce` (mandatory, applies rewrite) and `observe` (compute + emit telemetry, no mutation).

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `pkg/infra/plugins/regex_replace/` | New | config, validation, rewrite, Execute, tests |
| `pkg/container/modules/plugins.go` | Modified | register plugin (needs `*adapter.Registry`) |
| `pkg/app/plugins/catalog_metadata.go` | Modified | catalog meta, group `Guardrails` |
| `pkg/app/plugins/catalog_test.go` | Modified | add slug to `builtinSlugs` |
| `tests/functional/` | New | request + response functional test |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| `StopUpstream` drops sibling `pre_response` plugins | Med | Document; last-in-chain guidance |
| Streaming responses silently un-rewritten | Med | Pass-through + documented limitation |
| Catastrophic/greedy patterns hurt latency | Low | RE2 is linear-time; operator owns rules |

## Rollback Plan

Additive. Revert by removing the `regex_replace` package, its registry entry, catalog meta, and the `builtinSlugs` addition. No migrations or schema changes; existing plugins unaffected.

## Dependencies

- Adapter `Registry` (`DecodeRequestFor`/`DecodeResponseFor`, `EncodeRequest`/`EncodeResponse`).
- Go stdlib `regexp` (RE2).

## Success Criteria

- [ ] Instance with `target=request` masks matched text in the prompt before upstream.
- [ ] Instance with `target=response` rewrites the returned body via `StopUpstream`.
- [ ] Invalid regex (or unsupported RE2 feature) rejected at `ValidateConfig`.
- [ ] `observe` mode emits telemetry without mutating body.
- [ ] Streaming responses pass through unchanged.
- [ ] Catalog lists plugin under `Guardrails`; `catalog_test` covers the slug.
- [ ] `-race`-clean unit + functional tests pass.

> Implementers: this repo enforces **NO CODE COMMENTS** (strict, pre-commit). Conventional commits on `feat/run-993-...`; PR to `develop` with `RUN-993` in the body; 400-line PR budget.
