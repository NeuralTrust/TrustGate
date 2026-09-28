# Proposal: Prompt caching and cache usage accounting across all providers (ENG-1618)

> Base: `origin/main` (user decision 2026-09-23). Final PR: integration branch → `main`. Nothing from develop.

## Intent

TrustGate drops the cache markers that clients send when it translates between formats (and in some same-format hops). It also misreports cached tokens for several providers. Bedrock is the worst case: cached reads and writes are billed at $0 and token budgets are skewed, on current traffic. The fix covers every provider, not only Bedrock for ISDIN.

## Scope

### In Scope (ordered; usage correctness lands first)
1. **Usage/billing.**
   - Bedrock: add cache read and write into `InputTokens`, map `CacheDetails` to the 1h write count, reverse the fold in the encoder, fix the fixtures that pin the wrong numbers.
   - Parse vendor fields: DeepSeek hit/miss; `cache_write_tokens` for OpenAI, Azure, Moonshot and OpenRouter; OpenRouter `cache_discount`/`cost` (log only, never used for billing); Cohere `cached_tokens`. When a provider reports the same number in two fields, take the max, never the sum.
   - The Chat, Responses, Cohere and Anthropic encoders (the Anthropic one including the `cache_creation` breakdown, buffered and SSE) emit cache fields. Tokenratelimit reads the client-format body (`budget.go:438-474`), so it needs them.
   - 1h write rate (`pricing.go:162`): use the registry override if set. Otherwise, for Claude models (Anthropic direct or on Bedrock), charge `CacheWrite1h = 2 × Input`, per the Anthropic and AWS docs. For all other models it stays `CacheWrite`. The registry discount applies after.
2. **Cache intent in the canonical model (Approach A):** extra fields on the canonical model, alongside the `Content` string, the same way ENG-1608 added `Images`.
   - A breakpoint and TTL on system, on each tool and on each message.
   - Request-level `CacheOptions{Key, Retention, Mode, Auto}`.
   - Anthropic, OpenAI Chat and OpenAI Responses decode and encode these faithfully. When translating to a target without an equivalent (Gemini, Cohere), drop them on purpose and document the drop.
   - A breakpoint attaches to the last block the encoder emits (images come first).
3. **Precedence:** the client's markers always win. Above the target's maximum (4 for Anthropic and Bedrock), drop the earliest message breakpoints first. A 1h marker that comes after a 5m marker is downgraded to 5m.
4. **Pass-through fixes:**
   - Mistral: carry `prompt_cache_key`.
   - OpenRouter: carry `cache_control` and the routing keys (`provider`, `models`, `transforms`, `route`).
   - Groq: keep the request fields we do not model.
   - Azure: keep today's API selection; Responses→Azure Chat maps `prompt_cache_key` and `prompt_cache_retention` to the Chat fields, falling back to key-only on a 400 for retention (design D5).
   - Groq and OpenRouter responses are still re-encoded (reasons: `x_groq`, `provider` metadata, SSE comments).
5. **Bedrock `cachePoint`:**
   - Built from the canonical breakpoints, in tools→system→messages order, at most 4, TTL respected.
   - A table in code of which model families support explicit caching (and 1h).
   - On a `ValidationException`, retry without `cachePoint`, the same way the existing system-prompt fallback works.
   - `foldSystemIntoFirstTurn` keeps the `cachePoint`.
   - The minimum token count is not enforced.
6. **Plugins:**
   - Plugins that re-encode the request or response (regexreplace, bedrockguardrail and googlemodelarmor anonymize, trustguard rewrite) keep cache intent.
   - Plugins that rewrite `tools` (toolinjection, toolallowlist, pertoolratelimit) keep per-tool markers.
   - Document which plugins break prefix stability.
7. **Tests:**
   - Unit tests per adapter, buffered and streaming, plus a `bedrock_live` cache case.
   - E2E per modified provider (see Success Criteria).

### Out of Scope
- Breakpoints that the gateway inserts itself (issue block 6). Follow-up ticket: off by default, 1h opt-in.
- A Bedrock-native (Converse) inbound route.
- Gemini `cachedContents` route; Claude on Vertex; `semanticcache`; data-plane-api/LegacyGateway.
- The prompttemplate bug with an array `system` (separate ticket).
- Historical cost backfill:
  - Bedrock rows can be recomputed downstream from the raw counts.
  - DeepSeek hits were never recorded and cannot be recovered. Covered by a release note only.
- E2E for Moonshot (unit tests only), Vertex (covered by the Gemini e2e) and openai_compatible.

## Capabilities

### New Capabilities
- `prompt-cache-usage-accounting`: how each provider's cache usage maps to canonical, how the encoders emit it, and the pricing rules (including the 1h rate).
- `prompt-cache-intent`: canonical breakpoints and options; precedence; how each cross-format pair maps or drops them.
- `prompt-cache-passthrough`: Mistral, OpenRouter, Groq and Azure Responses request fidelity.
- `bedrock-prompt-caching`: `cachePoint` emission, the capability table, the retry fallback.
- `plugin-cache-preservation`: plugins that re-encode or rewrite tools keep markers.

### Modified Capabilities
None. No existing spec (mcp-*, policy-*) is affected.

## Approach

Nine chained PRs, each ≤400 changed lines (S2 and S4 split per design.md):

| PR | Content |
|---|---|
| S1a | Bedrock usage |
| S1b | OpenAI-family and Cohere decode |
| S1c | Client encoders and 1h pricing |
| S2a | Canonical intent, normalize hook, Anthropic |
| S2b | OpenAI Chat and Responses intent, GPT-5.6 gate |
| S3 | Pass-through |
| S4a | Bedrock `cachePoint` wire and SDK |
| S4b | Bedrock capability table and retry |
| S5 | Plugins |

- S2a, S2b and S4a are rebased on ENG-1608.
- The new e2e test lives in multi-agent-tests on `feat/eng-1618-prompt-caching-e2e`.

## Affected Areas

| Area | Impact |
|---|---|
| `pkg/infra/providers/adapter/{canonical,anthropic,openai_completions,openai_responses,bedrock,cohere,mistral,openrouter,registry,format}*.go` | Modified |
| `pkg/infra/providers/bedrock/converse.go` | Modified |
| `pkg/infra/plugins/llmcost/pricing.go` | Modified |
| `pkg/infra/plugins/{regexreplace,bedrockguardrail,googlemodelarmor,trustguard,toolinjection,toolallowlist,pertoolratelimit}` | Modified |
| `multi-agent-tests/src/e2e/tests/test_prompt_caching.py` | New |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Conflicts with ENG-1608 (unpushed, same structs) and #826 (Anthropic SSE encoder, trustguard) | High | Rebase S2 and S4 after ENG-1608 merges; S1 does not depend on it |
| Bedrock input, cost and budget numbers jump after S1a | High | Release note; heads-up to ISDIN |
| Converse `totalTokens` and Moonshot field shapes unconfirmed | Med | `max(total, in+out)`; `bedrock_live` test; parse both Moonshot shapes, take the max |
| A Bedrock model rejects `cachePoint` | Med | Capability table plus the ValidationException retry |
| Relaxing Groq/OpenRouter re-encoding changes responses | Med | Change the request side only |
| Missing provider API keys block e2e | Med | Stop and report |

## Rollback Plan

Each PR is revertible on its own, in reverse order:
- S5/S4/S3/S2 have no schema or config changes, so a revert restores the previous translation.
- Reverting S1a/b/c restores the previous (wrong) usage numbers. Only revert on a regression, and announce it.
- No migrations.

## Dependencies

- ENG-1608 lands first (S2 and S4 are rebased on it).
- PR #826 ordering.
- API keys for the e2e runs, and AWS credentials for `bedrock_live`.

## Success Criteria

- [ ] Recorded usage and cost match the provider's `usage` for every provider, buffered and streaming, including 1h writes.
- [ ] Round-trip tests: markers survive every supported pair; unsupported targets drop them on purpose.
- [ ] Plugin tests keep the markers.
- [ ] Every modified provider passes an adversarial review. It then passes these against a LOCAL gateway built from the worktree (never prod):
  - native `make matrix-ag UPSTREAM=X AGENT=X`;
  - cross-format `make matrix-ag PROVIDER=X`, both of them with `STREAM=1` and without;
  - `pytest -m prompt_caching`. This sends the same long prefix twice and checks cached tokens both in the provider response and in `GET /v1/playground/traces/{X-AG-Trace-Id}` (auth: `X-AG-Playground-Token`, HS256).
- [ ] `make test`, lint and verifier all green.
