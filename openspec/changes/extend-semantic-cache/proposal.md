# Proposal: Extend the semantic_cache plugin — RUN-699

## Why

The `semantic_cache` plugin (`pkg/infra/plugins/semanticcache`) returns cached
responses for semantically similar prompts to cut upstream cost and latency.
Today it is a thin slice of RUN-699's target: it only understands
`similarity_threshold`, a duration-string `ttl`, and a nested
`embedding{provider,model,api_key}`; it partitions the cache by registry/gateway
(never by consumer); it is Redis-only; it always stores on 2xx; it cannot be
bypassed except via a hardcoded `Cache-Control: no-cache`; and it has no notion
of streaming or tool requests. This change brings the plugin up to the RUN-699
config contract while preserving every existing config and behaviour.

- Linear: **RUN-699** — "Plugin: Semantic caching (extend semantic_cache)".
  Purpose: return cached responses for semantically similar prompts to reduce
  cost/latency.

## What changes

- **New config surface (back-compat preserved)** on the existing plugin slug
  `semantic_cache`:
  - `scope` (enum `consumer | global`, default `consumer`) — authoritative for
    the **cache partition only** (plugin-local; independent of policy
    `Global`/`RuntimeScope` composition).
  - `mode` (enum `exact | semantic | both`, default `semantic`).
  - `ttl_seconds` (int seconds) — adopted; legacy `ttl` (duration string) kept as
    a back-compat alias. `ttl_seconds` wins when both are set.
  - `embedding_provider` / `embedding_model` — flattened fields adopted; nested
    `embedding{provider,model,api_key}` kept as back-compat. Flattened wins when
    set.
  - `vector_store` (enum `redis | pgvector | in_memory`, default `redis`).
  - `cache_only_on_status` (int array, default `[200]`) — gates **storing** only.
  - `bypass_header` (string, default `X-Cache-Bypass`) — request header that
    skips lookup+store.
  - `skip_if_tools_present` (bool, default `true`).
  - `skip_if_streaming` (bool, default `false`).
- **Cache partitioning** keyed off `in.Scope` plus the registry id:
  `consumer` → partition by `ConsumerID` (degrade to pass-through if empty, so we
  never share across consumers); `global` → partition by `GatewayID`. The
  partition is always namespaced by registry id so identical prompts to different
  upstreams never collide.
- **`X-Cache: HIT|MISS`** literal response header (spec requirement) added
  alongside the existing `X-Cache-Status` / `X-Cache-Similarity` (kept for
  back-compat). `MISS` must also appear on the forwarded (miss) response.
- **Bypass / gating**: `bypass_header` skips the cache entirely;
  `cache_only_on_status` gates storing; `skip_if_streaming` bypasses
  lookup+store for `stream=true` requests; `skip_if_tools_present` skips serving
  a hit when the request declares tools and skips storing when the request
  declares tools or the response carries tool calls.
- **`embedding.api_key` becomes OPTIONAL** — missing/invalid credentials degrade
  to pass-through (cache no-ops; the request never fails). Removes the current
  hard `validate()` requirement.
- **Store factory** keyed by `vector_store`, returning the existing `RedisStore`,
  a new `in_memory` store (TTL eviction), or a new `pgvector` store (new infra
  store + DB migration).
- **Mode**: `exact` = deterministic match on the normalized last user message
  hashed under the scope partition (no embedding); `semantic` = current embedding
  similarity; `both` = exact lookup first, semantic fallback, store under both.

## Scope

### In scope

- Full RUN-699 config surface with documented back-compat for every legacy field.
- Consumer/global cache partitioning via `in.Scope`, registry-namespaced.
- `bypass_header`, `cache_only_on_status`, `skip_if_streaming`,
  `skip_if_tools_present` gates.
- `X-Cache: HIT|MISS` header on both hit and miss legs.
- Optional embedding credentials with graceful pass-through degradation.
- Store factory + `in_memory` + `pgvector` backends.
- `exact` / `both` deterministic-match modes.

### Out of scope (non-goals / documented limitations)

- **Cache key = last user message only.** History, system prompt, and request
  params (temperature, etc.) are intentionally ignored. This is why `consumer` is
  the safe default scope. Multi-turn / parameterized keys are future work.
- **Streaming replay fidelity.** With `skip_if_streaming:false`, a stored
  streamed response is the buffered raw upstream bytes (SSE concatenation from
  `wrapStreamWithPostResponse`), replayed verbatim on a hit. Deep
  canonicalization/re-segmentation of SSE is a future follow-up. `true` sidesteps
  this by never caching streamed traffic.
- **pgvector requires a DB migration** (vector extension + table/index); it is
  the last, heaviest phase and is not required for the early value.
- No change to policy `Global`/`RuntimeScope` composition semantics; `scope` here
  governs only the cache partition.

## Phased delivery (400-line PR budget → chained PRs)

Each phase is independently shippable, reviewable, and reverts cleanly. Phases
are chained: each PR targets the previous slice's branch.

| Phase | Slice | Notes |
|---|---|---|
| **P1** | Config surface + back-compat (`ttl_seconds`/`ttl`, flattened/nested embedding), optional `api_key`, `cache_only_on_status`, `bypass_header`, literal `X-Cache: HIT\|MISS` header, catalog metadata. | No partition/store changes. Pure config + header + storing-gate. Largest config churn — keep store/mode untouched. |
| **P2** | Cache partitioning via `in.Scope` (`consumer`/`global`, registry-namespaced, empty-consumer pass-through) + `skip_if_streaming` + `skip_if_tools_present`. | Behavioural correctness slice; uses `in.Scope.Subject()`, `CanonicalRequest.Tools/Stream`, `CanonicalResponse.ToolCalls/FinishReason`, `resp.Streaming`. |
| **P3** | `Store` factory keyed by `vector_store` + `in_memory` backend (TTL eviction) + DI wiring in `plugins.go`. | `redis` stays default; factory makes backend pluggable. |
| **P4** | `mode` `exact`/`both` (deterministic hashed last-user-message match + semantic fallback + dual store). | Adds a non-embedding lookup path; larger logic slice. |
| **P5** | `pgvector` backend (new infra store) + DB migration (vector extension + table/index). | Heaviest; isolated so the migration ships alone. |

If any slice approaches the budget, split P1 (config vs catalog) or P4
(`exact` vs `both`) further.

## Affected areas

| Area | Impact | Description |
|---|---|---|
| `pkg/infra/plugins/semanticcache/config.go` | Modified | New fields, back-compat aliasing, optional `api_key`, defaults, `validate()`. |
| `pkg/infra/plugins/semanticcache/plugin.go` | Modified | Partition from `in.Scope`+registry; bypass/streaming/tools gates; `X-Cache` header; status-gated store; mode dispatch. |
| `pkg/infra/plugins/semanticcache/data.go` | Modified | Trace extras for scope/mode/store/bypass/skip reasons. |
| `pkg/infra/cache/semantic/store.go` (+ new files) | New/Modified | `Store` factory; `in_memory` + `pgvector` implementations alongside `RedisStore`. |
| `pkg/container/modules/plugins.go` | Modified | Build the store via factory keyed by config; wire into `semanticcache.New`. |
| `pkg/app/plugins/catalog_metadata.go` (+ `catalog_test.go`) | Modified | Expand `semantic_cache` `SettingsSchema` (use `pertoolratelimit` `scope` enum precedent). |
| `pkg/infra/database/migrations/` | New (P5) | pgvector extension + vector table/index migration. |
| `tests/functional/` | New | End-to-end HIT/MISS, bypass, consumer-isolation, streaming-skip, tools-skip. |

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| **Cross-consumer leakage** — a consumer served another consumer's cached body. | High | `consumer` is default; partition by `ConsumerID`; **empty ConsumerID degrades to pass-through**; registry-namespaced keys; functional isolation test. |
| **Streaming replay incorrectness** — replayed raw SSE buffer is not a clean response. | Med | Documented limitation; `skip_if_streaming:true` opt-out; default `false` preserves today's behaviour, not worse. |
| **Back-compat regression** for existing `ttl`/nested-embedding configs. | Med | Legacy fields kept as aliases with precedence rules; table-driven config tests cover legacy-only, new-only, and both-set. |
| **Hard failure on missing credentials** breaking traffic. | Med | `api_key` optional; embedding/infra errors degrade to pass-through (never fail the request) — preserves current pass-through-on-error contract. |
| **pgvector migration** failure / extension unavailable. | Low | Isolated final phase; migration shipped alone; backend selected only when `vector_store: pgvector`. |
| **Catalog drift** between schema and plugin fields. | Low | `catalog_test.go` asserts the schema; update with each phase. |

## Capabilities

### New Capabilities

- None at the openspec spec level — `semantic_cache` is an existing plugin;
  behaviour is documented in this change's `spec.md`.

### Modified Capabilities

- None.

## Test strategy

Table-driven unit tests next to the code, `go test -race ./...`:

- **Config** — legacy-only (`ttl`, nested embedding), new-only (`ttl_seconds`,
  flattened embedding), both-set precedence; defaults; optional `api_key`;
  enum/range validation.
- **Partitioning** — consumer vs global key derivation; empty-ConsumerID
  pass-through; registry namespacing prevents cross-upstream collision.
- **Gates** — `bypass_header` present/absent; `cache_only_on_status` allows/blocks
  store; `skip_if_streaming` true/false; `skip_if_tools_present` true/false across
  request-`Tools` and response-`ToolCalls`/`FinishReason=="tool_calls"`.
- **Headers** — `X-Cache: HIT` on hit, `X-Cache: MISS` on forwarded miss;
  back-compat `X-Cache-Status`/`X-Cache-Similarity` preserved.
- **Store factory** — `redis` / `in_memory` selection; `in_memory` TTL eviction;
  `pgvector` against a test DB (P5).
- **Mode** — `exact` hash hit/miss; `semantic` similarity threshold;
  `both` exact-first-then-semantic with dual store (P4).
- **Degradation** — embedding/infra error ⇒ pass-through, request never fails.
- **Functional** — end-to-end HIT/MISS, bypass, consumer isolation, streaming and
  tools skip.

## Rollback plan

Additive and reversible. Each chained PR reverts independently. New config fields
default to today's behaviour (`scope:consumer` is the only behavioural default
change — guarded by empty-consumer pass-through). The store factory defaults to
`redis`; removing the `in_memory`/`pgvector` branches and the new fields restores
the prior plugin. P5's pgvector migration is the only stateful change and ships
isolated, so it can be reverted on its own (and is inert unless
`vector_store: pgvector` is configured).

## Success criteria

- [ ] All RUN-699 config fields are accepted, validated, and documented; every
      legacy field still works with defined precedence.
- [ ] Cache partitions by consumer (default) or gateway, registry-namespaced;
      empty consumer ⇒ pass-through (no cross-consumer leakage).
- [ ] `X-Cache: HIT` on cache hits and `X-Cache: MISS` on forwarded misses, with
      legacy headers preserved.
- [ ] `bypass_header`, `cache_only_on_status`, `skip_if_streaming`,
      `skip_if_tools_present` behave per spec.
- [ ] Missing/invalid embedding credentials degrade to pass-through; the request
      never fails.
- [ ] `vector_store` selects `redis` / `in_memory` / `pgvector` via the factory.
- [ ] `mode` supports `exact` / `semantic` / `both`.
- [ ] Catalog metadata reflects the full schema; `go test -race ./...` green.
