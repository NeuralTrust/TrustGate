# Spec for Semantic Cache (semantic_cache plugin) — RUN-699

Extends the existing `semantic_cache` plugin (`pkg/infra/plugins/semanticcache`)
to the RUN-699 config contract while preserving every legacy field and behaviour.
The plugin returns cached responses for matching prompts to cut upstream
cost/latency. The cache key is the normalized last user message only (history,
system prompt, and request params are intentionally ignored — see proposal
non-goals). Every cache/embedding/infra failure MUST degrade to pass-through:
the cache no-ops and the request is never failed.

## ADDED Requirements

### Requirement: Config parsing and back-compat precedence

The plugin MUST accept the full RUN-699 config surface and MUST keep every legacy
field working with defined precedence. `ttl_seconds` (int seconds) MUST be
adopted and the legacy `ttl` (duration string) MUST remain a back-compat alias;
when both are set `ttl_seconds` MUST win. Flattened `embedding_provider` /
`embedding_model` MUST be adopted and the nested `embedding{provider,model,api_key}`
MUST remain a back-compat alias; when both are set the flattened fields MUST win.
Defaults MUST be: `scope=consumer`, `mode=semantic`, `similarity_threshold=0.95`,
`vector_store=redis`, `cache_only_on_status=[200]`, `bypass_header=X-Cache-Bypass`,
`skip_if_tools_present=true`, `skip_if_streaming=false`.

#### Scenario: Legacy-only config still works
- GIVEN a config with only `ttl:"1h"` and nested `embedding{provider,model}`
- WHEN the config is parsed
- THEN the effective TTL MUST be 3600s and the effective provider/model MUST come from the nested block

#### Scenario: New fields override legacy aliases
- GIVEN both `ttl_seconds:3600` and `ttl:"1h"`, and both flattened and nested embedding fields with different values
- WHEN the config is parsed
- THEN `ttl_seconds` MUST win for TTL and the flattened `embedding_provider`/`embedding_model` MUST win

#### Scenario: Defaults applied when fields omitted
- GIVEN a config that omits `scope`, `mode`, `vector_store`, `bypass_header`, `cache_only_on_status`, and the skip flags
- WHEN the config is parsed
- THEN the documented defaults MUST be applied

### Requirement: Configuration validation

`similarity_threshold` MUST be within `(0,1]`. `scope` MUST be one of
`{consumer, global}`, `mode` one of `{exact, semantic, both}`, and `vector_store`
one of `{redis, pgvector, in_memory}`. The embedding `api_key` MUST be OPTIONAL;
its absence MUST NOT fail validation.

#### Scenario: Invalid enum or range rejected
- GIVEN a config with `similarity_threshold:1.5`, or an unknown `scope`/`mode`/`vector_store`
- WHEN the config is validated
- THEN validation MUST fail for that configuration

#### Scenario: Missing api_key accepted
- GIVEN a config with no embedding `api_key`
- WHEN the config is validated
- THEN validation MUST succeed

### Requirement: Scope partitioning

The cache partition MUST be derived from `in.Scope` plus the registry id, and is
authoritative for the partition ONLY (independent of policy `Global`/`RuntimeScope`
composition). `consumer` MUST partition by `ConsumerID`; `global` MUST partition
by `GatewayID`. The partition MUST always be namespaced by registry id so
identical prompts to different upstreams never collide.

#### Scenario: Consumer scope isolates consumers
- GIVEN `scope:consumer` and two requests with the same prompt from different `ConsumerID`s
- WHEN the cache is consulted
- THEN each consumer MUST get its own partition and MUST NOT receive the other's cached body

#### Scenario: Empty consumer degrades to pass-through
- GIVEN `scope:consumer` and a request whose `ConsumerID` is empty
- WHEN the plugin runs
- THEN the cache MUST be bypassed (no lookup, no store) and the request MUST be forwarded normally

#### Scenario: Global scope partitions by gateway
- GIVEN `scope:global` and two requests with the same prompt under the same `GatewayID`
- WHEN the cache is consulted
- THEN they MUST share the same gateway/registry-namespaced partition

### Requirement: Bypass header gate

When the request carries the configured `bypass_header` (with any value), the
plugin MUST bypass the cache entirely (no lookup, no store). The existing
`Cache-Control: no-cache` bypass MUST also continue to work.

#### Scenario: Bypass header present
- GIVEN a request carrying `X-Cache-Bypass: 1`
- WHEN the plugin runs
- THEN no lookup or store MUST occur and the request MUST be forwarded

#### Scenario: Cache-Control no-cache still bypasses
- GIVEN a request carrying `Cache-Control: no-cache`
- WHEN the plugin runs
- THEN the cache MUST be bypassed as before

### Requirement: Skip-if-streaming gate

When `skip_if_streaming:true` and the request is a streaming request, the plugin
MUST bypass the cache entirely and streamed responses MUST never be stored. When
`skip_if_streaming:false` (default), streaming requests MUST keep today's
behaviour.

#### Scenario: Streaming skipped when enabled
- GIVEN `skip_if_streaming:true` and a request with `stream=true`
- WHEN the plugin runs
- THEN no lookup or store MUST occur

#### Scenario: Streaming cached when disabled
- GIVEN `skip_if_streaming:false` and a streaming request
- WHEN the plugin runs
- THEN the cache MUST behave as it does today (streamed bytes may be buffered and stored)

### Requirement: Skip-if-tools-present gate

When `skip_if_tools_present:true` (default), the plugin MUST NOT serve a cache hit
if the request declares tools, and MUST NOT store if the request declares tools OR
the response carries tool calls (`ToolCalls` / `FinishReason == "tool_calls"`).

#### Scenario: Hit not served for tool request
- GIVEN `skip_if_tools_present:true` and a request declaring tools that matches a cached entry
- WHEN the plugin runs
- THEN the cached hit MUST NOT be served and the request MUST be forwarded

#### Scenario: Tool-call response not stored
- GIVEN `skip_if_tools_present:true` and a response carrying tool calls
- WHEN the response leg runs
- THEN the response MUST NOT be stored

### Requirement: Cache-only-on-status gate

`cache_only_on_status` (default `[200]`) MUST gate STORING only. A response whose
status is not in the list MUST NOT be stored; lookup and serving are unaffected.

#### Scenario: Non-listed status not stored
- GIVEN `cache_only_on_status:[200]` and an upstream `500` response
- WHEN the response leg runs
- THEN the response MUST NOT be stored

#### Scenario: Listed status stored
- GIVEN `cache_only_on_status:[200]` and an upstream `200` response
- WHEN the response leg runs
- THEN the response MUST be eligible for storing (subject to other gates)

### Requirement: Mode behaviours

`mode` MUST select the lookup strategy. `exact` MUST match a deterministic hash of
the normalized last user message under the scope partition (no embedding).
`semantic` MUST use embedding similarity against `similarity_threshold` (current
behaviour). `both` MUST attempt an exact lookup first and fall back to semantic,
and on store MUST write under both the exact and semantic keys.

#### Scenario: Exact mode deterministic match
- GIVEN `mode:exact` and a request whose normalized last user message equals a stored entry's
- WHEN the cache is consulted
- THEN a hit MUST be returned without computing an embedding

#### Scenario: Semantic mode threshold
- GIVEN `mode:semantic`, `similarity_threshold:0.95`, and a stored entry with similarity 0.97
- WHEN the cache is consulted
- THEN a hit MUST be returned; an entry at similarity 0.90 MUST be a miss

#### Scenario: Both mode exact-first then semantic
- GIVEN `mode:both` and no exact match but a semantically similar stored entry above threshold
- WHEN the cache is consulted
- THEN the exact lookup MUST miss, the semantic fallback MUST hit, and a store MUST write both keys

### Requirement: Vector store selection

The backend MUST be selected by `vector_store` via a Store factory: `redis`
(default), `in_memory` (TTL eviction), or `pgvector`. The selected store MUST be
used for all lookups and stores; `redis` MUST remain the default.

#### Scenario: In-memory backend selected
- GIVEN `vector_store:in_memory`
- WHEN the plugin builds its store
- THEN the in-memory backend MUST be used and entries MUST expire per TTL

#### Scenario: Default redis backend
- GIVEN a config omitting `vector_store`
- WHEN the plugin builds its store
- THEN the redis backend MUST be used

### Requirement: X-Cache response headers

On a cache hit the forwarded response MUST carry the literal header
`X-Cache: HIT`; on a forwarded miss it MUST carry `X-Cache: MISS`. The existing
`X-Cache-Status` and `X-Cache-Similarity` headers MUST be preserved for
back-compat.

#### Scenario: HIT header on cache hit
- GIVEN a request that matches a cached entry
- WHEN the cached response is served
- THEN it MUST include `X-Cache: HIT` plus the legacy `X-Cache-Status`/`X-Cache-Similarity` headers

#### Scenario: MISS header on forwarded miss
- GIVEN a request with no matching cached entry
- WHEN the response is forwarded from upstream
- THEN it MUST include `X-Cache: MISS`

### Requirement: Degraded pass-through on failure

Any cache, embedding, or infra failure (including missing/invalid embedding
credentials) MUST degrade to pass-through: the cache no-ops and the request MUST
NOT fail.

#### Scenario: Missing credentials degrade gracefully
- GIVEN `mode:semantic` and missing/invalid embedding credentials
- WHEN the plugin runs
- THEN no embedding lookup or store MUST occur and the request MUST be forwarded successfully

#### Scenario: Store outage degrades gracefully
- GIVEN the configured vector store is unreachable
- WHEN the plugin runs
- THEN lookup/store MUST be skipped and the request MUST be forwarded successfully (forwarded response carrying `X-Cache: MISS`)
