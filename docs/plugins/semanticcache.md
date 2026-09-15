# `semanticcache` — Embedding-Based Response Cache

Catalog slug: `semantic_cache`

Serves cached responses for semantically similar requests. `pre_request`
does the lookup; `post_response` stores successful upstream responses for
future hits. The cache partition is scoped per registry plus the configured
`scope`.

Source:

- `pkg/infra/plugins/semanticcache/config.go`
- `pkg/infra/plugins/semanticcache/plugin.go`
- `docs/policies.json` (`Routing` → `semantic_cache`)

Stages: `pre_request` + `post_response` (both mandatory).
Protocols: `LLM` only.
Modes: `enforce`, `observe`.

## Configuration fields

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `similarity_threshold` | number | no | `0.85` | Cosine similarity in `(0, 1]` required to serve a hit. |
| `ttl` | string (Go duration) | no | `24h` (resolved) | How long entries stay valid, e.g. `10m`, `24h`. Ignored when `ttl_seconds > 0`. |
| `ttl_seconds` | integer `>= 0` | no | `0` (unset) | TTL in seconds; wins over `ttl`. Resolved default is `86400` (24h). |
| `scope` | enum `consumer` \| `global` | no | `consumer` | Cache isolation scope (combined with the registry partition). |
| `mode` | enum `exact` \| `semantic` \| `both` | no | `semantic` | `exact` never needs embeddings; `semantic`/`both` vectorize the request. |
| `vector_store` | enum `redis` \| `pgvector` \| `in_memory` | no | `redis` | Where vectors + payloads are stored. |
| `embedding_provider` | string | no | `openai` | Flattened provider; wins over `embedding.provider`. |
| `embedding_model` | string | no | `text-embedding-ada-002` | Flattened model; wins over `embedding.model`. |
| `embedding` | object `{provider, model, api_key}` | effectively required for semantic modes | provider `openai`, model `text-embedding-ada-002` | Nested embedding config. `api_key` is the provider credential. Missing keys are valid at parse time but semantic lookup degrades at runtime. |
| `cache_only_on_status` | array of integers | no | `[200-299]` | Only these upstream statuses are stored/served. Empty means `200 <= code < 300`. |
| `bypass_header` | string | no | `X-Cache-Bypass` | Any request carrying this header bypasses lookup + store. |
| `skip_if_tools_present` | boolean | no | `true` | When `true`, requests/responses with tools skip the cache. Set `false` to cache tool traffic. |
| `skip_if_streaming` | boolean | no | `false` | When `true`, streaming requests bypass the cache. |

## Example JSON

Policy `settings` object:

```json
{
  "similarity_threshold": 0.85,
  "ttl": "10m",
  "embedding": {
    "provider": "openai",
    "model": "text-embedding-ada-002",
    "api_key": "sk-..."
  }
}
```

TTL in seconds with explicit scope/mode/store:

```json
{
  "similarity_threshold": 0.9,
  "ttl_seconds": 3600,
  "scope": "consumer",
  "mode": "semantic",
  "vector_store": "redis",
  "embedding_provider": "openai",
  "embedding_model": "text-embedding-ada-002",
  "bypass_header": "X-Cache-Bypass",
  "skip_if_tools_present": true,
  "skip_if_streaming": false
}
```

Full policy object (Admin API):

```json
{
  "name": "semantic-cache",
  "slug": "semantic_cache",
  "enabled": true,
  "priority": 10,
  "parallel": false,
  "stages": ["pre_request", "post_response"],
  "settings": {
    "similarity_threshold": 0.85,
    "ttl": "10m",
    "embedding": {
      "provider": "openai",
      "model": "text-embedding-ada-002",
      "api_key": "sk-..."
    }
  }
}
```

Requires a vector store (default `redis`, i.e. Redis Stack with RediSearch
for `make up`) and a valid embedding API key.

## Behavior

- Hit: served without contacting upstream with `X-Cache: HIT`,
  `X-Cache-Status: HIT`, and (semantic hits) `X-Cache-Similarity: 0.9700`.
  Exact hits omit the similarity header. Miss: `X-Cache: MISS` /
  `X-Cache-Status: MISS`, forwarded upstream and stored async on
  `post_response` when the status is cacheable.
- Bypass: `Cache-Control: no-cache`-style `noCache` requests, any request
  with the `bypass_header`, `skip_if_streaming` streams, and (by default)
  tool traffic all pass through without lookup/store.
- Fail-open (degraded, never blocks): missing partition, unavailable vector
  index or embedding service, and non-cacheable statuses pass through so a
  cache outage does not take down LLM traffic.
