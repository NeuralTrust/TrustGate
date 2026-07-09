---
linear: RUN-925
type: feat
changelog: "Add Cohere LLM provider with native v2 chat, embeddings, and rerank proxy routes."
---

# Proposal: Cohere LLM provider (RUN-925)

## Why

TrustGate needs first-class Cohere support so gateways can route native Cohere v2 chat, OpenAI-shaped embeddings, and rerank traffic through a single provider integration with catalog seeding for App v2.

## What changes

- **Provider client** (`pkg/infra/providers/cohere/`): sync chat, embeddings, rerank, and connection test against Cohere API.
- **Adapters** (`pkg/infra/providers/adapter/cohere_*.go`): Cohere v2 chat, OpenAI embeddings ↔ Cohere embed, and rerank wire formats.
- **Proxy routing** (`pkg/api/resolver/proxy_path_resolver.go`): `/v2/chat`, `/v1/embeddings`, `/v1/rerank` fixed routes with capability metadata.
- **Provider invoker** (`pkg/app/proxy/provider.go`): capability-aware prepare/invoke for chat, embeddings, and rerank.
- **Factory** (`pkg/infra/providers/factory/locator.go`): register `cohere.NewCohereClient()`.
- **Catalog** (`pkg/app/catalog/sync.go`): seed Cohere provider and manual model rows with capabilities.

## Behavior

| Route | Source format | Cohere upstream |
|-------|---------------|-----------------|
| `/{slug}/v2/chat` | Cohere v2 chat | `POST /v2/chat` |
| `/{slug}/v1/chat/completions` | OpenAI (cross-format) | `POST /v2/chat` |
| `/{slug}/v1/embeddings` | OpenAI embeddings | `POST /v2/embed` |
| `/{slug}/v1/rerank` | Cohere rerank | `POST /v2/rerank` |

## Out of scope

- App v2 registry UI for Cohere model capabilities (separate app repo ticket).

## QA checklist

- [ ] `go test ./pkg/infra/providers/... ./pkg/infra/providers/adapter/... ./pkg/api/resolver/... ./pkg/app/proxy/...`
- [ ] `go test -tags=functional ./tests/functional/... -run CohereProvider`
- [ ] Catalog sync exposes Cohere provider and seeded models with capabilities
