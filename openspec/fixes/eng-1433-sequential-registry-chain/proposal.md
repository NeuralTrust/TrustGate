---
linear: ENG-1433
type: fix
changelog: "Resolve an unqualified model name by walking the consumer's registry chain in configured order and routing to the first registry whose provider serves it, instead of pinning the first registry and relaying its model_not_found."
---

# Proposal: Sequential registry chain for unqualified model names

## Why

A consumer bound to several registries with no model policies misroutes every unqualified
model name. Candidate eligibility was decided solely by the consumer's allow-list, and a
nil allow-list allowed every model, so the first registry captured models its provider
cannot serve. `routeBackend` then pinned that first candidate, so no other registry was
tried and the client received one provider's `model_not_found` — attributing the failure
to the wrong system.

Detected in Santander PRE-EU (v2.11.11) with OpenAI + Google Vertex: `gemini-3-flash-preview`
returned OpenAI's `model_not_found`. It affects the standard shape of the Santander use
cases (Maisa, Noxus), and Noxus cannot inject the `@provider/` prefix workaround.

## What

- Split the two questions the allow-list was answering: `Candidate.PolicyAllowsModel`
  keeps operator policy, `Candidate.DefersModelChoice` reports that no allow-list
  constrains the candidate.
- Add `appcatalog.ModelAvailability`, a TTL-cached, singleflight-guarded verdict
  (`Serves` / `Absent` / `Unknown`) over the provider's catalog listing. Azure
  deployment names, OpenAI-compatible endpoints, Bedrock ARNs, an empty listing and a
  repository error all yield `Unknown`. `openai_compatible` never inherits OpenAI's
  listing.
- Narrow candidates by that verdict in `resolveRouting`, beside the existing capability
  and files-id filters. Only a verified `Absent` drops a candidate; if the filter empties
  the chain it is ignored, so a stale catalog can never be the sole reason a request fails.
- Walk the chain: an unqualified model no longer pins `candidates[0]`. It takes the first
  link and advances to the next on a provider `model_not_found`, in the consumer's
  configured order. `lb` stays nil, so the chain is deterministic and never load-balanced.
- `@provider/model` keeps pinning with no load balancing and no fallback.
- New `routingdomain.ErrNoRegistryServesModel`, surfaced as `404 model_not_supported`
  naming the requested model, the probed providers and the last provider's own message,
  replacing the relayed provider error. Drops the unused `ErrAmbiguousModel`.
- The fallback attempt budget no longer truncates the chain walk: it bounds failover
  retries, not registry selection. The total-latency bound still applies, so a slow chain
  cannot hold a request open indefinitely.
- The catalog syncer invalidates the availability cache so a sync is visible to routing
  without waiting out the TTL.

Behaviour change to note: `trace.LLMAttrs.Pinned` is now `false` for unqualified models.

## QA

- `go test ./pkg/...` and `go test -race ./pkg/...`
- `golangci-lint run ./...`
- `make test-functional` — `TestRoutingIntent_SequentialChain` covers the reproduction
  (fall-through to the registry that serves the model, catalog-verified skip with no
  upstream call, `404 model_not_supported` when nobody serves it, qualified pin intact,
  no load balancing)
