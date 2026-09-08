---
linear: ENG-1514
type: fix
changelog: "The no-registry-serves-model error now names every registry bound to the consumer with the reason it was ruled out, and no longer relays one upstream provider's model_not_found text."
---

# Proposal: The no-registry-serves-model error owns the failure

## Why

On a consumer bound to an Anthropic registry restricted to `claude-haiku-*` plus an OpenAI
registry with no allow-list, a `claude-sonnet-*` request answered `404 model_not_supported`
with OpenAI's own `model_not_found` text appended. The reader debugs OpenAI, which is the
exact failure mode ENG-1433 set out to remove.

Two gaps in `noRegistryServesModelError`:

1. It appended the last probed body's message, re-attributing a gateway verdict to one provider.
2. It listed only the registries actually probed. Anthropic was dropped by its own allow-list
   inside `resolveShortModel` and never appeared, so an operator staring at two bound registries
   could not tell why one was missing.

## What

The error now recomputes, per registry bound to the consumer, why it was ruled out:

```
404 model_not_supported
routing: no registry serves the requested model: "claude-sonnet-4-5"
(Anthropic: restricted by its model allow-list; OpenAI: not in the provider catalog)
```

- New `pkg/app/proxy/model_exclusions.go`. `noRegistryServesModelError` becomes a `*forwarder`
  method; `chainProviders` and `adapter.ProviderErrorMessage` are deleted with the old shape.
- Reasons come from the resolver's own predicates, not a second implementation of the matching
  rule: a throwaway `routingdomain.Candidate` carries the consumer's allow-list to
  `PolicyAllowsModel` and `DefersModelChoice`. No domain change, no `approuting.Resolver`
  signature change, no mock regeneration.
- The catalog reason is claimed only for registries the catalog filter could see
  (`DefersModelChoice()`), and the allow-list reason is gated on the requested ref not being a
  glob, since `PolicyAllowsModel` returns false for both.
- Exclusions are re-derived per registry, never inferred by set difference: the lenient rule
  restores the pre-filter candidate set when the catalog empties it, so a registry the catalog
  ruled out is back in the set by the time the error is built.
- Both `rc.Registries` and `rc.FallbackBackends` are walked, deduped by registry id, because
  `resolveInline` builds candidates from both.
- When no reason is concrete the message lists bare labels instead of repeating an empty
  explanation, and the fallback wording claims only ineligibility — a capability filter can drop
  a registry before it is ever considered.

Out of scope: the lenient fallback itself (an ENG-1433 trade-off that keeps a stale catalog from
being the sole cause of a failure) and ENG-1464 AC#2.

## QA

- `go test ./pkg/...`, `go test -race ./pkg/...`, `golangci-lint run ./...`
- `make test-functional` — `TestRoutingIntent_SequentialChainHardening` reproduces the reported
  configuration end to end and asserts each registry is named with its own reason, that no
  provider text reaches the client, and that the restricted registry is never contacted
- Two assertions added in ENG-1433's review round encoded the opposite contract and are inverted
  rather than deleted, so the regression cannot return silently
