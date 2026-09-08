---
linear: ENG-1514
type: fix
changelog: "The no-registry-serves-model error now names every registry bound to the consumer with the reason it was ruled out, and no longer relays one upstream provider's model_not_found text."
---

# Proposal: The no-registry-serves-model error owns the failure

## Why

On a consumer bound to an Anthropic registry restricted to `claude-haiku-*` plus an OpenAI
registry with no allow-list, a `claude-sonnet-*` request answers `404 model_not_supported`
with OpenAI's own `model_not_found` text appended. The reader debugs OpenAI, which is the
exact failure mode ENG-1433 set out to remove.

Two gaps, both in `noRegistryServesModelError` (`pkg/app/proxy/routing.go:367-378`):

1. It appends `": last provider response: <text>"` from `adapter.ProviderErrorMessage` on the
   last probed body, re-attributing a gateway-level verdict to one provider.
2. It renders `(tried <providers>)` from `chainProviders(chain)` — only the registries actually
   probed. Anthropic was dropped by its own allow-list inside `resolveShortModel` and never
   appears, so an operator staring at two bound registries cannot tell why one is missing.

Trace for the reported config: Anthropic is dropped by the allow-list; OpenAI is dropped by
`filterCandidatesByProviderListing` (`VerdictAbsent`); the chain empties, so the lenient rule
restores it; OpenAI is probed and answers `model_not_found`.

## What

Recompute the per-registry exclusion reasons in the app layer at error-construction time and
render them in place of the probed-provider list. Drop the provider tail.

### Approach and its constraints

- **App layer only.** No change to `pkg/domain/routing`, no change to the `approuting.Resolver`
  interface, no mock regeneration, no edits to the 13 `ResolveIntent` call sites. Every runtime
  classification enum in this repo already lives in `pkg/app` as `type X int` (`appproxy.Outcome`,
  `failureKind`, `appcatalog.Verdict`); `pkg/domain` has no precedent for one, and half the
  vocabulary (catalog absence) is an app fact the domain cannot name.
- **Re-ask the catalog, do not thread state.** `f.listing.Lists` is a `cache.TTLMap` +
  `singleflight` lookup per provider — the second call is an in-memory read. Threading exclusion
  state through `routedBackend` and `forwardRequestDTO` buys nothing.
- **Never infer from `dto.candidates`.** `filterCandidatesByProviderListing` (`routing.go:117-120`)
  restores the pre-filter set when the catalog rules everything out, so OpenAI is back in the set
  at error time. Every reason is re-derived per registry from `rc`.
- **One entry per registry, not per provider.** `chainProviders` dedupes by provider code; two
  registries on one provider with different allow-lists would collapse into one entry or emit
  contradictory reasons under one label. Entries are keyed by registry ID and labelled by
  `Registry.Name` (required by `Registry.Validate`), falling back to the provider code.
- **Sound for this call site only.** `routeBackend` returns early for `isRoleBased` with no
  `chain`, so `sequential` is false and this error never fires for role-based consumers; pool
  aliases are not short models. The chain exists only for inline consumers with a short model,
  where `resolveInline` builds candidates from `rc.Registries` + `rc.FallbackBackends` — so
  walking those two slices is exactly the candidate origin and needs no role or pool branch.

### New file: `pkg/app/proxy/model_exclusions.go`

Apache header only, no comments (`.agents/AGENT.md` §11.1). One responsibility per file (§10.2).

```go
type exclusionReason int

const (
	exclusionUnexplained exclusionReason = iota
	exclusionAllowList
	exclusionCatalogAbsent
)

func (r exclusionReason) String() string

type registryExclusion struct {
	label  string
	reason exclusionReason
}

func (f *forwarder) modelExclusions(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	model string,
) []registryExclusion

func (f *forwarder) exclusionReasonFor(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *domain.Registry,
	model string,
) exclusionReason

func registryLabel(reg *domain.Registry) string

func renderExclusions(exclusions []registryExclusion) string
```

`exclusionReason.String()`:

| Constant | Rendered |
|---|---|
| `exclusionAllowList` | `restricted by its model allow-list` |
| `exclusionCatalogAbsent` | `not in the provider catalog` |
| `exclusionUnexplained` | `considered and did not serve it` |

The third is not decoration. `filterCandidatesByCapability` / `filterCandidatesByFilesID`
(`routing.go:151-174`) can thin the set on an embeddings or files short-model request, and a
registry that was probed and answered `model_not_found` under an unknown catalog verdict has no
policy or catalog reason either. The wording claims only what was verified: the registry was in
the candidate origin, and the model was not served. It does not name a cause.

`modelExclusions` walks `rc.Registries` then `rc.FallbackBackends` in order, skipping nil
registries, registries already seen by `ids.RegistryID`, and registries whose label is empty.
Both slices are walked because both feed `resolveInline`; dropping fallback backends would
silently omit a bound registry from an error whose whole point is completeness.

`exclusionReasonFor` reuses the domain predicates rather than re-implementing the matching rule:

```go
policy, _ := rc.Consumer.ModelPolicies.For(reg.ID)
candidate := routingdomain.Candidate{Allowed: policy.Allowed}
if !candidate.DefersModelChoice() {
	if !modelmatch.IsPattern(model) && !candidate.PolicyAllowsModel(model) {
		return exclusionAllowList
	}
	return exclusionUnexplained
}
if f.listing != nil && f.listing.Lists(ctx, reg.Provider(), model) == appcatalog.VerdictAbsent {
	return exclusionCatalogAbsent
}
return exclusionUnexplained
```

Three things this shape is buying:

- **No policy row, or a row whose `Allowed` is nil, is the "all models" case.**
  `ModelPolicies.For` returns a zero `ModelPolicy` when absent, so `Candidate{Allowed: nil}` and
  `DefersModelChoice()` express both cases with the resolver's own predicate. A row with an empty
  non-nil `Allowed` (`"allowed": []` on the wire) stays an allow-list, matching `inlineCandidate`.
- **The catalog reason is only claimed for registries the catalog filter could actually see.**
  `filterCandidatesByProviderListing` skips any candidate where `!c.DefersModelChoice()`, so a
  registry with a matching allow-list is never dropped by the catalog and must never be labelled
  that way.
- **The pattern guard.** `PolicyAllowsModel` returns false both when the allow-list misses and
  when the *requested ref itself* is a glob (`candidate.go:35-37`, via `modelmatch.IsPattern`).
  A pattern ref is denied for every candidate and 403s as `ErrModelDenied` long before this error,
  but the recompute must not be able to label it "restricted by its model allow-list" — so the
  allow-list reason is gated on `!modelmatch.IsPattern(model)`.

### Changed: `noRegistryServesModelError` becomes a method

It needs `f.listing` and `rc`. Both are in scope at the single call site
(`forwarder.go:289`, inside `invokeWithFailover`). It becomes a method on `*forwarder`, not a
free function taking a `appcatalog.ModelListing` parameter: every other catalog-aware helper in
this package is already a method (`filterCandidatesByProviderListing`, `logSkippedRegistry`), and
a listing parameter would decouple nothing while widening the signature.

```go
func (f *forwarder) noRegistryServesModelError(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	model string,
) error
```

Body: `%w: %q` when there are no exclusions to render, `%w: %q (%s)` otherwise. The `chain` and
`last failoverState` parameters go away; `chainProviders` (`routing.go:380-395`) becomes dead and
is deleted with it. Call site:

```go
return nil, f.noRegistryServesModelError(ctx, rc, dto.request.RequestedModel)
```

The `routingdomain.ErrNoRegistryServesModel` sentinel is left alone — it lives in
`pkg/domain/routing/errors.go` and all its siblings carry the `routing:` prefix. Its text already
says the gateway owns the verdict; the ticket's target wording differs only in that prefix.

### Rendered output

Reported config — registries named `Anthropic` (allow-list `claude-haiku-*`) and `OpenAI`
(no allow-list), requesting `claude-sonnet-4-5`:

```
HTTP 404
{
  "error": "model_not_supported",
  "message": "routing: no registry serves the requested model: \"claude-sonnet-4-5\" (Anthropic: restricted by its model allow-list; OpenAI: not in the provider catalog)"
}
```

One registry, no allow-list, catalog verdict unknown, probed and answered `model_not_found`:

```
HTTP 404
{
  "error": "model_not_supported",
  "message": "routing: no registry serves the requested model: \"nope-9\" (registry-openai: considered and did not serve it)"
}
```

`httpio.ErrorBody` carries only `Error` and `Message`
(`pkg/api/handler/http/httpio/errors.go:30-33`), so the reason list is a flat parenthesised,
semicolon-separated tail on one line — no new wire field.

### File changes

| File | Action | What changes |
|---|---|---|
| `pkg/app/proxy/model_exclusions.go` | Create | `exclusionReason` enum + `String()`, `registryExclusion`, `modelExclusions`, `exclusionReasonFor`, `registryLabel`, `renderExclusions` |
| `pkg/app/proxy/routing.go` | Modify | `noRegistryServesModelError` becomes a `*forwarder` method taking `(ctx, rc, model)`; provider tail deleted; `chainProviders` deleted |
| `pkg/app/proxy/forwarder.go` | Modify | Call site at `:289` passes `ctx, rc, dto.request.RequestedModel` |
| `pkg/app/proxy/model_exclusions_test.go` | Create | Table test over the three reasons, the pattern-ref guard, the empty-`Allowed` case, dedup across `Registries` + `FallbackBackends`, and the name→provider label fallback |
| `pkg/app/proxy/forwarder_test.go` | Modify | `backendFor` sets `Name: "registry-" + provider` so two fixtures no longer share the label `test-backend` |
| `pkg/app/proxy/routing_sequential_test.go` | Modify | Invert `…KeepsTheProviderDetail`; retarget `…NoRegistryServesTheModel`; add the two-registry reported-shape fixture |
| `pkg/api/handler/http/proxy/proxy_handler_test.go` | Modify | `TestHandle_NoRegistryServesModelReturns404ModelNotSupported` hand-builds `"%w: %q (tried openai, vertex)"` at `:645-646` — rebuild it in the new shape |
| `tests/functional/routing_intent_test.go` | Modify | Invert `the gateway error carries the provider's own diagnosis`; add the reported two-registry subtest |

### Tests

Two assertions added in ENG-1433's review round now encode the opposite of the requirement.
**Invert them, do not delete** — a deleted test lets the regression come back silently.

- `TestForward_SequentialChain_NoRegistryServesTheModelKeepsTheProviderDetail`
  (`routing_sequential_test.go:378-398`) → rename to
  `…NoRegistryServesTheModelDropsTheProviderDetail`; keep the `newModelNotFoundUpstream`-shaped
  invoker and flip `assert.Contains(err, "do not have access")` to `assert.NotContains`, with the
  message asserting the gateway's own verdict is what surfaces.
- `the gateway error carries the provider's own diagnosis`
  (`tests/functional/routing_intent_test.go:671-684`) → rename to
  `the gateway error carries no provider's own diagnosis`; flip the `do not have access`
  assertion to `NotContains` and assert the registry name appears with a reason.

Retargeted:

- `TestForward_SequentialChain_NoRegistryServesTheModel` (`routing_sequential_test.go:173-197`) —
  the `Contains "openai"` / `Contains "vertex"` assertions survive unchanged once `backendFor`
  names registries `registry-<provider>`; add an assertion that neither `tried` nor the provider
  body text is present.
- `TestHandle_NoRegistryServesModelReturns404ModelNotSupported` (`proxy_handler_test.go:641-676`) —
  the stub error becomes
  `fmt.Errorf("%w: %q (Anthropic: restricted by its model allow-list; OpenAI: not in the provider catalog)", routingdomain.ErrNoRegistryServesModel, "claude-sonnet-4-5")`,
  and the two `Contains` checks assert both registry labels and both reasons. This is a handler
  mapping test; it pins the status and error code, not the forwarder's construction.

New — the reported shape, which no existing test builds:

- `TestForward_SequentialChain_NoRegistryServesTheModelNamesEveryBoundRegistry`
  (`routing_sequential_test.go`): two registries, `anthropic` with
  `ModelPolicies{anthropicID: {Allowed: []string{"claude-haiku-*"}}}` on the consumer and `openai`
  with none; `stubListing{verdicts: {"openai:claude-sonnet-4-5": appcatalog.VerdictAbsent}}`;
  invoker answers 404 `model_not_found`. Asserts the exact message, that the anthropic upstream
  was never invoked, and that `openai` was invoked exactly once (the lenient re-add).
- `the error names every bound registry and why each was ruled out`
  (`tests/functional/routing_intent_test.go`, in `TestRoutingIntent_SequentialChainHardening`):
  gateway + `anthropicBackendPayload` and `openaiBackendPayload(…, upstream.URL())`, consumer
  bound with `model_policies` `{"allowed": ["claude-haiku-*"]}` on the anthropic binding only,
  request `claude-sonnet-4-5`. Skip via the existing `openaiCatalogListsModel(t, "gpt-4o-mini")`
  guard, since `VerdictAbsent` needs a synced catalog. Asserts 404 `model_not_supported`, both
  registry names present, both reasons present, `do not have access` absent, and zero hits on the
  anthropic side. `setupChain` does not take per-registry policies, so this builds the consumer
  inline the way the `an allow-list that excludes the model removes its registry from the chain`
  subtest already does.

### Line-count forecast

| File | +/- |
|---|---|
| `model_exclusions.go` | +90 |
| `model_exclusions_test.go` | +85 |
| `routing.go` | +10 / -28 |
| `forwarder.go` | +1 / -1 |
| `forwarder_test.go` | +1 / -1 |
| `routing_sequential_test.go` | +65 / -12 |
| `proxy_handler_test.go` | +10 / -8 |
| `tests/functional/routing_intent_test.go` | +45 / -14 |

≈ **371 changed lines** against the 400-line budget. Single PR, no chaining. If it runs over,
`model_exclusions_test.go` is the slice to trim — the functional and sequential tests carry the
requirement.

## Risks

- **`adapter.ProviderErrorMessage` loses its only production caller.** It stays: an exported
  helper in `pkg/infra/providers/adapter` with its own tests, and `unused` does not flag exported
  identifiers. Deleting it is a separate cleanup.
- **A second `f.listing.Lists` call per bound registry on the error path.** TTL-cached and
  single-flighted, and the request has already failed. No new DB or network work. `f.listing` is
  nil in several unit-test forwarders, hence the nil guard.
- **`exclusionUnexplained` is the honest default and will be the common reason** on
  `openai_compatible` chains where no catalog is authoritative. That is a truthful downgrade from
  today's confidently-wrong provider attribution, not a regression.
- **Registry names are operator-supplied and now reach an error body.** They are already returned
  by the admin API to the same audience, and no secret material is on `Registry.Name`.
- **Two registries can share a name.** Entries are keyed by registry ID, so both render — the
  message repeats a label rather than collapsing two different reasons into one, which is the
  safe direction.
- **The functional test depends on a synced provider catalog** for `VerdictAbsent`. Guarded by
  the same skip the existing catalog subtest uses.
- **Out of scope, unchanged:** the lenient fallback that re-adds the full chain when the catalog
  empties it (ENG-1433 trade-off), and ENG-1464 AC#2.

## QA

- [ ] `go build ./...`
- [ ] `go test ./pkg/...` and `go test -race ./pkg/...`
- [ ] `golangci-lint run ./...` — 0 issues
- [ ] `make test-functional` — `MCP_CONNECT_RATE_LIMIT_ENABLED=false` in `.env.functional`;
      `TestPlaygroundTraceE2E` and `TestSmartRoutingE2E_RecordsSavings` fail on clean `main` too
- [ ] The error body names no provider's own message
- [ ] The error body names both bound registries and why each was ruled out
- [ ] A registry dropped by allow-list and one dropped by the catalog are distinguished
- [ ] `403 model_not_allowed` still returned when an explicit allow-list denies every candidate
- [ ] A glob model ref still 403s and is never labelled "restricted by its model allow-list"
- [ ] Reproduce the reported setup end to end: Anthropic restricted to `claude-haiku-*` plus
      OpenAI with no allow-list, invoking a sonnet model
