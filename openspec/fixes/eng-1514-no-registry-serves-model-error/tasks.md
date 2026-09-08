---
linear: ENG-1514
type: fix
design: openspec/fixes/eng-1514-no-registry-serves-model-error/proposal.md
branch: fix/no-registry-serves-model-error
base: origin/main
---

# Tasks: ENG-1514 — the no-registry-serves-model error owns the failure

Four phases, four commits, one PR. The design is approved and is not revisited here; this
document fixes sequencing, commit boundaries, per-phase verification and the review budget.

## Binding constraints carried into every phase

- `.agents/AGENT.md` §11.1 — **no comments of any kind**, Go doc comments included. New files
  carry the 14-line Apache header and nothing else. `//go:generate` and lint directives are the
  only exceptions.
- `.agents/AGENT.md` §10.2 — one responsibility per file. `model_exclusions.go` holds the
  exclusion vocabulary and nothing else.
- `.agents/AGENT.md` §13 — 400 changed lines per PR.
- `golangci.yml` enables `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused` with
  `run.tests: true`.
- Every phase must leave `make build`, `make test`, `make lint` green before it is committed.
  The pre-commit hook runs lint + full unit tests + gosec, so a phase that does not compile or
  does not pass cannot be committed at all.

## Facts established against the working tree

These were checked, not assumed, and they drive the ordering below.

1. `noRegistryServesModelError` has exactly one caller — `pkg/app/proxy/forwarder.go:289`.
   `chainProviders` has exactly one caller — `noRegistryServesModelError` itself
   (`routing.go:369`). Nothing else in the repo references either.
2. Deleting the provider tail does **not** orphan an import. `routing.go` keeps using `strings`
   (`:214`, `:530`) and `adapter` (`:218-263`) after the change. No import churn, no
   compile-on-delete surprise.
3. `"test-backend"` appears exactly once in the repo — its own definition at
   `pkg/app/proxy/forwarder_test.go:79`. Renaming it has zero call-site churn.
4. **`unused` is enabled and would reject `model_exclusions.go` as a standalone commit.** Every
   symbol in the new file is unexported; with no caller and no test, `unused` flags
   `modelExclusions`, `exclusionReasonFor`, `registryLabel`, `renderExclusions`,
   `exclusionReason.String` and `registryExclusion`. The new file therefore **cannot** be its own
   phase — it lands with its wiring in Phase 2.
5. `TestForward_SequentialChain_NoRegistryServesTheModel` (`routing_sequential_test.go:173`)
   currently passes its `Contains "openai"` / `Contains "vertex"` assertions only because the
   message renders `(tried openai, vertex)`. Once labels come from `Registry.Name`, both
   fixtures render `test-backend` and both assertions fail. Hence Phase 1.
6. `anthropicBackendPayload` (`tests/functional/embeddings_provider_test.go:57`) takes a name
   only and carries **no `provider_options.base_url`** — it points at the real Anthropic API and
   its hits are not countable. The anthropic client does honour `base_url`
   (`pkg/infra/providers/anthropic/client.go:114-116`), so Phase 3 builds the anthropic payload
   inline with a `base_url` override rather than changing the shared helper and dragging the
   embeddings tests into this diff.

---

## Phase 1 — distinct names for the registry test fixtures

**Commit:** `test(proxy): give each registry fixture a distinct name`

**Why first:** Phase 2 replaces the provider list with registry labels. Two fixtures currently
share `Name: "test-backend"`, so the retargeted assertions in Phase 2 would either pass
vacuously or collide. Landing the rename on its own keeps it visibly a no-op — behaviour
unchanged, every existing assertion still green — instead of hiding a fixture change inside the
behaviour commit.

**Files**

| File | Change |
|---|---|
| `pkg/app/proxy/forwarder_test.go` | `backendFor` sets `Name: "registry-" + provider` (line 79) |

**Tasks**

- [ ] 1.1 — `backendFor`: `Name: "test-backend"` → `Name: "registry-" + provider` · `pkg/app/proxy/forwarder_test.go:79`

**Verify before committing**

```
make lint
make test
```

Both must be green *before* Phase 2 exists — that is the whole point of the split. Nothing else
reads `"test-backend"`, so no other test needs touching.

**Forecast:** +1 / -1 = **2 lines**

---

## Phase 2 — the gateway owns the verdict

**Commit:** `fix(proxy): name every bound registry and why it was ruled out`

**Why this is one commit and cannot be three:** three separate forces pin these files together.
The new file alone fails `unused` (fact 4). The behaviour change alone fails
`TestForward_SequentialChain_NoRegistryServesTheModelKeepsTheProviderDetail`, which asserts the
exact opposite of the new requirement — and the pre-commit hook runs the full unit suite, so
that commit is physically impossible. The inverted test alone fails against unchanged
behaviour. Production code, its consumer and the two opposing assertions land together or not
at all.

**Files**

| File | Action | Change |
|---|---|---|
| `pkg/app/proxy/model_exclusions.go` | Create | `exclusionReason` enum + `String()`, `registryExclusion`, `modelExclusions`, `exclusionReasonFor`, `registryLabel`, `renderExclusions` |
| `pkg/app/proxy/routing.go` | Modify | `noRegistryServesModelError` becomes `func (f *forwarder) noRegistryServesModelError(ctx, rc, model) error`; provider tail deleted; `chainProviders` (`:380-395`) deleted |
| `pkg/app/proxy/forwarder.go` | Modify | Call site `:289` → `f.noRegistryServesModelError(ctx, rc, dto.request.RequestedModel)` |
| `pkg/app/proxy/routing_sequential_test.go` | Modify | Invert one test, retarget one, add one |

**Tasks**

- [ ] 2.1 — Create `pkg/app/proxy/model_exclusions.go` with the Apache header and no comments.
  `exclusionReason` int enum (`exclusionUnexplained` = zero value, `exclusionAllowList`,
  `exclusionCatalogAbsent`) and `String()` rendering exactly the three strings in the design's
  table · `pkg/app/proxy/model_exclusions.go`
- [ ] 2.2 — `registryLabel(reg)` returns `reg.Name`, falling back to `reg.Provider()`;
  `renderExclusions` joins `"<label>: <reason>"` with `"; "` · `pkg/app/proxy/model_exclusions.go`
- [ ] 2.3 — `exclusionReasonFor` exactly as specified: `ModelPolicies.For(reg.ID)` →
  `routingdomain.Candidate{Allowed: policy.Allowed}`; `!DefersModelChoice()` branch gated on
  `!modelmatch.IsPattern(model)`; catalog branch nil-guards `f.listing` and only fires on
  `appcatalog.VerdictAbsent`. Do not re-implement the matching rule — reuse the domain
  predicates · `pkg/app/proxy/model_exclusions.go`
- [ ] 2.4 — `modelExclusions` walks `rc.Registries` then `rc.FallbackBackends`, skipping nil
  registries, IDs already seen, and empty labels · `pkg/app/proxy/model_exclusions.go`
- [ ] 2.5 — Convert `noRegistryServesModelError` to a `*forwarder` method taking
  `(ctx, rc, model)`; body is `%w: %q` with no exclusions, `%w: %q (%s)` otherwise; delete the
  `adapter.ProviderErrorMessage` tail and the `chain` / `last failoverState` parameters ·
  `pkg/app/proxy/routing.go:367-378`
- [ ] 2.6 — Delete `chainProviders` · `pkg/app/proxy/routing.go:380-395`
- [ ] 2.7 — Update the single call site · `pkg/app/proxy/forwarder.go:289`
- [ ] 2.8 — Invert `TestForward_SequentialChain_NoRegistryServesTheModelKeepsTheProviderDetail`
  → `…DropsTheProviderDetail`. Keep the `modelNotFoundBody` invoker; flip
  `assert.Contains(err, "do not have access")` to `assert.NotContains` with a message stating
  the gateway's own verdict is what surfaces. **Invert, do not delete** — a deleted test lets
  the regression back in silently · `pkg/app/proxy/routing_sequential_test.go:378-398`
- [ ] 2.9 — Retarget `TestForward_SequentialChain_NoRegistryServesTheModel`: the
  `Contains "openai"` / `Contains "vertex"` assertions survive on Phase 1's labels; add
  `NotContains "tried"` and `NotContains "do not have access"` ·
  `pkg/app/proxy/routing_sequential_test.go:173-197`
- [ ] 2.10 — Add `TestForward_SequentialChain_NoRegistryServesTheModelNamesEveryBoundRegistry`:
  two registries; `ModelPolicies{anthropicID: {Allowed: []string{"claude-haiku-*"}}}` on the
  consumer; `stubListing{verdicts: {"openai:claude-sonnet-4-5": appcatalog.VerdictAbsent}}`;
  invoker answers 404 `model_not_found`. Assert the exact message, that the anthropic upstream
  was never invoked, and that `openai` was invoked exactly once (the lenient re-add).
  `routableConsumerWith` does not set `ModelPolicies`, so set the field on the returned consumer
  rather than widening the shared helper · `pkg/app/proxy/routing_sequential_test.go`

**Verify before committing**

```
make license          # confirms the new file's Apache header
make fmt
make lint             # unused must be clean — this is the gate that forced 2.1 into this commit
make test
make test-race
go build ./...
```

**Forecast**

| File | +/- |
|---|---|
| `model_exclusions.go` | +95 … +105 |
| `routing.go` | +10 / -28 |
| `forwarder.go` | +1 / -1 |
| `routing_sequential_test.go` | +65 … +78 / -12 |

**≈ 210 – 235 lines**

---

## Phase 3 — the boundary tests

**Commit:** `test(proxy): rebuild the no-registry error assertions at the boundaries`

**Why here and not last:** the functional subtest at `routing_intent_test.go:671` asserts
`do not have access`, so `make test-functional` is red from the moment Phase 2 lands. The
pre-commit hook does not run functional tests, so nothing blocks — which is exactly why this
phase must sit immediately after Phase 2 and not at the end. If a zero-red-window is required,
squash this phase into Phase 2; the split costs one commit of red functional suite and buys a
reviewable separation between the fix and its boundary coverage.

The handler test is independent of the forwarder — it drives a `proxymocks.Forwarder` and
hand-builds the message literal, so it is green today and stays green until edited. It rides
along here because it belongs to the same "assertions that encode the old message shape"
concern.

**Files**

| File | Change |
|---|---|
| `pkg/api/handler/http/proxy/proxy_handler_test.go` | Rebuild the stub error and the two `Contains` checks |
| `tests/functional/routing_intent_test.go` | Invert one subtest, add the reported-shape subtest |

**Tasks**

- [ ] 3.1 — `TestHandle_NoRegistryServesModelReturns404ModelNotSupported`: stub error becomes
  `fmt.Errorf("%w: %q (Anthropic: restricted by its model allow-list; OpenAI: not in the provider catalog)", routingdomain.ErrNoRegistryServesModel, "claude-sonnet-4-5")`;
  the two `Contains` checks assert both registry labels and both reasons. This pins handler
  status/error-code mapping, not forwarder construction — keep it that way ·
  `pkg/api/handler/http/proxy/proxy_handler_test.go:641-676`
- [ ] 3.2 — Invert `the gateway error carries the provider's own diagnosis` →
  `the gateway error carries no provider's own diagnosis`: flip `do not have access` to
  `NotContains` and assert the registry name appears with a reason ·
  `tests/functional/routing_intent_test.go:671-684`
- [ ] 3.3 — Add `the error names every bound registry and why each was ruled out` inside
  `TestRoutingIntent_SequentialChainHardening`. `setupChain` takes no per-registry policies, so
  build the consumer inline the way `an allow-list that excludes the model removes its registry
  from the chain` (`:647-669`) already does. Anthropic binding carries
  `model_policies {"allowed": ["claude-haiku-*"]}`; OpenAI binding carries none. Request
  `claude-sonnet-4-5`. Guard with the existing `openaiCatalogListsModel(t, "gpt-4o-mini")` skip —
  `VerdictAbsent` needs a synced catalog. Assert 404 `model_not_supported`, both registry names,
  both reasons, `do not have access` absent, zero hits on the anthropic side ·
  `tests/functional/routing_intent_test.go`
- [ ] 3.4 — For 3.3's anthropic registry, build the payload **inline** with
  `provider_options: {"base_url": <stub>.URL()}` so its hits are countable. Do **not** widen
  `anthropicBackendPayload` (`tests/functional/embeddings_provider_test.go:57`) — it has no
  `base_url` today, and changing its signature pulls the embeddings suite into this diff for no
  gain · `tests/functional/routing_intent_test.go`

**Verify before committing**

```
make lint
make test
make test-functional   # MCP_CONNECT_RATE_LIMIT_ENABLED=false in .env.functional
```

`TestPlaygroundTraceE2E` and `TestSmartRoutingE2E_RecordsSavings` fail on clean `main` too —
compare against a `main` run rather than reading them as regressions.

**Forecast**

| File | +/- |
|---|---|
| `proxy_handler_test.go` | +10 / -8 |
| `tests/functional/routing_intent_test.go` | +45 … +52 / -14 |

**≈ 77 – 84 lines**

---

## Phase 4 — unit coverage for the recompute

**Commit:** `test(proxy): cover the per-registry exclusion recompute`

**Why last:** purely additive, depends only on Phase 2, and it is the design's own nominated
trim lever. Putting the discretionary slice last means the 400-line decision is made with the
real count of Phases 1–3 already on the branch, not against an estimate.

**Files**

| File | Change |
|---|---|
| `pkg/app/proxy/model_exclusions_test.go` | Create |

**Tasks**

- [ ] 4.1 — Table-driven test over `exclusionReasonFor` covering all three reasons ·
  `pkg/app/proxy/model_exclusions_test.go`
- [ ] 4.2 — The pattern-ref guard: a glob `model` is never labelled
  `restricted by its model allow-list` · `pkg/app/proxy/model_exclusions_test.go`
- [ ] 4.3 — The empty non-nil `Allowed` case (`"allowed": []` on the wire) stays an allow-list,
  matching `inlineCandidate` · `pkg/app/proxy/model_exclusions_test.go`
- [ ] 4.4 — `modelExclusions` dedups across `Registries` + `FallbackBackends` by registry ID and
  preserves order · `pkg/app/proxy/model_exclusions_test.go`
- [ ] 4.5 — `registryLabel` falls back to the provider code when `Name` is empty ·
  `pkg/app/proxy/model_exclusions_test.go`

**Verify before committing**

```
make lint
make test
make test-race
```

**Forecast:** +85 … +115 → **≈ 100 lines**

**Trim lever if the branch is over 400 at this point:** fold 4.1–4.3 into a single table with a
`want exclusionReason` column and drop 4.5 — `registryLabel` is a two-branch function whose
fallback is already exercised by 4.4's fixtures. That recovers 25–35 lines. Do not trim Phases
2 or 3; those carry the requirement.

---

## Review Workload Forecast

| Phase | Commit | Lines (est.) | Risk |
|---|---|---|---|
| 1 | `test(proxy): give each registry fixture a distinct name` | 2 | Low |
| 2 | `fix(proxy): name every bound registry and why it was ruled out` | 210 – 235 | Medium |
| 3 | `test(proxy): rebuild the no-registry error assertions at the boundaries` | 77 – 84 | Low |
| 4 | `test(proxy): cover the per-registry exclusion recompute` | 85 – 115 | Low |
| | **Total** | **374 – 436** | **Medium** |

**Sanity check against the design's ≈371.** The design's per-file table sums to exactly 371 and
the structural numbers hold up: `routing.go -28` is precisely `noRegistryServesModelError`
(`:367-378`, 12 lines) plus `chainProviders` (`:380-395`, 16 lines), and `forwarder.go` /
`forwarder_test.go` are genuine one-liners. Three estimates are optimistic against what the
phase tasks actually require:

- `model_exclusions.go` **+90 → 95–105.** The 14-line Apache header, package clause and six
  imports consume ~25 lines before the first declaration; six declarations plus a three-arm
  `String()` do not fit in the remaining 65.
- `model_exclusions_test.go` **+85 → 85–115.** Five distinct concerns (4.1–4.5), each needing a
  `Registry` and a `RoutableConsumer` fixture. 85 is reachable only with the trim already
  applied.
- `routing_sequential_test.go` **+65 → 65–78.** Task 2.10 alone — two registries, a
  `ModelPolicies` map the shared helper does not build, a `stubListing`, an exact-message
  assertion and two invocation-count assertions — is ~45 lines before the two edits.

So 371 is the floor, not the estimate. The honest range straddles the budget.

**400-line budget risk:** Medium — the midpoint clears 400 by roughly 5%.
**Chained PRs recommended:** No.
**Decision needed before apply:** No.

**Rationale for a single PR.** The work is one behavioural change plus its tests, and no phase
ships independent user value — Phase 1 is a fixture rename, Phases 3 and 4 are assertions with
no product surface. A chain here would hand reviewers three PRs that cannot be evaluated apart
from the one that matters. The overrun, if it materialises, is 5–9% and has a named,
pre-agreed trim lever sitting in the last phase. Measure the real diff after Phase 3
(`git diff --shortstat origin/main...HEAD`), then size Phase 4 to land under 400. If the branch
somehow exceeds 400 with Phase 4 already trimmed, request `size:exception` rather than chaining:
the split points available (production vs. tests) would separate a behaviour change from the
tests that prove it, which is the worst available boundary.

---

## Final verification checklist

Run against the complete branch before opening the PR.

- [ ] `go build ./...`
- [ ] `make test` and `make test-race` (`go test ./pkg/...`, `-race`)
- [ ] `make lint` — 0 issues, `unused` included
- [ ] `make test-functional` — `MCP_CONNECT_RATE_LIMIT_ENABLED=false` in `.env.functional`;
      `TestPlaygroundTraceE2E` and `TestSmartRoutingE2E_RecordsSavings` fail on clean `main` too
- [ ] `make license` — the new file carries the 14-line Apache header
- [ ] `git diff --shortstat origin/main...HEAD` ≤ 400 changed lines
- [ ] No comments anywhere in the diff (§11.1), header and lint directives excepted
- [ ] The error body names no provider's own message
- [ ] The error body names both bound registries and why each was ruled out
- [ ] A registry dropped by allow-list and one dropped by the catalog are distinguished
- [ ] `403 model_not_allowed` still returned when an explicit allow-list denies every candidate
- [ ] A glob model ref still 403s and is never labelled `restricted by its model allow-list`
- [ ] **Reported repro, end to end:** a consumer bound to an Anthropic registry restricted to
      `claude-haiku-*` plus an OpenAI registry with no allow-list; request `claude-sonnet-4-5`;
      expect `404` / `model_not_supported` with
      `routing: no registry serves the requested model: "claude-sonnet-4-5" (Anthropic: restricted by its model allow-list; OpenAI: not in the provider catalog)`
      and zero requests reaching the Anthropic upstream
- [ ] No mocks regenerated, no `pkg/domain/routing` change, no `approuting.Resolver` signature
      change, none of the 13 `ResolveIntent` call sites touched
