# Tasks: LLM Store — personal keys on personal LLM consumers (RUN-1763)

Inputs: `proposal.md` (binding, option C: B1–B9, D1–D14), `design.md` (binding: DD1–DD19, the 16-PR chain), `specs/**/spec.md` (12 capabilities), `exploration.md`, Linear [RUN-1763](https://linear.app/neuraltrust/issue/RUN-1763). Base `origin/develop` @ `1ea70e06`. Paths start at the repo root. This file replaces the pre-option-C `tasks.md`.

Conventions (binding): `.agents/AGENTS.md`, meaning hexagonal layers (`pkg/domain` ← `pkg/app` ← `pkg/infra` / `pkg/api`), one use case per file with `//go:generate mockery`, one DTO per file under `request/` and `response/`, DI only in `pkg/container/modules/*` (`dig` resolves by exact type, so register view providers for segregated interfaces), the strict no-comments policy (exported doc comments, license headers and swag annotations stay; no narrative comments), and swag annotations on every new or changed handler. golang-pro: `ctx` first and propagated, `%w` wrapping, immutable shared state, table tests, `-race`.

Orchestrator resolutions of the open questions (binding, encoded below):

| # | Resolution | Tasks |
|---|---|---|
| OQ1 | A personal key with zero links authenticates. Chat answers 403 `model_not_allowed` and `/store/v1/models` answers `[]`. | 11.6, 13.8, 14.6, 15a.4 |
| OQ2 | Substitution reads only the primary registries of the `user`-level consumers. Their fallback backends never add a provider to `S`. | 13.1, 13.6 |
| OQ3 | When the catalog verdict is `VerdictUnknown`, a registry without an allow-list admits any short model. This is documented. | 13.2, 13.7, 15b.4 |
| OQ4 | Fail-closed 503 under `partition: key` is treated as signed off. | 8.1, 8.5 |

Each task names its files and the spec scenarios it satisfies (`capability › Scenario`). Phase N = design PR N, except that design PR 15 is split into 15a and 15b (adjustment A4).

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | Hand-written ≈4,970 (range 4,400–5,500): code ≈1,690, tests ≈3,140, docs ≈140. Generated ≈850, outside the budget: mocks ≈300 in P2b, P5, P6, P9, P12, P13 and P14, and swagger/openapi ≈550 in P3, P4, P6 and P10. openspec ≈2,100, also outside. |
| Per-PR (hand-written) | P1 270 · P2a 377 · P2b 324 · P3 320 · P4 285 · P5 290 · P6 280 · P7 310 · P8 265 · P9 300 · P10 345 · P11 325 · P12 300 · P13 375 · P14 290 · P15a 350 · P15b 180 · P16 140 |
| 400-line budget risk | High: the total is ≈12× the budget. Every PR is ≤ 400 hand-written lines. P13 (375) and P2a (377, measured) are within 25 lines of the limit, and P10 and P15a sit at ≈345–350. Measure before opening. If P13 goes over, move the benchmark and the 64-goroutine test into P14. |
| Chained PRs recommended | Yes |
| Chain strategy | Stacked PRs to `develop` in four lanes, no tracker branch. Every PR is behaviour-neutral or self-contained and inert until the app creates a personal consumer, so a Feature Branch Chain is not needed. |
| Parallelizable starts | t0, cut from `develop`: P1, P2a, P7. After P2a: P2b, P3, P5. After P2b: P4. After P5: P11 and P16 (and P6 once P3 is in). After P4: P9. After P11: P12 and P13. |
| Critical path | P2a → P5 → P11 → P13 → P14 → P15a → P15b (7 PRs) |
| Merge order | P1, P2a, P7 → P2b, P3, P5 → P4, P6, P8, P11, P16 → P9, P12, P13 → P10, P14 → P15a → P15b |
| Delivery strategy | chained-stacked |

Decision needed before apply: Yes. Confirm adjustments A1–A5 below. They resize and re-sequence PRs and reverse no binding decision.
Chained PRs recommended: Yes
Chain strategy: stacked (four lanes from `develop`, joins rebased on `develop`)
400-line budget risk: High

How to measure the budget (this excludes openspec/ and generated files, as ENG-1618 and RUN-1746 did):
- `git diff --shortstat <parent> -- pkg tests docs ':!docs/swagger.*' ':!docs/docs.go' ':!docs/openapi.json' ':!**/mocks/**'`
- New files are untracked until staged, and an untracked file is invisible to `git diff`. Run `git add -N <new files>` (intent-to-add) before measuring, or the count leaves them out.

### Adjustments to the design's chain

| # | Change | Why | Effect |
|---|---|---|---|
| A1 | `auths.ListFilter.{ExcludeOwned, OwnerID}` (domain field, PG predicate, PG test) moves from P2 to P4 | P2 was at 390. The filter has exactly one consumer: the P4 list handler. | P2 390 → 345, P4 240 → 285 |
| A2 | `routingdomain.SourceFallback` and `Candidate.FallbackOnly()` move from P13 to P11 | P13 was over budget in this forecast (≈410). Both changes are pure domain code. | P13 → 375, P11 → 325 |
| A3 | P12 also depends on P7, which adds `AuthContext.OwnerID`. P11 and P14 rebase on P1. | P7 and P12 would otherwise both add `AuthContext.OwnerID`. P1, P11 and P14 all edit `auth.go:196` or `proxy_handler.go`. | No new PR. P7 merges long before P12 (the store lane is 4 PRs deep). |
| A4 | Design PR 15 becomes P15a (full-plane functional) and P15b (DB-less functional plus `docs/llm-store.md`). The P10 functional test takes the self-key and admin owned-key flows. | The listed functional scenarios came to ≈450 lines, over the budget. | 17 PRs instead of 16. P15a 350, P15b 180. |
| A5 | Design PR 2 becomes P2a (`audience`) and P2b (`owner_id`), stacked: P2b's base is P2a | P2 measured 667 hand-written lines (forecast 345): the listed scenarios cost ≈420 test lines, and six new files carry license headers. P2b reuses P2a's codec fixture and migration shadow helpers. | 18 PRs. P2a 377, P2b 324 (measured). P3 and P5 depend on P2a; P4 and P9 on P2b. |

### Chain topology

| Lane | PRs | Base while the parent is open | Base once the parent merged |
|------|-----|------|------|
| T (expiry, telemetry) | P1 | `develop` | — |
| A (data model, admin, self keys) | P2a → {P2b, P3, P5}; P2b → P4 → P9 → P10; {P3, P5} → P6 | parent branch (for P6, the later of P3 and P5) | `develop` |
| B (budgets) | P7 → P8 | parent branch | `develop` |
| C (store data plane) | P5 → P11 → {P12 (+P7), P13} → P14 → P15a (+P6, P8, P10) → P15b; P5 → P16 | last open parent | `develop` |

Retargeting a base does not re-run CI, so close and reopen the PR after a retarget. "No checks reported" means the PR has a merge conflict: check `mergeable` before you re-push.

### Suggested Work Units

| Unit | Slice | Goal | Depends | Hand-written (code / test) | Generated |
|------|-------|------|---------|------|------|
| P1 | S0 + S1 | Expired keys rejected, `auth_key` cross-process eviction, `trustgate.auth.id` | — | 70 / 200 | — |
| P2a | S3a | `audience`: migration, domain, consumer repo, golden codec bytes, migration shadow helpers | — | 126 / 251 | — |
| P2b | S3a | `owner_id`: migration, auth domain, auth repo, `FindByOwner`, snapshot adapter, compiler and adapter tests, personal/owned codec round trip | P2a | 130 / 194 | mocks 64 |
| P3 | S3b | Consumer rules: personal ⇒ LLM, default model, immutability, bulk `auths` 422, hybrid 422, audience DTOs | P2a | 120 / 200 | swagger ≈60 |
| P4 | S3c | Admin auth rules: list filter and `?owner_id`, `owned_key` 422, rotator owner check, warnings | P2b | 120 / 165 | swagger ≈50 |
| P5 | S3d | `consumer_auth` link columns, `AuthLink`, `auth_links` read, upsert port | P2a | 120 / 170 | mocks ≈30 |
| P6 | S3e | Attach with link attributes (DD7), audience mismatch on attach | P3, P5 | 100 / 180 | mocks ≈30, swagger ≈60 |
| P7 | S2a | `partition: key`, `AuthID`/`OwnerID` plumbing, calendar windows | — | 120 / 190 | — |
| P8 | S2b | Hard limits (503, 403 `model_unpriced`, 429 scope), catalog and docs | P7 | 100 / 165 | — |
| P9 | S4a | Owned-key domain constructor and expiry cap, `PersonalKeys` use case | P2b, P4 | 145 / 155 | mocks ≈50 |
| P10 | S4b | Self-only HTTP routes and DTOs, functional key flows | P9 | 130 / 215 | swagger ≈380 |
| P11 | S5a | `Data.StoreLinks`, `HasPersonalConsumers`, `bySlug` skip, D11 rejections, `FallbackOnly` | P5 (rebase on P1) | 110 / 215 | — |
| P12 | S5b | `StoreKeyResolver`, middleware store branch, interim handler 404 | P11, P7 | 110 / 190 | mocks ≈30 |
| P13 | S5c | `StoreSelector`, `storeScope`, `candidatePipeline` extraction | P11 | 130 / 245 | mocks ≈60 |
| P14 | S5d | Handler store path, `ForwardInput.Keep`, `ListModelsInput.Keep`, `StoreModels` | P12, P13 (rebase on P1) | 110 / 180 | mocks ≈60 |
| P15a | S5e | Full-plane end-to-end functional suite | P6, P8, P10, P14 | 0 / 350 | — |
| P15b | S5e | DB-less functional suite, `docs/llm-store.md` | P15a | 70 docs / 110 | — |
| P16 | S6 | Snapshot size and entity-count metrics | P5 | 75 / 65 | — |

Why each slice ships on its own:
- Nothing personal exists until the app creates a personal consumer, and the app ships only after every plane runs the whole chain (Deploy order, step 3). Until then each PR is inert apart from S0.
- P2a, P2b, P5: nullable or constant-default columns and `omitempty` wire fields. Golden bytes prove that existing snapshots do not change.
- P3, P4, P6: new 422s fire only on personal consumers or owned keys, which nobody can create before P10. Application keys and consumers keep their contracts.
- P7, P8: everything is gated on `partition: key`, which no existing policy carries.
- P12 without P14: on a gateway with personal consumers, the store branch authenticates and the handler answers 404 (task 12.4). P14 replaces that.
- P1 is the only OSS-visible change: expired application keys get 401. It carries the release note.

PR rules:
- Titles are bare, e.g. `feat: personal key store branch (RUN-1763)`.
- Bodies include the Chain Context section (parent, children, what is inert).
- Every PR says `Part of RUN-1763`. The last PR to merge (P15b) says `Fixes RUN-1763` only if ENG-1710 and ENG-1704 are tracked separately. Otherwise it also says `Part of`.
- No Claude attribution lines in commits or PR bodies.
- `frontend/`, `.cursor/` and `snapshot.proto` never appear in a diff.

### Verification blocks

- **VG** (every PR):
  - `go build ./...`, `go vet ./...`, `go vet -tags functional ./...` (`make test` does not compile the `functional` tag), `make lint`, `make test-race`, `make license-check`.
  - `git diff --stat origin/develop -- frontend proto` is empty (`llm-store-oss-invariance › Frontend diff`, `› Golden snapshot`).
  - Run clean-comments on the touched Go files, then grep the staged diff for removed `-//` lines. Exported doc comments and swag annotations stay.
  - Run generators with `PATH="$HOME/go/bin:$PATH"` (`go generate ./pkg/...` for mockery).
  - `make docs` goes in its own `chore(docs)` commit. Develop's OpenAPI drift drags in unrelated lines, so regenerate in a temporary worktree and keep only this PR's paths.
  - gosec G101 may flag new constants that contain `key` (`owned_key`, `budget_unavailable` keys). An inline `#nosec G101` is the repo convention.
  - Wait for the CI `functional-tests` check (`llm-store-oss-invariance › CI`, `› Existing handler tests`).
- **VR** (repository and migration tests). CI runs the repository tests with `PG_TEST_URL`, but not the migration tests. Locally, use a disposable container only:
  1. `docker run -d --rm --name run1763-pg -p 55447:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine`
  2. `PG_TEST_URL='postgres://postgres:postgres@localhost:55447/postgres?sslmode=disable' make test-repositories`
  3. With the same URL: `go test -tags functional -count=1 -run 'TestAdd(ConsumerAudience|AuthOwner)Migration' ./pkg/infra/database/migrations/`. Add each PR's migration test to the `-run` pattern (P5: `TestAddConsumerAuthGrantMigration`). The tag is required. Without `-run`, the package also runs `TestConsumerRegistryPositionMigration`, which already fails in its own setup on `develop`.
- **VF** (functional, tag `functional`): `make test-functional` against local Postgres and Redis. Never copy the main checkout's `.env`, which points at Azure DB, and never point `E2E_*` at prod.

## Phase 1: S0 expiry + S1 telemetry (base `develop`)

Depends: —. Est.: ≈270 (code 70 / test 200). Commit boundary: (a) `docs(openspec)`: the change folder, outside the budget; (b) `fix`: expiry, S0; (c) `feat`: telemetry, S1. Release note in the PR body.

- [x] 1.1 `pkg/api/resolver/api_key_resolver.go`: inject `now func() time.Time`. `Resolve` skips `Auth.IsExpired(now())` auths the way it skips disabled ones. Wire `time.Now().UTC()` at `pkg/container/modules/api.go:196`.
- [x] 1.2 `pkg/api/middleware/auth.go`: `NewAuthMiddleware` takes the clock. `apiKeyAttachedElsewhere(…, now)` (`:196`) ignores expired auths. Wire at `pkg/container/modules/api.go:250`.
- [x] 1.3 `pkg/infra/cache/subscriber/invalidate_gateway_data_event_subscriber.go` (DD15): take `AuthKeyTTLName` and clear it next to `authCache`. Wire at `pkg/container/modules/cache_events.go:44`.
- [x] 1.4 Telemetry: `pkg/infra/trace/trace.go` (`Metadata.AuthID`, `SetAuthID`, no-op on empty), `pkg/infra/metrics/events/event.go` (`AuthID json:"auth_id,omitempty"`), `pkg/app/metrics/builder.go:68-84`, `pkg/infra/telemetry/otlp/mapping.go:70-74,202-206` (`trustgate.auth.id`, not emitted when empty), `pkg/api/handler/http/proxy/proxy_handler.go:154,419` (`stampConsumerTrace(c, rc, authCtx)`).
- [x] 1.5 `docs/telemetry/otlp-metadata-contract.md:52-56`: add the `trustgate.auth.id` row. The `trustgate.principal.subject` row says it holds the key owner for a personal key. Accept: `usage-auth-id-telemetry › Contract row present`.
- [x] 1.6 Test `pkg/api/resolver/api_key_resolver_test.go` (fixed clock): an expired key on its own consumer gets the unknown-key status, `expires_at == now` is expired, and a future or absent expiry is accepted. Accept: `proxy-api-key-expiry › Expired key on its own consumer`, `› Expiry boundary`, `› Future or absent expiry`, `› Fixed clock in a unit test`.
- [x] 1.7 Test `pkg/api/middleware/auth_test.go`: an expired key attached to another consumer → 401. A valid key attached to another consumer → 403. Accept: `proxy-api-key-expiry › Expired key of another consumer`, `› Valid key of another consumer`.
- [x] 1.8 Test `invalidate_gateway_data_event_subscriber_test.go`: the event clears both `auth` and `auth_key`. Accept: the unit half of `llm-store-gateway › Rotation seen by another replica` and `› Stale key cache after a detach` (both end to end in 15a.7).
- [x] 1.9 Test `pkg/app/metrics/builder_test.go` and `pkg/infra/telemetry/otlp/mapping_test.go`: the auth id is present when set and absent when empty. `principal_subject` is the key name for an application key. Accept: `usage-auth-id-telemetry › Application key on a consumer`, `› No auth id`, `› Application key subject`.
- [x] 1.10 Test `tests/functional/proxy_api_key_expiry_test.go` (C, `functional`): an application key with a past `expires_at` → 401 on `/<slug>/v1/chat/completions`. A future one → 200.
- [ ] 1.11 PR body `## Release note`: application keys with a past `expires_at` stop working on `/<slug>/v1/*`, and rollback is a revert. Accept: `proxy-api-key-expiry › Release note present`.
- [ ] 1.12 Run VG and VF.

## Phase 2: S3a data model — P2a `audience` (base `develop`), P2b `owner_id` (base P2a)

Depends: —. Measured 667 hand-written lines, so the phase ships as two stacked PRs (A5).
- P2a 377: 2.1 (audience migration), 2.2, 2.4, 2.7 (audience test and `shadow_helpers_test.go`), 2.8 (`audience_test.go`), 2.9 (golden bytes), 2.11 (consumer half). Commit boundary: (a) `test`: capture the golden codec bytes for an application consumer and an application key on the base, before any struct change; (b) `feat`: migration, domain, consumer repo.
- P2b 324: 2.1 (owner migration), 2.3, 2.5, 2.6, 2.7 (owner test), 2.8 (`IsOwned`), 2.9 (personal and owned round trip), 2.10, 2.11 (auth half). Commit boundary: (a) `feat`: migration, auth domain, auth repo, snapshot adapter; (b) `chore`: mocks.

- [x] 2.1 Create `pkg/infra/database/migrations/20261005120000_add_consumer_audience.go` and `20261005120100_add_auth_owner.go` (IDs moved after develop's latest migration, `20261003150000`). Use the SQL from the design and the template `20260922120000_add_auth_expires_at.go`: idempotent, one transaction per direction, no table.
- [x] 2.2 Create `pkg/domain/consumer/audience.go`: `Audience`, `AudienceApplication`, `AudiencePersonal`, `ParseAudience` (`"application"` → `""`), `IsPersonal()`, `AudienceName()`. `consumer.go`: `Audience json:"audience,omitempty"`, `CreateParams.Audience`, `RehydrateParams.Audience`. `errors.go`: `ErrInvalidAudience`.
- [x] 2.3 `pkg/domain/auth/auth.go`: `OwnerID json:"owner_id,omitempty"`, `IsOwned()`. `errors.go`: `ErrOwnedKeyExists` (wraps `ErrAlreadyExists`). `repository.go`: `FindByOwner(ctx, gatewayID, ownerID)`. Run `go generate ./pkg/domain/auth/...`.
- [x] 2.4 `pkg/infra/repository/consumer/repository.go`: `c.audience` in `consumerSelectColumns` (`:50-58`), `INSERT` (`:118`) and `scanConsumer` (`:732`, `ParseAudience`). `Update` never writes `audience`.
- [x] 2.5 `pkg/infra/repository/auth/repository.go`: one `authColumns` const replaces the six SELECT copies (`:140-288`) and adds `owner_id`. `INSERT` writes `NULLIF($n,'')`. A 23505 on `auths_gateway_owner_uniq` → `ErrOwnedKeyExists`. `UPDATE` stays unchanged, so it never writes `owner_id`. `scanAuth`. `FindByOwner`.
- [x] 2.6 `pkg/runtimeconfig/snapshot/adapters/auth_repository.go`: `FindByOwner` scans the gateway's auths in the snapshot.
- [x] 2.7 Test `pkg/infra/database/migrations/20261005120000_add_consumer_audience_test.go` and `…120100_add_auth_owner_test.go` (`PG_TEST_URL`): up twice, down twice. Existing rows get `application` and `NULL`. `audience='team'` hits 23514. A second owned key on G hits 23505, while the same owner on H succeeds. Accept: `personal-llm-consumers › Existing rows`, `› Invalid value refused by the database`; `owned-api-keys › Existing rows untouched`, `› Second owned key for the same user`; `llm-store-oss-invariance › Migrations create nothing personal`.
- [x] 2.8 Test `pkg/domain/consumer/audience_test.go` and `pkg/domain/auth/auth_test.go`: `ParseAudience` table, `IsOwned`.
- [x] 2.9 Test `pkg/infra/configsnapshot/codec_test.go`: golden bytes from 2(a) for the application consumer and the application key, with no `audience` and no `owner_id`. Round trips for a personal consumer and an owned auth. Accept: `personal-llm-consumers › Codec round trip`, `› Application consumer bytes`; `owned-api-keys › Codec round trip`, `› Application key bytes`; `llm-store-oss-invariance › Golden snapshot` (the version hash is unchanged).
- [x] 2.10 Test `pkg/app/configsnapshot/compiler_test.go`: a gateway with one application key and one owned key compiles both, on the bulk and the per-gateway paths, and `AuthByAPIKeyHash` finds the owned key. Accept: `owned-api-keys › Compiler includes owned keys`.
- [x] 2.11 Test `tests/functional/repositories/auth/repository_test.go`: `FindByOwner(G)` hits and `FindByOwner(H)` is not found. Two concurrent `Save`s for one owner → one row and one `ErrOwnedKeyExists`. `Update` leaves `owner_id` alone. `tests/functional/repositories/consumer/repository_test.go`: `audience` round trip; `Update` leaves `audience` alone. Accept: `owned-api-keys › Find by owner`; `personal-key-endpoints › Concurrent creates`, `› Another gateway` (repository half).
- [x] 2.12 Run VG and VR.

## Phase 3: S3b consumer rules (base P2a)

Depends: P2a. Est.: ≈320 (code 120 / test 200). Commit boundary: (a) `feat`: domain and use-case rules, DTOs, wiring; (b) `chore(docs)`: `make docs`.

- [x] 3.1 `pkg/domain/consumer/consumer.go` `Validate` (`:212`): `personal` ⇒ `TypeLLM`, and personal needs a concrete (non-glob) `ModelPolicies[r].Default` for some `r` in `RegistryIDs`; fallback backends do not count. `errors.go`: `ErrAudienceImmutable`, `ErrPersonalAuthsBulk`, `ErrHybridPersonal`, `ErrPersonalNoDefault`, `ErrAudienceMismatch`. Done in `audience.go` (`validatePersonal`, `ValidateRegistryDetach`): a registry in an enabled `Fallback.Chain` never counts. `ErrAudienceMismatch` moves to 3.2, its only user.
- [x] 3.2 `pkg/domain/consumer/auth_rules.go` `ValidateAuthConfig` (`:37`): a personal consumer takes only owned auths, and an application consumer takes only unowned ones → `ErrAudienceMismatch`. Deferred: it needs `Auth.IsOwned()` (P2b), which P3's base (P2a) lacks. It lands with `ErrAudienceMismatch` and its matrix test in the first PR whose base has P2b (P6 rebased on P2b). The updater already runs `ValidateAuthConfig` over replaced `auths`, so the PUT half of `owned-key-attachment › Owned key onto an application consumer` needs no further updater code. Landed in P6: the matrix is `TestValidateAuthConfig_Audience` (`audience_test.go`), and `TestUpdater_Update_RefusesAnOwnedKeyOnAnApplicationConsumer` covers the replaced-`auths` path (422, no repository write).
- [x] 3.3 `pkg/app/consumer/creator.go`: carry `audience`. Personal plus non-empty `auths` → `ErrPersonalAuthsBulk`. Personal on a `ServedByHybridDataPlane()` gateway → `ErrHybridPersonal` (new gateway reader dependency). Run `ValidateAuthConfig` over the create `auths`. Create never took `auths`, for any audience, so keys arrive only through attach and there is nothing to refuse or to run `ValidateAuthConfig` over (`personal-llm-consumers › Create with keys` amended). The creator depends on a `gatewayFinder` (`FindByID`) and reads the gateway only for a personal consumer.
- [x] 3.4 `pkg/app/consumer/updater.go`: an `audience` different from the stored one → `ErrAudienceImmutable`. The `auths` field present on a personal consumer (`[]` included) → `ErrPersonalAuthsBulk`, before `replaceAuthLinks`. An owned auth in an application consumer's `auths` → `ErrAudienceMismatch` (arrives with 3.2 through `revalidateAuthsForTransition`).
- [x] 3.5 `pkg/app/consumer/associator.go`: detaching from a personal consumer the last registry with a concrete default → `ErrPersonalNoDefault`, and nothing is detached. `DetachRegistry` calls the repository first and reads the consumer only on its 409, to answer 422 when the registry holds the last primary default. A consumer that already has no primary default is never refused. Registry delete (`PruneRegistryReferencesTx`) refuses with 409 `has_dependents` when the prune would strip a personal consumer's last primary default.
- [x] 3.6 DTOs: `pkg/api/handler/http/consumer/request/create_consumer_request.go` (`Audience string json:"audience,omitempty"`), `update_consumer_request.go` (`Audience *string`), `response/consumer_response.go` (`Audience string json:"audience"`, always present). Swag `@Failure 422` on the create and update handlers. `auth_ids` is unchanged and `auth_links` is not exposed.
- [x] 3.7 `pkg/container/modules/consumer.go`: wire the creator's gateway dependency.
- [x] 3.8 Test `pkg/domain/consumer/consumer_test.go` and `auth_rules_test.go`: personal MCP 422, personal LLM ok, no default 422, glob default 422, a default only on a fallback 422, the audience × owned matrix. In `audience_test.go`, next to the rules. The audience × owned matrix moves with 3.2.
- [x] 3.9 Test `pkg/app/consumer/{creator,updater,associator}_test.go`: hybrid 422 with nothing saved; an application consumer on hybrid is created; create with keys 422; switch refused; same value accepted; `auths: []` on personal 422 with no repo write; detaching R1 (the only default) 422 while R2 detaches. "Create with keys 422" became a handler case (create ignores `auths`, 201); the updater also refuses dropping the last default and a switch to MCP.
- [x] 3.10 Test the handlers: the default `audience` is `application`; an invalid value → 422. `pkg/api/handler/http/consumer/audience_handler_test.go`; a prune test with a personal consumer is in `tests/functional/repositories/consumer/registry_prune_test.go`.
- Accept (3.1–3.10): `personal-llm-consumers › Default audience`, `› Personal MCP consumer`, `› Personal LLM consumer`, `› Personal consumer without a default`, `› Glob default does not count`, `› Detaching the only registry with a default`, `› Switch refused`, `› Same value accepted`, `› Create with keys`, `› Update with an empty list`, `› Hybrid gateway`, `› Application consumer on a hybrid gateway`; `owned-key-attachment › Owned key onto an application consumer` (create and PUT half).
- [x] 3.11 Run VG and VR.

## Phase 4: S3c admin auth rules (base P2b)

Depends: P2b. Est.: ≈285 (code 120 / test 165). Commit boundary: (a) `feat`; (b) `chore(docs)`: `make docs`.

- [x] 4.1 `pkg/domain/auth/repository.go`: `ListFilter.ExcludeOwned bool`, `ListFilter.OwnerID string` (A1). `pkg/infra/repository/auth/repository.go`: list and count add `AND ($k::boolean IS NOT TRUE OR owner_id IS NULL) AND ($m = '' OR owner_id = $m)`. The compiler keeps the unfiltered `List` (`compiler.go:462,725`).
- [x] 4.2 `pkg/common/errors/errors.go`: `ErrManagedByOwner`. `pkg/domain/auth/errors.go`: `ErrOwnedKey`. `httpio/errors.go` `MapDomainError`: → 422 `owned_key` (DD10).
- [x] 4.3 `pkg/api/handler/http/auth/list_auth_handler.go` (`:61-93`): always sets `ExcludeOwned`; `?owner_id=<sub>` sets `OwnerID` and clears `ExcludeOwned`. Swag `@Param owner_id`. `response/auth_response.go`: `OwnerID json:"owner_id,omitempty"`. The secret and hash are never present.
- [x] 4.4 `pkg/app/auth/updater.go`: an owned key → `ErrOwnedKey`. `pkg/app/auth/rotator.go`: `RotateInput.OwnerID`; an owned key needs `OwnerID == existing.OwnerID`, else `ErrOwnedKey` (DD14). The admin rotate handler passes `""`. Swag `@Failure 422` on PUT and rotate.
- [x] 4.5 The admin auth create DTO has no `owner_id`. Assert that the decoder drops it and that the creator never sets it.
- [x] 4.6 `pkg/app/policy/warnings.go:285` `apiKeyAuths`: skip `IsOwned()`.
- [x] 4.7 Test `tests/functional/repositories/auth/repository_test.go`: with 3 application keys and 2 owned keys, `ExcludeOwned` → 3 items and total 3. `OwnerID=alice` → 1 item. The default filter → 5.
- [x] 4.8 Test `list_auth_handler_test.go`, `get_auth_handler_test.go` and the update/rotate handler tests: list hides owned keys, `?owner_id` lists the owner's key, get shows `owner_id` without the hash, and PUT and rotate → 422 `owned_key` with no repo write.
- [x] 4.9 Test `pkg/app/auth/{updater,rotator}_test.go`: owner match and mismatch. Admin `DELETE` on an owned key goes through the deleter unchanged (detach, TTL eviction, invalidation, `Signal`). Test `pkg/app/policy/warnings_test.go`: owned keys only → no api-key warning.
- Accept (4.1–4.9): `owned-api-keys › List hides owned keys`, `› List by owner`, `› Get shows the owner`, `› Update and rotate refused`, `› Admin revocation` (unit half; the end-to-end check is in 10.8 and 15b.2), `› Owner in an admin create body`, `› Owned keys only`.
- [x] 4.10 Run VG and VR.

## Phase 5: S3d `consumer_auth` link columns (base P2a)

Depends: P2a. Est.: ≈290 (code 120 / test 170). Commit boundary: (a) `test`: golden bytes for an application consumer with application links, captured on P2a; (b) `feat`; (c) `chore`: mocks.

- [x] 5.1 Create `pkg/infra/database/migrations/20261005120200_add_consumer_auth_grant.go`: three nullable columns and `consumer_auth_grant_check`, following the design. The CHECK counts `num_nonnulls(level, priority, granted_at)` (0, or 3 with a known level, `priority >= 0` and a finite `granted_at`): the earlier `level IN (…) AND priority >= 0` form evaluated to NULL, and so passed, when `level` or `priority` alone was NULL.
- [x] 5.2 Create `pkg/domain/consumer/auth_link.go`: `GrantLevel` (`user`/`group`/`all`), `ParseGrantLevel`, `Rank()`, `DefaultGrantPriority = 1`, `AuthLink{Level, Priority, GrantedAt}`, `Validate()`, and `ErrInvalidAuthLink` in `errors.go`.
- [x] 5.3 `pkg/domain/consumer/consumer.go`: `AuthLinks map[ids.AuthID]AuthLink json:"auth_links,omitempty"`, `RehydrateParams.AuthLinks`. `repository.go`: `AttachAuth(ctx, consumerID, authID, link *AuthLink)`. Callers pass `nil` for now (behaviour-neutral). Run `go generate ./pkg/domain/consumer/...`.
- [x] 5.4 `pkg/infra/repository/consumer/repository.go`: the `auth_links` `json_object_agg` subselect, filtered on `level IS NOT NULL`. `AttachAuth` (`:413-431`): `nil` keeps `ON CONFLICT DO NOTHING`; non-nil upserts the three columns. `replaceAuthLinks` is unchanged.
- [x] 5.5 `pkg/runtimeconfig/snapshot/adapters/consumer_repository.go`: the new `AttachAuth` signature keeps the read-only error.
- [x] 5.6 Test the migration (`PG_TEST_URL`): up and down twice; existing links stay `NULL`; a half-filled row → 23514. Accept: `owned-key-attachment › Existing links untouched`, `› Half-filled link refused`.
- [x] 5.7 Test `auth_link_test.go`: level table, `Rank`, priority below 0, zero `granted_at`.
- [x] 5.8 Test `codec_test.go`: golden bytes from 5(a) with no `auth_links`; a personal consumer round trips `{group, 2, 2026-10-01T09:00:00Z}` with the key in `auth_ids`. Accept: `owned-key-attachment › Codec round trip`, `› Application consumer bytes`.
- [x] 5.9 Test `tests/functional/repositories/consumer/repository_test.go`: the upsert changes P1's priority and leaves P2's link alone; re-sending the same values is a no-op; `auth_links` holds personal rows only; deleting personal P1 cascades its links while the owned auth survives with its P2 link. Accept: `owned-key-attachment › Priority change` (repository half); `personal-llm-consumers › Delete` (repository half).
- [x] 5.10 Run VG and VR.

## Phase 6: S3e attach with link attributes (base: the later of P3 and P5)

Depends: P3, P5. Est.: ≈280 (code 100 / test 180). Commit boundary: (a) `feat`; (b) `chore`: mocks; (c) `chore(docs)`: `make docs`.

- [x] 6.1 Create `pkg/api/handler/http/consumer/request/attach_auth_request.go`: `{level?, priority?, granted_at? (RFC 3339)}` with `priority` defaulting to 1, and a `ToLink() (*AuthLink, error)` that returns nil for an empty body. `ToLink` returns nil when none of the three fields is present (`{}` included), defaults `priority` to 1 and parses `granted_at` as RFC 3339 (stored in UTC). It does not validate the link: the domain owns that rule, so a consumer or auth outside the gateway answers 404 even with a bad body. A whitespace-only body counts as no body.
- [x] 6.2 `pkg/api/handler/http/consumer/association_handler.go`: `AttachAuth` accepts an optional body. An empty body behaves as today. Swag `@Param body`, `@Failure 422`.
- [x] 6.3 `pkg/app/consumer/associator.go` `AttachAuth(ctx, gatewayID, consumerID, authID, link)` (DD7): personal consumer plus owned key needs a non-nil link that passes `Validate`; an application consumer needs `link == nil`; `ValidateAuthConfig` catches the audience mismatch; the cross-gateway check stays as today. Run `go generate ./pkg/app/consumer/...`. The link rule is the domain method `Consumer.ValidateAuthLink` (`auth_link.go`), run after `ValidateAuthConfig`.
- [x] 6.4 Test `association_handler_test.go`: empty body = today's status and body; `level` on an application consumer → 422; a missing `level` or `granted_at` → 422; `priority` defaults to 1.
- [x] 6.5 Test `associator_test.go`: first attach; a second consumer leaves the first link alone; owned key onto an application consumer → 422; application key onto a personal consumer → 422; cross-gateway gets today's status; no repo write on any refusal. One table, `TestAssociator_AttachAuth_AudienceAndLink`: its strict mocks allow exactly one write, `AttachAuth(consumer, key, link)`, which is why a second consumer cannot touch the first link here; the repository half of `› Links are complementary` is P5's upsert test.
- [x] 6.6 Test `tests/functional/repositories/consumer/repository_test.go`: a personal consumer with 500 owned links reads 500 `AuthIDs` and 500 `AuthLinks`. Test `consumer_response_test.go`: the body has `auth_ids` and no `auth_links`. The shared `seedLLMConsumer` helper gives each seeded consumer a registry with a concrete default, which also repairs P5's `TestRepository_AttachAuthUpsertsOnlyThatPersonalLink`: once P3 and P5 met in this base, its personal seeds failed `ErrPersonalNoDefault`.
- Accept (6.1–6.6): `owned-key-attachment › Owned key onto an application consumer` (attach half), `› Application key onto a personal consumer`, `› Application attach unchanged`, `› First attach`, `› Links are complementary`, `› Missing level`, `› Link fields on an application consumer`, `› Priority change`, `› Other gateway`; `personal-llm-consumers › Large personal consumer`.
- [x] 6.7 Run VG and VR.

## Phase 7: S2a `partition: key` (base `develop`)

Depends: —. Est.: ≈310 (code 120 / test 190). Commit boundary: one `feat` commit.

- [x] 7.1 `pkg/app/auth/context.go`: `AuthContext.OwnerID` (A3: this is the single owner of the field). `pkg/infra/context/request_context.go`: `AuthID`, `OwnerID`. `pkg/app/plugins/plugin.go`: `RuntimeScope.AuthID/OwnerID`, `Key() (dimension, id string, ok bool)` (DD8). `executor.go:443` `scopeFromRequest`. `proxy_handler.go:174-175` stamps both from `authCtx`, never from a header.
- [x] 7.2 `pkg/infra/plugins/tokenratelimit/config.go`: `Partition` (`""` or `key`, anything else invalid); `calendar_month` and `calendar_day` in `rules[].time_window` and `aggregate.time_window`, valid only with `key`; `key` with `custom_pricing` or `group_by_header` → invalid.
- [x] 7.3 `keys.go`: `trl:<policy>:key:owner:<id>` or `…:key:auth:<id>`, then `[:p:<2006-01|2006-01-02>]`, then `[:model:<slug>]`. `plugin.go`: `now func() time.Time`, with the TTL running to the UTC period end and floored at `quotaTTL`. `budget.go`: `Scope.Key()` returning `ok == false` → pass, with no Redis read or write.
- [x] 7.4 Test `config_test.go`: no partition is unchanged; an unknown partition, a calendar window without `key`, and `key` with custom pricing or group-by-header are invalid; `key` with `24h` is valid.
- [x] 7.5 Test `keys_test.go` and `plugin_test.go` (miniredis, fake clock): two owners get two counters; one owner on two consumers shares a counter under a global policy; an application key counts as `auth:<id>`; the same owner after a rotation, and after a revoke and re-create (new auth id), keeps its counter; a playground request makes zero Redis ops; the month and day rollover keys and TTL work.
- Accept (7.1–7.5): `token-budget-key-partition › Default unchanged`, `› Unknown partition`, `› Two owners, two counters`, `› One owner across consumers`, `› Application key`, `› Rotation keeps the budget`, `› Revoke and re-create keeps the budget`, `› Playground request`, `› Month rollover`, `› Day key and TTL`, `› Calendar window without partition`, `› Rolling window with partition`, `› Custom pricing`, `› Group by header`; `llm-store-oss-invariance › Existing plugin and MCP tests` (existing suite green).
- [ ] 7.6 Run VG.

## Phase 8: S2b hard limits (base P7)

Depends: P7. Est.: ≈265 (code 100 / test 165). Commit boundary: one `feat` commit, plus `docs/policies.json` in the same commit.

- [ ] 8.1 `tokenratelimit/budget.go` `budgetGate` (`:171,201-213`): under `key` with `appplugins.Blocks(mode)`, a Redis read error → `*appplugins.PluginError{503, "budget_unavailable"}`. A ctx the caller cancelled keeps today's path, as does a post-response accrual error (log and pass). `HandleCounterFailure` does not change (OQ4).
- [ ] 8.2 `plugin.go` `preRequest`: under `key`, `unit: dollars` and a blocking mode, `llmcost.Resolve` with registry rates (`pricing.go:151`) failing → 403 `model_unpriced` before the upstream call.
- [ ] 8.3 `responses.go:72-85`: over budget answers the existing 429 with `error.scope = key`.
- [ ] 8.4 `pkg/app/plugins/catalog_metadata.go:142-273` and `docs/policies.json:112`: `partition` (`key`), the calendar windows, per-owner counting, the 503, the 403, the refused combinations and the uncounted no-auth pass. The fail-open sentence stays true for the default partition.
- [ ] 8.5 Test `plugin_budget_test.go`: a closed miniredis gives 503 in enforce and passes in observe, and the default partition stays fail-open; unpriced on dollars → 403 while tokens pass; a registry rate counts as priced; over budget → 429 with `scope=key`; `TestPlugin_DollarBudget_UnpricedModelAccruesZero` still passes.
- [ ] 8.6 Test `pkg/app/plugins` catalog schema: `partition` and the calendar windows are listed.
- Accept (8.1–8.6): `token-budget-key-partition › Redis down`, `› Observe mode never blocks`, `› Unpriced model on a dollar budget`, `› Registry rate counts as priced`, `› Over budget`, `› Catalog lists the field`.
- [ ] 8.7 Run VG.

## Phase 9: S4a `PersonalKeys` use case (base P4, after P2b)

Depends: P2b, P4. Est.: ≈300 (code 145 / test 155). Commit boundary: (a) `feat`; (b) `chore`: mocks.

- [x] 9.1 `pkg/domain/auth/auth.go`: `MaxOwnedKeyLifetime = 90 * 24 * time.Hour`, `NewOwnedAPIKeyAuth(gatewayID, ownerID, expiresAt, now)`, `ValidateOwnedExpiry(at, now)` (`now < at ≤ now + 90 d`), `ValidateOwner(ownerID)` (one rule for the constructor and every `PersonalKeys` lookup). `errors.go`: `ErrOwnedExpiry`, `ErrInvalidOwner`. The key is named `personal`, with no user id, because auth names reach `principal.subject`, whoami and telemetry. The clock is injected end to end: `SetExpiry(at, now)`, `RotateAPIKey(now)`, `NewRotator(…, now)`; `NewAPIKeyAuth` judges its expiry against its own `CreatedAt`, and the admin updater passes one `time.Now().UTC()` for the expiry check and `UpdatedAt`.
- [x] 9.2 Create `pkg/app/auth/personal_keys.go`: the `PersonalKeys` interface plus implementation, with `//go:generate mockery`. The behaviour:
  - `Create`: run `ValidateOwnedExpiry` (inside `NewOwnedAPIKeyAuth`, built before any I/O), refuse a hybrid gateway (`ErrPersonalKeyHybrid`, wraps `ErrValidation`), pre-check with `FindByOwner` (409), then `Save`, where a race hits the unique index and gives `ErrOwnedKeyExists`. Then run the creator's side effects: `AuthTTLName` and `AuthKeyTTLName`, `invalidation.GatewayData`, `Signal`.
  - `Rotate`: `FindByOwner`, then `Rotator.Rotate{Expiry, OwnerID}`. An absent expiry keeps the current one, unless it has passed: then `ErrOwnedExpiry` (422) before any write. A present one must pass the cap. The links are untouched, and their ids are read before the rotation so a listing failure never strands a rotated secret.
  - `Revoke`: `FindByOwner`, then `Deleter.Delete`, which detaches every link.
  - `Get`: `FindByOwner` plus the `consumers.ListByAuthID` ids, with `[]` when there are none.
  - Every lookup goes through `find`: `ValidateOwner`, `FindByOwner`, then `Auth.ManagedBy(owner)`, which turns anything not owned by the caller into `ErrNotFound`.
  - `PersonalKey` is `{Auth, ConsumerIDs}`. The raw secret lives only in `Auth.RawKey`.
- [x] 9.3 `pkg/container/modules/auth.go`: provide `NewPersonalKeys` with `now = func() time.Time { return time.Now().UTC() }` (the method value `time.Now().UTC` would freeze the clock at wiring time). The provider takes `consumerdomain.Repository` and passes it as the `Reader`, so no view provider is needed.
- [x] 9.4 Test `pkg/domain/auth/auth_test.go`: `ValidateOwnedExpiry` edges (now, +90 d, +90 d +1 s, the past).
- [x] 9.5 Test `personal_keys_test.go` (mocks, fixed clock, `cache.NewTTLMapManager`): the first key comes back with no links and the raw key; the 409 pre-check; the race 409 from the repository; hybrid 422; expiry bounds; rotate keeps the id and links and evicts the old hash; rotating an expired key works; rotate, revoke and get each → `ErrNotFound` without a key or on a key the caller does not own; an expired key rotated without a new expiry → 422 with no write; revoke then re-create works; error paths (gateway or owner lookup failing on create, consumer listing failing on get and rotate) write nothing and signal nothing.
- Accept (9.1–9.5): `personal-key-endpoints › First key`, `› Hybrid gateway`, `› Second key`, `› Concurrent creates` (use-case half), `› Bounds on create`, `› Rotate`, `› Rotate an expired key`, `› Nothing to rotate`, `› Revoke and re-create`, `› Nothing to revoke`.
- [x] 9.6 Run VG.

P10 hand-off (from the P9 review):
- The DTO maps `key` from `PersonalKey.Auth.RawKey` on create and rotate only. GET never maps it (the stored row has none, but the mapping must not rely on that).
- The handler answers 403 when `callerSubject(c)` is empty, before calling `PersonalKeys`. The use case's `ErrInvalidOwner` (422) is a backstop, not the contract.
- Ordering is validation before lookup: a bad `expires_at` answers 422 even for a caller without a key (rotate validates the body before `FindByOwner`), and the handler must decode and validate the body before calling the use case, so a malformed body is never a 404.

Follow-up, out of P9 scope: the auth repository `Update` should compare-and-set on the previous `key_hash` (`UPDATE … WHERE id = $1 AND key_hash = $prev`), so two concurrent rotations of one key end with one success and one 409 instead of the last writer silently winning while the first caller holds a secret that no longer works. Applies to the admin rotate and `PersonalKeys.Rotate` alike.

## Phase 10: S4b self-only HTTP (base P9)

Depends: P9. Est.: ≈345 (code 130 / test 215). Commit boundary: (a) `feat`: handler, DTOs, routes, wiring; (b) `test`: functional; (c) `chore(docs)`: `make docs` (≈380 generated lines).

- [x] 10.1 Create `pkg/api/handler/http/store/llm_key_handler.go`: GET, POST, POST rotate and DELETE on `callerSubject(c)` (`requests_handler.go:212`) only. An empty subject → 403. Full swag annotations (`@Success 200/201/204`, `@Failure 403/404/409/422`).
- [x] 10.2 Create `store/request/create_llm_key_request.go` (`expires_at`, required) and `store/request/rotate_llm_key_request.go` (`expires_at?`). Body `owner_id`, `principal_sub` and `consumer_id` are not decoded. Create `store/response/personal_key_response.go`: `{id, consumer_ids, key (create and rotate only), key_prefix, key_suffix, expires_at, enabled, created_at, updated_at}`, with no hash and no link attributes.
- [x] 10.3 `pkg/server/router/admin_router.go:225-247`: routes under `/:gateway_id/store` with `RequireInteractiveIdentity()` (`admin_authz.go:108`). Wire in `pkg/container/modules/{store,server_admin}.go`; `admin_router_wiring_test.go` must pass.
- [x] 10.4 Test `llm_key_handler_test.go`: a service credential → 403; a body owner is ignored; the status codes; GET never returns `key`.
- [x] 10.5 Run `make docs`. Test `docs/openapi_test.go`: the four paths, their DTOs and their status codes. Accept: `personal-key-endpoints › Paths in the document`.
- [x] 10.6 `tests/functional/common_test.go`: add the `CreateLLMKey`, `RotateLLMKey` and `RevokeLLMKey` helpers (admin JWT with a `user_id`, `setup_test.go:128`).
- [x] 10.7 Test `tests/functional/llm_key_test.go` (C), self flows: create → 201 with `consumer_ids: []`; GET → 200 without a secret; second create → 409; rotate → same id, new secret; DELETE → 204; re-create → 201; no key → 404 on GET, rotate and DELETE; a console user of another tenant → 404, like an unknown gateway; a token without a tenant user (platform `AdminToken`) → 403; the same user on two gateways → two keys. Service credentials are refused with 403 by the group guard (other gateway, no registries scope) and by `RequireInteractiveIdentity()` and the handler guard (all of them); the functional harness mints no service credential, so a router test covers them.
- [x] 10.8 Same file, admin plane on an owned key: `GET /auths` hides it, `?owner_id` lists it, `GET /auths/:id` shows `owner_id`, PUT and rotate → 422 `owned_key`, and admin `DELETE` → 204.
- Accept (10.1–10.8): `personal-key-endpoints › Service credential`, `› Service credential outside the group guard`, `› Another tenant`, `› Platform token`, `› Body owner ignored`, `› First key`, `› Second key`, `› Another gateway`, `› Metadata without the secret`, `› No key`, `› Rotate`, `› Nothing to rotate`, `› Revoke and re-create`, `› Nothing to revoke`; `owned-api-keys › List hides owned keys`, `› List by owner`, `› Get shows the owner`, `› Update and rotate refused`, `› Admin revocation` (admin-plane half).
- [x] 10.9 Run VG and VF.

P10 notes (from the P10 apply):
- Defense in depth: besides `RequireInteractiveIdentity()` on the routes, the handler refuses with 403 anything but a console user with a tenant and a subject, so a platform token cannot hold a key. `pkg/server/router/admin_router_test.go` builds the admin router and proves a gateway-bound service credential with the registries scope gets 403 from the route guard on all four routes.
- A second create answers 409 `already_exists` with the hint to rotate or revoke: `ErrOwnedKeyExists` wraps `commonerrors.ErrPersonalKeyExists`, mapped before `ErrAlreadyExists`.
- `expires_at` is read with the admin API's rule, now `httpio.ParseExpiresAt`: a malformed value says "expires_at must be an RFC 3339 instant". On rotate, absent, null and empty all keep the current expiry.
- Size is over the 400 budget: five new production files carry license headers and the four handlers carry swag annotations. Generated swagger/openapi is outside the budget.

Follow-ups, out of P10 scope:
- Rate-limit create, rotate and revoke per (gateway, caller). Every write recompiles the snapshot and invalidates the gateway's data, so a user looping on rotate costs every plane of the gateway.
- Compare-and-set on `key_hash` in the auth repository `Update` (`UPDATE … WHERE id = $1 AND key_hash = $prev`), so two concurrent rotations end with one success and one 409 for the loser, instead of the last writer silently winning (same as the P9 follow-up; applies to the admin rotate too).

## Phase 11: S5a `Data` index + D11 rejections (base P5, rebased on P1)

Depends: P5 (rebase on P1, A3). Est.: ≈325 (code 110 / test 215). Commit boundary: (a) `feat(routing)`: `SourceFallback` and `FallbackOnly` (A2); (b) `feat`: `Data` index and D11.

- [x] 11.1 `pkg/domain/routing/candidate.go`: `SourceFallback`, `Candidate.FallbackOnly()` (true when every source is `fallback`). `pkg/app/routing/resolver.go` uses the domain const instead of `sourceFallback`.
- [x] 11.2 `pkg/app/consumer/consumer_data.go`: the `StoreLink` type; `storeLinks map[ids.AuthID][]StoreLink` and `personal int`, built in `NewData` over **active** personal consumers, each slice sorted once by `(Rank, Priority, GrantedAt, consumer id)`; an auth id with no `AuthLinks` entry is skipped; `HasPersonalConsumers()`, `StoreLinks(id)` (shared, never mutated). `indexBySlug` (`:124`) skips personal consumers. Each slice is also capacity-clipped (`slices.Clip`), so an `append` by a reader reallocates instead of writing into the shared array.
- [x] 11.3 `pkg/app/consumer/data_finder.go:349` `loadAuths`: skip the auth ids of personal consumers (DD12).
- [x] 11.4 D11 rejections:
  - `pkg/api/middleware/auth.go:196` `apiKeyAttachedElsewhere` skips personal consumers.
  - `pkg/api/middleware/auth_chain.go:370` `resolveAPIKey` and `pkg/app/consumer/api_key_consumers.go:148-164` `ForAPIKey` treat `IsOwned()` as an unknown key.
  - `pkg/app/consumer/path_resolver.go:145`: a personal consumer is no match (DD13).
  - Review additions (defense in depth, in case the admin audience rule is bypassed): `data_finder.go` `collectAuths` never puts an owned auth into an application consumer's `rc.Auths`; `pkg/api/handler/http/mcp/whoami_handler.go` `gatewayForKey` and `pkg/app/oauth/consumer_api_key.go` `validAPIKeyAuth` refuse an owned key as an unknown one (`gatewayForKey` also refuses a disabled key).
- [x] 11.5 Test `pkg/domain/routing/candidate_test.go`: the `FallbackOnly` table.
- [x] 11.6 Test `consumer_data_test.go`:
  - The order P4, P2, P1, P3.
  - An inactive consumer is left out, and a gateway with only inactive personal consumers gives `HasPersonalConsumers() == false`.
  - N = 0 gives an empty slice.
  - A personal slug is not in `bySlug`.
  - 64 concurrent readers under `-race`.
  - Accept: `llm-store-gateway › Index order`, `› No links` (index half), `› Inactive consumer is not a link` (index half); `personal-key-isolation › Personal consumer by slug` (unit).
- [x] 11.7 Test `pkg/api/middleware/auth_test.go` (there is no such file: the `AuthMiddleware` suite lives in `auth_resolver_test.go`, so the test went there): a personal key on an application slug answers exactly as an unknown key (401 with an api-key consumer, and the same status and body on an OAuth-only one); an application key of another application consumer → 403. Test `auth_chain_test.go` and `api_key_consumers_test.go`: an owned key → 401 even without a path scope; an application key is unchanged. Test `path_resolver_test.go`. Accept: `personal-key-isolation › Personal key on an application consumer`, `› Personal key on an OAuth-only application consumer`, `› Application key of another consumer`, `› Personal key on MCP`, `› Application key on MCP`. Also tested: `data_finder_test.go` (no owned key in an application consumer's credentials), `whoami_handler_test.go` (owned and disabled keys answer as unknown), `end_user_connections_test.go` (owned key refused even when the consumer holds it).
- [x] 11.8 Run VG.

## Phase 12: S5b middleware store branch (base P11, after P7)

Depends: P11, P7. Est.: ≈300 (code 110 / test 190). Commit boundary: (a) `feat`; (b) `chore`: mocks.

- [x] 12.1 `pkg/domain/consumer`: `StoreSlug = "store"` (it already existed for the MCP Store, so it is reused and its doc says the proxy plane serves `/{StoreSlug}/v1`). Create `pkg/app/consumer/store_key_resolver.go`: `StoreKeyResolver` and `ErrStoreKeyRejected` with mockery. `FindByAPIKey`, then `Enabled ∧ api_key ∧ IsOwned() ∧ GatewayID == gw`. `ErrNotFound` (which includes `ErrExpired`) and every failed check → `ErrStoreKeyRejected`. Infra errors are wrapped with `%w`. As built: `NewStoreKeyResolver(apiKeys, now)` takes a clock and checks `Auth.AcceptsAPIKey(hash, now) ∧ IsOwned() ∧ GatewayID == gw`; the not-found test is `commonerrors.ErrNotFound`, because `authdomain.ErrExpired` wraps that and not `authdomain.ErrNotFound`.
- [x] 12.2 `pkg/api/middleware/auth.go:56-101,161-182`: `serveStore` runs hybrid → 404, then `Data` error → 500, then `!HasPersonalConsumers()` → 404 (byte-identical to the `MatchSlug` miss), then no key → 401, then resolve → 401 or 500. `attach` takes `Principal{Subject: owner_id, Method: api_key}` and `AuthContext{AuthID, OwnerID}`, and `rc == nil` skips the consumer locals. `NewAuthMiddleware` takes `storeKeys`. As built: `serveStore(c, gw, route)` loads `Data` itself after the hybrid check; a nil `storeKeys` answers 404 first, with no `Data` load, and `NewAuthMiddleware` warns once when it is nil; a resolver infra error logs at Warn, a rejection at Debug; `AuthContext.Subject` is the owner, like the principal; the slug test is `consumerdomain.IsStoreSlug`.
- [x] 12.3 `pkg/container/modules/consumer.go` `provideConsumerServices` (both planes, `core_data.go:106`): provide `NewStoreKeyResolver` (with `utcNow`), and `modules/api.go` passes it to `NewAuthMiddleware`.
- [x] 12.4 `proxy_handler.go`: a guard (interim) makes the store slug with no store wiring answer 404 `not_found`. P14 replaces it. Test `TestHandle_StoreSlugIsNotFoundWithoutStoreWiring`.
- [x] 12.5 Test `store_key_resolver_test.go`: the 401 matrix (unknown, disabled, expired, unowned, another gateway, non-`api_key`) and the 500 wrap.
- [x] 12.6 Test `auth_test.go` (there is no such file: the tests went into `auth_resolver_test.go`, the `AuthMiddleware` suite, as in 11.7):
  - The 404 cases (no personal consumers, only inactive ones, hybrid) with a counting `APIKeyFinder` fake that records zero calls, and a body equal to today's unknown-slug body.
  - Rejected keys → 401, including an application key.
  - The key in `X-AG-API-Key` and in `Authorization: Bearer`.
  - Principal and `AuthContext.OwnerID` in ctx.
  - Other slugs unchanged.
- Accept (12.1–12.6): `llm-store-gateway › Other slugs unchanged`, `› Gateway without personal consumers`, `› Only inactive personal consumers`, `› Hybrid gateway`, `› Valid personal key` (unit), `› Rejected keys`, `› Context of a personal request` (middleware half); `personal-key-isolation › Application key on the store`; `llm-store-oss-invariance › Fresh OSS gateway` (unit).
- [x] 12.7 Run VG: `go build ./...`, `go vet ./...`, `go vet -tags functional ./...`, `go test -race ./pkg/...`, `golangci-lint run` on the touched packages, `make license-check`; the slug-routing functional tests (`TestProxyE2E|TestProxyAPIKeyExpiry|TestModelsDiscovery|TestRoutingIntent|TestHybridGatewayGuardE2E|TestDBLessDataPlane`) pass on disposable Postgres and Redis. Hand-written diff vs P11+P7: 414 lines after the review fixes (395 before).
- Follow-up (out of scope, from the P12 review): hash the key once instead of twice (`APIKeyFinder.FindByAPIKey` hashes it, then `StoreKeyResolver` hashes it again for `AcceptsAPIKey`); and a short negative cache for unknown keys on the full plane, so repeated unknown-key probes on a gateway with personal consumers stop reaching Postgres, cleared with `auth_key` on `InvalidateGatewayDataEvent`.

## Phase 13: S5c `StoreSelector` (base P11)

Depends: P11. Est.: ≈375 (code 130 / test 245). Commit boundary: (a) `refactor`: extract `candidatePipeline` from `forwarder.resolveRouting` (`routing.go:47-91`), behaviour-neutral, with the existing forwarder tests green; (b) `feat`: selector and scope; (c) `chore`: mocks.

- [x] 13.1 Create `pkg/app/proxy/store_scope.go`: `storeScope(links) []scopedLink`. `S` = the lower-cased `Registry.Provider()` of the **primary** registries of `user` links only (OQ2). A `group`/`all` link gets `Keep(c) = provider(c) ∉ S` when `S ≠ ∅`. A link left with no primary registry is dropped. The helper is shared with `StoreModels`. `scopedLink` embeds the `StoreLink`, keeps its order (so the selector can rely on the DD4 sort), and carries the substituted providers as a predicate (`keepsRegistry`). The `CandidateFilter` comes from that predicate (`filter()`, nil when nothing is substituted), so no synthetic `Candidate` is built per link.
- [x] 13.2 `pkg/app/proxy/routing.go`: `candidatePipeline(ctx, intent, needed, rc, data, keep, listingMode)` runs Resolve → Keep → capability → files → listing. The store mode drops a deferring candidate on `VerdictAbsent` with no keep-all fallback (DD17); `VerdictListed` and `VerdictUnknown` keep it (OQ3). The slug mode keeps `routing.go:115-117`. As built: `candidatePipeline` is a struct (`resolver`, `listing`, `logger`) that replaces the forwarder's `resolver` and `listing` fields, and `run(ctx, candidateQuery)` takes the arguments as one struct, with `strictListing bool` as the listing mode. `CandidateFilter` lives here, next to its only use in the pipeline. The forwarder passes `keep == nil` and `strictListing == false`, so the slug path stays behaviour-neutral: the existing forwarder suite passes unchanged.
- [x] 13.3 Create `pkg/app/proxy/store_selector.go`: `StoreSelector`, `StoreSelectInput`, `StoreSelection`, `ErrNoStoreConsumer` (wraps `ErrModelDenied`), with mockery.
  - A link admits when a `!FallbackOnly()` candidate remains, and for a zero intent that candidate also has a `Default`.
  - Pool intents (P11 review note): `resolveInlinePool` (`pkg/app/routing/resolver.go`) looks members up through `registriesByID`, which includes `FallbackBackends`, and tags every member `pool:<alias>`, so `FallbackOnly()` is false for a fallback-chain member. Admission must not go through such a registry: tag fallback-chain members with `SourceFallback` there, or base pool admission on membership in `rc.Registries`.
  - Specificity: 0 for a literal allow entry, 1 for a glob, 2 with no allow-list, 0 for the other intent kinds.
  - The winner is the minimum of `(Rank, Priority, specificity, GrantedAt, id)`.
  - Pool alias: when every link refuses, the first resolver error decides, so an unknown alias → 400 and a known alias with no member left → 403.
  - The selector holds no state and never calls a repository, gRPC or Redis.
  - As built: admission takes candidates that are `!FallbackOnly()` **and** whose registry is in `rc.Registries`. That covers the pool case without touching `resolveInlinePool`, so the slug path's `route_source` is unchanged. The pool error follows the spec: 400 (`ErrUnknownPoolAlias`) only when every effective link refuses with an unknown alias, and 403 when any link defines the alias but has no primary member left, so it is not decided by the first error. The links arrive in DD4 order, so the loop stops at the first admitting tier (`Rank`, `Priority`), or as soon as a literal match wins. The `StoreSelector` doc comment states that contract and the OQ3 behaviour. Review fixes: a zero intent needs a `Default` only when the route has no capability, so `GET`/`DELETE /store/v1/files/{id}` work without one. `StoreSelection` also carries the parsed `Intent`, the `Ref` and the winner's `*CandidateSet` (already filtered by `Keep`), so P14 neither re-parses the body nor re-resolves. Each refused effective link is logged at debug (`consumer_id`, `level`, `priority`, `reason`; skipped unless debug is enabled). `type specificity int` replaces the `-1` sentinel.
- [x] 13.4 `pkg/container/modules/proxy.go`: provide `NewStoreSelector`.
- [x] 13.5 Test `store_selector_test.go`, worked example table (mock `ModelListing`; as built, a hand-written `storeCatalog` fake gives Listed, Absent for a provider that has a listing, and Unknown for a provider without one, as `modelListing` does). Also asserted: kept providers `{openai, deepseek}` for "without D `gpt-4.1` → A", and with no model, A wins over a `user` D whose only default is on a fallback registry: `gpt-4.1` → denied, `gpt6` → D, `opus-5.5` → C, `opus-4.8` → B, empty → D, `@openai/gpt-4.1` → denied, `auto` → D, without D `gpt-4.1` → A with `Keep == nil`, without D `deepseek-chat` → denied, B at p0 → B. Accept: `store-consumer-selection › gpt-4.1 is denied`, `› gpt6 goes to D`, `› opus-5.5 goes to C`, `› opus-4.8 goes to B`, `› No model goes to D`.
- [x] 13.6 Test substitution and admission: A's OpenAI is substituted while A's Mistral survives; a `user` consumer's fallback provider does not enter `S` (OQ2); fallback never admits. Also tested: a substituted registry of a surviving group consumer does not admit (`gpt-4.1` → 403). Pool aggregation is tested too: a pool whose only member is a fallback-chain registry, next to a `user` link without pools (mixed refusals), gives 403 `ErrNoStoreConsumer` and not `ErrUnknownPoolAlias` (P11 review note); so does a known alias whose every member is substituted. Accept: `› User link narrows a provider`, `› Other providers of a group consumer survive`, `› Fallback does not admit`.
- [x] 13.7 Test listing and ordering (plus: a literal entry beats a glob): Anthropic with no allow-list does not capture `gpt-4.1` when the verdict is Absent; it is selected when the verdict is Unknown (OQ3); specificity applies at equal level; priority beats specificity; a glob beats no allow-list; the oldest grant wins. Accept: `› Anthropic without allow-list does not capture gpt models`, `› Unknown listing keeps the candidate`, `› Specificity at equal level and priority`, `› Priority before specificity`, `› Glob before no allow-list`, `› Oldest grant breaks a tie`.
- [x] 13.8 Test intents (plus: a bare `provider/model` is a native short model; `@openai` → 400 `ErrInvalidModelRef`; N = 0 with `pool:fast` → 403, not 400; capability routes: embeddings skip a `user` link whose provider lacks them, or answer 403 when no link has them; a files id selects the link whose provider owns it, without a default; the selection carries `Intent`, `Ref` and the `Keep`-filtered candidates): `pool:fast` → P1 and `pool:slow` → 400; `auto` → P2; `@anthropic/opus-5.5` → C and `@openai/gpt-4o` → 403; empty → D with `gpt6`; N = 0 → `ErrNoStoreConsumer`, which `errors.Is` matches against `ErrModelDenied` (OQ1). Accept: `› Pool alias`, `› Auto`, `› Qualified reference`, `› Empty model`; `llm-store-gateway › No links` (selector half).
- [x] 13.9 Test 64 goroutines × different intents under `-race`, each equal to the sequential result, plus `BenchmarkStoreSelector_N10`. Accept: `› Concurrent selection`. As built, these live in their own file, `store_selector_concurrency_test.go`, so they can move to their own commit or to P14 without edits. Benchmark (worst case: all 10 links in one tier, each resolved): ≈10–14 µs/op (noisy machine), ≈15 KB/op, 167 allocs/op, including body parsing.
- [x] 13.10 Run VG and measure the diff. If it is over 400, move 13.9 to P14. Measured against the P11 head after the review fixes, with new files `git add -N`'d: 747 hand-written lines (719 added, 28 removed). By commit: (a) `refactor` candidatePipeline 87 (`routing.go`, `forwarder.go`); (b) `feat` selector, scope, DI and tests 595 (`store_scope.go` 73, `store_selector.go` 190, `store_selector_test.go` 329, `modules/proxy.go` 3), plus the generated mock (96, outside the budget); (c) `test` concurrency and benchmark 65 (`store_selector_concurrency_test.go`). (b) alone is over budget; about 60 of its lines are license headers and imports. 13.9 is ready to move to P14 if the orchestrator wants that.

## Phase 14: S5d handler store path + `StoreModels` (base P13, after P12, rebased on P1)

Depends: P12, P13 (rebase on P1). Est.: ≈290 (code 110 / test 180). Commit boundary: (a) `feat(proxy)`: `ForwardInput.Keep` and `ListModelsInput.Keep`, slug path byte-identical; (b) `feat`: `StoreModels` and handler store path; (c) `chore`: mocks.

- [x] 14.1 `pkg/app/proxy/forwarder.go` and `routing.go`: `ForwardInput.Keep`. When it is set, resolve even for a zero intent, and make `nonCandidateRoutes` (`:455-475`) exclude the substituted LB routes and fallback backends. Empty after `Keep` → `ErrModelDenied`. As built: `ForwardInput` also carries `Resolved *ResolvedRouting` (`Intent`, `Ref`, `Candidates`), which `StoreSelection` now embeds, so the store path neither re-parses the body nor re-resolves: the forwarder takes the selection's intent, sets `RequestedModel` from its `Ref`, and routes over its candidates. `Keep` is applied in both branches by one helper, `keepCandidates` (also used by `candidatePipeline.run`), which answers `ErrModelDenied` when nothing survives; with `Resolved == nil` and `Keep` set, the forwarder resolves even for a zero intent. Because the store path always hands the forwarder a non-nil, `Keep`-filtered set, the existing `nonCandidateRoutes` and `firstAvailableFallback` already exclude substituted LB routes and fallback backends, and the short-model chain is built from the same set; no change was needed there. `Keep == nil` and `Resolved == nil` leave the slug path byte-identical.
- [x] 14.2 `pkg/app/proxy/list_models.go`: `ListModelsInput.Keep`. Create `store_models.go`: `StoreModels.List/Get`, the union of `ModelsLister.List` per effective link with `Keep` combined with `!FallbackOnly()`, deduplicated and sorted, with `[]` when there is nothing (OQ1). As built: `StoreModels.List` calls `ModelsLister.List` once per `storeScope` link with `ListModelsInput.Keep = scopedLink.primaryFilter()` (substitution filter AND `!FallbackOnly()`); the first link in DD4 order wins a duplicate id (`owned_by`), and `Get` reads `List`. A lister error fails the listing, as on the slug path.
- [x] 14.3 `pkg/api/handler/http/proxy/proxy_handler.go:139-195`:
  - `WithStore(selector, models)` and `handleStore`, which replaces the 12.4 guard.
  - `/models` and `/models/{id}` go to `StoreModels` and stamp no consumer.
  - Otherwise `StoreSelector`; then set `authCtx.ConsumerID`, call `stampConsumerTrace(c, rc, authCtx)`, and run the shared forward tail with `Keep`.
  - As built: the shared tail is `forward(c, ForwardInput)` (the cancel and streaming code moved there unchanged, its comment kept); `newForwardRequest` builds the `RequestContext` once (playground verdict, `stampAuth`), and the store path hands that same context to the selector and the forwarder. `requestCaller` (gateway id, `AuthContext`, `Data`) is shared with `resolveConsumer`; `methodNotAllowed`, `stampEndUser` and a generic `serveModels` are shared with the slug path. Order on the store path: no wiring → 404; no caller → 401; a caller that is not an owned `api_key` → 401 (defense in depth behind the middleware); method → 405; `/models` → `StoreModels` with no consumer stamped; otherwise select → 403/400, then `authCtx.ConsumerID`, `stampConsumerTrace`, end user, forward with `Keep` and `Resolved`. The selector also refuses an ambiguous chat body with `ErrAmbiguousRequestBody` before parsing it, so a store request answers 400 `invalid_request_body` as a slug request does, not a 403 from a model the decoder read one way.
- [x] 14.4 `pkg/container/modules/proxy.go`: provide `NewStoreModels` and call `WithStore` on both planes. The `Proxy` module serves both planes, so one provider covers them.
- [x] 14.5 Test `forwarder_test.go`: `Keep` excludes a substituted LB route and a substituted fallback; `Keep == nil` leaves the slug path unchanged (existing suite). Accept: `store-consumer-selection › Substituted fallback is not used`, `› Fallback serves the selected consumer` (unit). As built: `TestForward_KeepExcludesSubstitutedRegistries` (`Keep` alone: a substituted LB route, a substituted fallback after the balancer, `Keep == nil` keeps the fallback, nothing kept → `ErrModelDenied` with no upstream call), `TestForward_ServesTheStoreSelection` (selector output fed to the forwarder: A's substituted OpenAI fallback is never invoked for `mistral-large`; without D, A's DeepSeek fallback serves `gpt-4.1` after OpenAI fails) and `TestForward_StoreConsumerSharesOneBalancerAcrossOwners` (two owners, one balancer keyed `G:P`, moved here from 14.7 because the handler suite mocks the forwarder). Note for 15a.3: on the slug path and the store path alike, a short-model request drops a no-allow-list fallback whose provider catalog answers `VerdictAbsent` for that model, so with a seeded DeepSeek listing that lacks `gpt-4.1` the fallback is not tried for `gpt-4.1`; the unit test uses a catalog with no DeepSeek listing.
- [x] 14.6 Test `store_models_test.go`: the union with substitution is `gpt6`, `opus-4.8`, `opus-5.5`; without D it is `gpt-4.1`, `gpt6`, `opus-4.8`, `opus-5.5`; `deepseek-chat` never appears; N = 0 → `[]`; `Get` returns 200 for a listed id and 404 otherwise. Accept: `llm-store-gateway › Union with substitution (worked example)`, `› Union without a user link`, `› No links` (listing half). As built: `TestStoreModels_ListIsTheUnionAfterSubstitution` and `TestStoreModels_GetFindsOnlyListedModels` (real `ModelsLister`, `storeCatalog` gained `ListModels`).
- [x] 14.7 Test `proxy_handler_test.go` (store path):
  - 403 with no upstream call.
  - `ConsumerID`, `consumer.id`, `auth_id` and `principal_subject = owner_id` stamped after selection.
  - The request ctx carries `AuthID` and `OwnerID`.
  - `/models` stamps no consumer.
  - The plan is the selected consumer's policies plus the globals, with no MCP-wide policies.
  - One balancer keyed `G:P` serves two users.
  - Accept: `llm-store-gateway › Allowed and denied models`, `› Context of a personal request`, `› Event fields`, `› Shared balancer`, `› Policies of the selected consumer`; `usage-auth-id-telemetry › Personal key subject`.
  - As built: `TestHandleStore_ForbiddenWithoutAnUpstreamCall` (denied model, N = 0), `TestHandleStore_ServesThroughTheSelectedConsumer` (the forwarder gets the selected consumer itself, its policies `[P2, global]` and not the MCP-wide one, `Resolved.Ref`, `AuthID`/`OwnerID` on the request, `ConsumerID` on the ctx `AuthContext`, and `consumer.id`, `auth_id`, `principal_subject`, `principal_method` on the trace), `TestHandleStore_ModelsListTheUnionAndStampNoConsumer`, `TestHandleStore_RequiresAPersonalKey`. They use the real selector and `StoreModels` with a mocked forwarder. The shared balancer is asserted in 14.5.
- [x] 14.8 Run VG. Results: `go build ./...`, `go vet ./...`, `go vet -tags functional ./...` clean; `go test -race` on `pkg/app/proxy/...`, `pkg/api/handler/http/proxy/...`, `pkg/container/...`, `pkg/app/routing/...`, `pkg/app/consumer/...`, `pkg/api/middleware/...` pass; `golangci-lint run` on the touched packages: 0 issues; `make license-check` clean; no `frontend`/`proto` diff; the slug-routing functional tests (`TestProxyE2E|TestProxyAPIKeyExpiry|TestModelsDiscovery|TestRoutingIntent|TestHybridGatewayGuardE2E|TestDBLessDataPlane`) pass on disposable Postgres and Redis. Hand-written diff vs the P14 base (new files `git add -N`'d): 641 lines (601 added, 40 removed): code 286, tests 355; generated mock 156 outside the budget. Over the 400 target; it splits cleanly at the commit boundary: (a) app layer (`ForwardInput.Keep`/`Resolved`, `ListModelsInput.Keep`, `StoreModels`, their tests) ≈ 335; (b) handler store path, DI and handler tests ≈ 306.
- [x] 14.9 Review fixes (on top of the two P14 commits):
  - Traffic labeling: `TrafficLabelsMiddleware` runs before the handler and a store request has no consumer until selection, so store requests are never offered for labeling. Not fixed in P14; recorded as design Q6 and pinned by `TestHandleStore_TrafficLabelingDoesNotSeeStoreRequests`. Follow-up, one of: set the selected consumer on the ctx after selection and move the store offer after `c.Next()`; or an offer hook in the forwarded handler.
  - Listing URL: `ForwardInput.RouteSlug` (the handler sets `store`) feeds `modelsPath`, so a `model_not_supported` 404 on the store path says `GET /store/v1/models` and never names the personal consumer's slug; empty keeps the consumer slug. Test `TestForward_StoreModelMissPointsAtTheStoreListing`.
  - `StoreModels` cost: `NewStoreModels(resolver, catalog)` owns a `modelsLister` and calls its `collect(ctx, in, listed)` with one per-request `listed` memo, so each provider's catalog listing is read at most once per request; `Get` stops at the first link that lists the id. Test `TestStoreModels_QueriesEachProviderListingOncePerRequest`.
  - Rate limit: `Forwarder.CheckRateLimit` (the former `checkRateLimit`) is on the interface; the store path calls it before `Select`, so an over-limit caller gets 429 and a denied store request is charged as on the slug path. `Forward` skips the limiter and the ambiguity scan when `Resolved != nil` (the selector already scanned the body), so a store request is charged once. Tests: 429 before selection (handler); a limiter mock with no expectations in `TestForward_ServesTheStoreSelection`.
  - Attribution: `stampCallerTrace` (auth id, principal) runs before the method check and selection, so 403, 400 and 405 store responses carry `auth_id` and `principal_subject`; `stampConsumerTrace` (consumer only) runs after selection; `/models` carries the caller and no consumer.
  - Handler tests added: 405, 401 for a non-`api_key` method, an invalid end-user header after selection (consumer already stamped), 400 for an ambiguous body, 429 before selection, a streaming result through the shared tail, and a user-level link whose `Keep` excludes the substituted provider (`Resolved` holds only the surviving registry).
  - Cleanups: `handleModels` lost its unused `authCtx`; the `storeCatalog` catalog methods sit next to the type; `invokerByProvider` calls `t.Helper()` and reuses `invocationRecorder`.

## Phase 15a: S5e full-plane end to end (base P14, after P6, P8 and P10)

Depends: P6, P8, P10, P14. Est.: ≈350 (test only). Commit boundary: one `test` commit.

- [x] 15a.1 Create `tests/functional/llm_store_test.go`, setup helpers:
  - OpenAI, Anthropic and DeepSeek provider stubs (from `proxy_e2e_test.go`), with switchable failure.
  - A seeded catalog listing.
  - Personal consumers A–D created through the admin API (201 with `audience=personal`).
  - Ana's key through `POST /principal/llm-key`.
  - Links through `POST /consumers/:id/auths/:auth_id` with `{level, priority, granted_at}`.
- [x] 15a.2 Worked example on chat: `gpt-4.1` → 403, `gpt6` → D, `opus-5.5` → C, `opus-4.8` → B, no model → D. `/store/v1/models` → `gpt6`, `opus-4.8`, `opus-5.5`. Accept: `store-consumer-selection › Worked example` (full plane), `llm-store-gateway › Union with substitution (worked example)`.
- [x] 15a.3 Detach D: `gpt-4.1` → A. With the OpenAI stub failing, it falls back to DeepSeek. `deepseek-chat` → 403. Accept: `store-consumer-selection › Fallback serves the selected consumer`, `› Fallback does not admit`; `llm-store-gateway › Union without a user link`.
- [x] 15a.4 Freshness on the full plane: re-attaching with a priority change re-selects; detach one of two, then the last one, leaves `[]` with chat → 403 (OQ1); deleting a personal consumer keeps the key (`GET /principal/llm-key` shows the remaining `consumer_ids`); an inactive linked consumer is skipped. Accept: `owned-key-attachment › Priority change`, `› Detach one of two`, `› Detach the last one`; `personal-key-endpoints › Linked by the reconcile`; `personal-llm-consumers › Delete`; `llm-store-gateway › No links`, `› Inactive consumer is not a link`.
- [x] 15a.5 Isolation: an application key on `/store/v1` → 401; Ana's key on an application slug → 401; a personal consumer's slug → 404; Ana's key on MCP → 401; a gateway without personal consumers → 404 on `/store/v1/models`. Accept: `personal-key-isolation › Application key on the store`, `› Personal key on an application consumer`, `› Personal consumer by slug`, `› Personal key on MCP`; `llm-store-oss-invariance › Fresh OSS gateway`.
- [x] 15a.6 Rejected keys end to end: no key, an unknown key, a revoked key and another gateway's key all → 401. Accept: `llm-store-gateway › Valid personal key`, `› Rejected keys` (full plane).
- [x] 15a.7 Rotation across processes: the admin process rotates; after `InvalidateGatewayDataEvent` the old secret → 401 on the proxy and the new one → 200. Detaching in the admin process changes the proxy's `/models` after the event. Accept: `llm-store-gateway › Rotation seen by another replica`, `› Stale key cache after a detach`.
- [x] 15a.8 Budget: a global `token_rate_limiter` with `partition: key` hits 429 across requests served by two consumers for one owner. Accept: `token-budget-key-partition › One owner across consumers` (end to end).
- [x] 15a.9 Run VG and VF.

P15a as built (`tests/functional/llm_store_test.go`, helpers in `common_test.go`, catalog seed in `setup_test.go`):
- Catalog: `setup_test.go` seeds Anthropic `opus-4.8` and `opus-5.5` (source `functional`) after the admin boots and before the proxy does, because the proxy caches a provider's listing for 24 h and the live models.dev catalog the admin syncs at boot has no `opus-4.8`. OpenAI and DeepSeek are not seeded: their listings come from the live sync, and an OpenAI seed would make the listing authoritative for other tests in an offline run.
- Stubs: the Anthropic and DeepSeek chat endpoints are compile-time constants (no `base_url`), so they cannot be faked. B and C each carry a consumer-attached `model_allowlist` reject policy whose allow-list names the consumer: a request selected for them answers 403 from their own policy before any upstream call, which proves both the selection and `› Policies of the selected consumer`. A's DeepSeek fallback is an `openai_compatible` registry on a stub with switchable failure (`switchableUpstream`); that provider's listing is not authoritative, so the fallback is really exercised for `gpt-4.1` (the P14 note).
- 15a.2 (`TestLLMStore_WorkedExample`): the five rows, D's `gpt6` default in the upstream body, no hit on A. `/store/v1/models`: OpenAI lists exactly `gpt6` and everything else is Anthropic (B lists the live Anthropic catalog plus the seed), so the exact three-item union of the spec holds only for a seeded-only catalog. The usage event: one OTLP log record holds `trustgate.auth.id` = key, `trustgate.principal.subject` = owner and `trustgate.consumer.id` = D (protowire walk of the export, `otlpRecordWith`). `GET /principal/llm-key` lists A–D (`› Linked by the reconcile`).
- 15a.3/15a.4/15a.7 (`TestLLMStore_FallbackAndFreshness`): rotate, then the old secret answers 401 and the new one 200; C inactive → `opus-5.5` goes to B, active again → C; B re-attached at priority 0 → B; D detached → `gpt6` leaves the listing, `gpt-4.1` → A, and with A's OpenAI failing the DeepSeek stub serves after the retries; `@openai_compatible/deepseek-chat` → 403 always and `deepseek-chat` → 403 when the admin catalog lists `gpt-4.1` (live sync, as in `TestRoutingIntent`); deleting B keeps the key with `consumer_ids` = A, C; detaching A leaves exactly `opus-5.5`; detaching C leaves `[]`, chat 403, `consumer_ids` `[]`.
- 15a.5/15a.6 (`TestLLMStore_KeyIsolation`): the personal key on an application slug (401) and on a personal slug (404) answers byte for byte as an unknown key; on MCP it answers as an unknown key (401); no key, unknown, application key and another gateway's personal key → 401; a key with no links lists `[]` and chats 403; a revoked and an expired (4 s) key → 401; a gateway with only application consumers answers `/store/v1/models` with the unknown-slug 404 for no key, an unknown key and its application key.
- 15a.8 (`TestLLMStore_KeyBudget`): a global `token_rate_limiter` with `partition: key` (aggregate 5 tokens per minute): Ana's `gpt-4o-mini` on X, then 429 on `gpt-4o` served by Y; the only counter is `trl:<policy>:key:owner:<ana>`; Bob still gets 200; after Ana rotates, the new secret still gets 429.
- 15a.9 results (with P14's review fixes merged in): `go build ./...`, `go vet ./...`, `go vet -tags functional ./...` clean; `golangci-lint run --build-tags functional ./tests/functional/...` 0 issues; `go test -race ./pkg/... ./cmd/...` 167 packages ok; `make license-check` clean; no `frontend`/`proto` diff. Full functional package on disposable Postgres and Redis, twice: 420 passed, 4 skipped (the environment skips that predate this change), 0 failed; the repository packages pass with `PG_TEST_URL`. Hand-written size (new files `git add -N`'d): 520 lines (`common_test.go` 266, `llm_store_test.go` 221, `setup_test.go` 31 + 2 removed), over the ≈350 estimate because of the telemetry, budget-rotation, expiry and self-service checks added at apply time.

## Phase 15b: S5e DB-less + docs (base P15a)

Depends: P15a. Est.: ≈180 (test 110 / docs 70). Commit boundary: (a) `test`; (b) `docs`.

- [x] 15b.1 `tests/functional/dbless_data_plane_test.go`: `TestDBLessDataPlane_LLMStore` reuses the 15a helpers. It runs the worked example rows and `/models` on the DB-less DP. It checks a priority change after the next snapshot apply. It checks the warm request: the DP's config-sync fetch count does not move across a second request (add a harness counter if none exists), and the DP has no DB by construction. Accept: `store-consumer-selection › Worked example` (DB-less), `llm-store-gateway › Warm request on DB-less`, `› Priority change on DB-less`.
- [x] 15b.2 Same test: admin `DELETE /auths/:id` → 401 on the DP after the next apply; detaching one link → `/models` lists P2's models only. Accept: `owned-api-keys › Admin revocation`, `owned-key-attachment › Detach one of two` (DB-less half).
- [x] 15b.3 Create `docs/llm-store.md`, covering:
  - the model (personal consumers, personal key, links, levels)
  - the selection rules and the worked example
  - the error table
  - self endpoints and admin attach
  - `partition: key`
  - rollout and rollback
- [x] 15b.4 Same doc, behaviours to document: N = 0 → 403 and `[]` (OQ1); substitution uses primary registries only (OQ2); `VerdictUnknown` lets a registry without an allow-list admit any short model, so admins add allow-lists on such registries (OQ3); fail-closed 503 (OQ4); hybrid gateways are out of v1; `auth_ids` stays in admin responses.
- [x] 15b.5 Run VG and VF.

P15b as built: `TestDBLessDataPlane_LLMStore` reuses `setupStoreFixture` and `assertWorkedExample`. The harness counter is `countingProxy`, a TCP relay in front of the control plane's config-sync port that counts bytes both ways; the DP dials it with a 1 h poll and a 1 h client keepalive, the test waits for the connection to go quiet, sends a warm `gpt6` request (200 from D) and asserts the count did not move (and is positive, so the DP really syncs through it). Then B at priority 0 wins `opus-5.5` after the next apply, detaching A, B and D leaves exactly `opus-5.5`, and admin `DELETE /auths/:id` → 401. `docs/llm-store.md` covers concepts, admin setup, the key lifecycle, routing (404/401 order, substitution, admission, ordering, intent kinds, worked example), errors, `partition: key`, telemetry, freshness, rollout, rollback and out of scope. Its 503 `budget_unavailable` and 403 `model_unpriced` describe P8, which merges before P15b. 15b.5 results: the DB-less suite (`TestDBLessDataPlane|TestDBLessMCPVault`) 5 passed, 0 failed; the rest of VG as in 15a.9. Size: 309 lines (`docs/llm-store.md` 208, `dbless_data_plane_test.go` 101), over the ≈180 estimate (the harness counter alone is ≈50).

## Phase 16: S6 snapshot metrics (base P5)

Depends: P5. Est.: ≈140 (code 75 / test 65). Commit boundary: one `feat` commit.

- [x] 16.1 Create `pkg/app/configsnapshot/snapshot_metrics.go`, following the pattern in `tenant_caps_metrics.go:29`: `otel.Meter("trustgate/configsnapshot")`, `trustgate.configsnapshot.encoded_bytes{flavour, stat=max|total on scoped}`, `trustgate.configsnapshot.scopes` and `trustgate.configsnapshot.entities{kind=auths|owned_auths|personal_consumers|personal_links}` (every scope, hybrid included). No attribute carries a gateway, tenant or scope id; the publish log line gains `scopes`, `largest_scope`, `largest_scope_bytes`. An instrument error is logged and never returned.
- [x] 16.2 `pkg/app/configsnapshot/dispatcher.go:231-319`: record on publish only, never on a dedup. The non-partitioned path records as `global`. The "published config snapshot" log stays.
- [x] 16.3 Test `snapshot_metrics_test.go` (manual reader): catalog, global, scoped max/total and scopes match the published lengths, with 4 attribute sets after a scope is removed; the counts with 2 owned keys and 3 links, and a hybrid gateway's personal consumer counted; OSS data gives zero personal counts; nothing is recorded on a dedup; a no-op meter provider or a refused gauge does not fail the publish nor skip the other gauges. Accept: `config-snapshot-metrics › Partitioned publish`, `› Bounded series`, `› Counts`, `› Hybrid gateway`, `› OSS data`, `› No meter provider`.
- [x] 16.4 Run VG.

## Deploy order

| Step | Action | Where |
|------|--------|-------|
| 1 | DataCore D1 is in prod **before** P1 deploys: events start carrying `auth_id`. | out of repo |
| 2 | P1–P16 merge to `develop` in the merge order above and ship through the normal release train. There is no develop→main promotion. Each PR is inert on deploy, apart from S0 (release note). | TrustGate |
| 3 | **Every TrustGate plane** (admin, proxy, MCP, DB-less DPs, in EU and US) runs a build containing at least P2a, P2b, P3–P6 and P11–P14 **before the app creates any personal consumer**. Check the healthz `version` on every plane and region. An older DP ignores `audience`, `owner_id` and `auth_links`, and would serve a personal consumer at `/<slug>/v1` with its owned keys (D11 not enforced). | TrustGate |
| 4 | Create `token_rate_limiter` policies with `partition: key` or `calendar_*` only after P7–P8 are on every plane: an older binary rejects the config. | ops |
| 5 | The app ships `LlmStoreGrant`, the reconcile (attach with `{level, priority, granted_at}`, `?owner_id` lookup, revoke on offboarding) and the Portal (ENG-1710, ENG-1704). | app |

Rollback: follow the proposal. (1) Disable `partition: key` policies. (2) `UPDATE consumers SET active = false WHERE audience = 'personal';` before any older binary serves. (3) Optionally clean up the owned keys and their links. The columns may stay. Reverting S0 alone is a revert of P1's commit (b).

## QA mapping (proposal success criteria)

| Criterion | Tasks |
|-----------|-------|
| An expired application key → 401 on `/<slug>/v1`; other application keys unchanged | 1.6, 1.7, 1.10 |
| Worked example end to end on DB-less and full plane, including `/models` | 13.5, 14.6, 15a.2, 15b.1 |
| Attach, detach and priority change re-select with the same key; revoke → 401 | 5.9, 6.5, 15a.4, 15a.6, 15b.1, 15b.2 |
| Application key on store → 401; personal key on slug or MCP → 401; no personal consumer → 404 | 11.7, 12.6, 15a.5 |
| Second create → 409; rotate keeps id and links and kills the old secret on every replica | 2.11, 9.5, 10.7, 15a.7 |
| `partition: key`: 429, 503, 403 | 8.5, 15a.8 |
| Events carry `trustgate.auth.id`, `principal_subject = owner_id`, the selected `consumer.id`; snapshot metrics per publish | 1.9, 14.7, 16.3 |
| OSS: identical snapshot bytes; application `/auths`, `auth_ids` and body-less attach unchanged; `-race` and `go vet -tags functional` green | 2.9, 5.8, 6.4, 4.7, VG on every PR |

## Spec coverage

| Capability | Phases |
|------------|--------|
| proxy-api-key-expiry | 1 |
| usage-auth-id-telemetry | 1, 14 |
| token-budget-key-partition | 7, 8, 15a |
| personal-llm-consumers | 2, 3, 5, 6, 15a |
| owned-api-keys | 2, 4, 10, 15b |
| owned-key-attachment | 3, 5, 6, 15a, 15b |
| personal-key-endpoints | 2, 9, 10, 15a |
| personal-key-isolation | 11, 12, 15a |
| llm-store-gateway | 1, 11, 12, 14, 15a, 15b |
| store-consumer-selection | 13, 14, 15a, 15b |
| llm-store-oss-invariance | 2, 5, 7, 12, 15a, VG |
| config-snapshot-metrics | 16 |
