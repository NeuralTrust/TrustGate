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
| Estimated changed lines | Hand-written ≈4,970 (range 4,400–5,500): code ≈1,690, tests ≈3,140, docs ≈140. Generated ≈850, outside the budget: mocks ≈300 in P2, P5, P6, P9, P12, P13 and P14, and swagger/openapi ≈550 in P3, P4, P6 and P10. openspec ≈2,100, also outside. |
| Per-PR (hand-written) | P1 270 · P2 345 · P3 320 · P4 285 · P5 290 · P6 280 · P7 310 · P8 265 · P9 300 · P10 345 · P11 325 · P12 300 · P13 375 · P14 290 · P15a 350 · P15b 180 · P16 140 |
| 400-line budget risk | High: the total is ≈12× the budget. Every PR is ≤ 400 hand-written lines. P13 (375) is within 25 lines of the limit, and P10, P2 and P15a sit at ≈345–350. Measure before opening. If P13 goes over, move the benchmark and the 64-goroutine test into P14. |
| Chained PRs recommended | Yes |
| Chain strategy | Stacked PRs to `develop` in four lanes, no tracker branch. Every PR is behaviour-neutral or self-contained and inert until the app creates a personal consumer, so a Feature Branch Chain is not needed. |
| Parallelizable starts | t0, cut from `develop`: P1, P2, P7. After P2: P3, P4, P5. After P5: P11 and P16 (and P6 once P3 is in). After P4: P9. After P11: P12 and P13. |
| Critical path | P2 → P5 → P11 → P13 → P14 → P15a → P15b (7 PRs) |
| Merge order | P1, P2, P7 → P3, P4, P5 → P6, P8, P9, P11, P16 → P10, P12, P13 → P14 → P15a → P15b |
| Delivery strategy | chained-stacked |

Decision needed before apply: Yes. Confirm adjustments A1–A4 below. They resize and re-sequence PRs and reverse no binding decision.
Chained PRs recommended: Yes
Chain strategy: stacked (four lanes from `develop`, joins rebased on `develop`)
400-line budget risk: High

How to measure the budget (this excludes openspec/ and generated files, as ENG-1618 and RUN-1746 did):
- `git diff --shortstat <parent> -- pkg tests docs ':!docs/swagger.*' ':!docs/docs.go' ':!docs/openapi.json' ':!**/mocks/**'`

### Adjustments to the design's chain

| # | Change | Why | Effect |
|---|---|---|---|
| A1 | `auths.ListFilter.{ExcludeOwned, OwnerID}` (domain field, PG predicate, PG test) moves from P2 to P4 | P2 was at 390. The filter has exactly one consumer: the P4 list handler. | P2 390 → 345, P4 240 → 285 |
| A2 | `routingdomain.SourceFallback` and `Candidate.FallbackOnly()` move from P13 to P11 | P13 was over budget in this forecast (≈410). Both changes are pure domain code. | P13 → 375, P11 → 325 |
| A3 | P12 also depends on P7, which adds `AuthContext.OwnerID`. P11 and P14 rebase on P1. | P7 and P12 would otherwise both add `AuthContext.OwnerID`. P1, P11 and P14 all edit `auth.go:196` or `proxy_handler.go`. | No new PR. P7 merges long before P12 (the store lane is 4 PRs deep). |
| A4 | Design PR 15 becomes P15a (full-plane functional) and P15b (DB-less functional plus `docs/llm-store.md`). The P10 functional test takes the self-key and admin owned-key flows. | The listed functional scenarios came to ≈450 lines, over the budget. | 17 PRs instead of 16. P15a 350, P15b 180. |

### Chain topology

| Lane | PRs | Base while the parent is open | Base once the parent merged |
|------|-----|------|------|
| T (expiry, telemetry) | P1 | `develop` | — |
| A (data model, admin, self keys) | P2 → {P3, P4, P5}; {P3, P5} → P6; P4 → P9 → P10 | parent branch (for P6, the later of P3 and P5) | `develop` |
| B (budgets) | P7 → P8 | parent branch | `develop` |
| C (store data plane) | P5 → P11 → {P12 (+P7), P13} → P14 → P15a (+P6, P8, P10) → P15b; P5 → P16 | last open parent | `develop` |

Retargeting a base does not re-run CI, so close and reopen the PR after a retarget. "No checks reported" means the PR has a merge conflict: check `mergeable` before you re-push.

### Suggested Work Units

| Unit | Slice | Goal | Depends | Hand-written (code / test) | Generated |
|------|-------|------|---------|------|------|
| P1 | S0 + S1 | Expired keys rejected, `auth_key` cross-process eviction, `trustgate.auth.id` | — | 70 / 200 | — |
| P2 | S3a | `audience` and `owner_id` columns, domain, repos, `FindByOwner`, wire `omitempty`, golden bytes | — | 200 / 145 | mocks ≈40 |
| P3 | S3b | Consumer rules: personal ⇒ LLM, default model, immutability, bulk `auths` 422, hybrid 422, audience DTOs | P2 | 120 / 200 | swagger ≈60 |
| P4 | S3c | Admin auth rules: list filter and `?owner_id`, `owned_key` 422, rotator owner check, warnings | P2 | 120 / 165 | swagger ≈50 |
| P5 | S3d | `consumer_auth` link columns, `AuthLink`, `auth_links` read, upsert port | P2 | 120 / 170 | mocks ≈30 |
| P6 | S3e | Attach with link attributes (DD7), audience mismatch on attach | P3, P5 | 100 / 180 | mocks ≈30, swagger ≈60 |
| P7 | S2a | `partition: key`, `AuthID`/`OwnerID` plumbing, calendar windows | — | 120 / 190 | — |
| P8 | S2b | Hard limits (503, 403 `model_unpriced`, 429 scope), catalog and docs | P7 | 100 / 165 | — |
| P9 | S4a | Owned-key domain constructor and expiry cap, `PersonalKeys` use case | P2, P4 | 145 / 155 | mocks ≈50 |
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
- P2, P5: nullable or constant-default columns and `omitempty` wire fields. Golden bytes prove that existing snapshots do not change.
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
- **VR** (repository and migration tests; CI runs them with `PG_TEST_URL`). Locally, use a disposable container only:
  1. `docker run -d --rm --name run1763-pg -p 55447:5432 -e POSTGRES_PASSWORD=postgres postgres:16-alpine`
  2. `PG_TEST_URL='postgres://postgres:postgres@localhost:55447/postgres?sslmode=disable' make test-repositories`
  3. With the same URL: `go test ./pkg/infra/database/migrations/...`
- **VF** (functional, tag `functional`): `make test-functional` against local Postgres and Redis. Never copy the main checkout's `.env`, which points at Azure DB, and never point `E2E_*` at prod.

## Phase 1: S0 expiry + S1 telemetry (base `develop`)

Depends: —. Est.: ≈270 (code 70 / test 200). Commit boundary: (a) `docs(openspec)`: the change folder, outside the budget; (b) `fix`: expiry, S0; (c) `feat`: telemetry, S1. Release note in the PR body.

- [ ] 1.1 `pkg/api/resolver/api_key_resolver.go`: inject `now func() time.Time`. `Resolve` skips `Auth.IsExpired(now())` auths the way it skips disabled ones. Wire `time.Now().UTC()` at `pkg/container/modules/api.go:196`.
- [ ] 1.2 `pkg/api/middleware/auth.go`: `NewAuthMiddleware` takes the clock. `apiKeyAttachedElsewhere(…, now)` (`:196`) ignores expired auths. Wire at `pkg/container/modules/api.go:250`.
- [ ] 1.3 `pkg/infra/cache/subscriber/invalidate_gateway_data_event_subscriber.go` (DD15): take `AuthKeyTTLName` and clear it next to `authCache`. Wire at `pkg/container/modules/cache_events.go:44`.
- [ ] 1.4 Telemetry: `pkg/infra/trace/trace.go` (`Metadata.AuthID`, `SetAuthID`, no-op on empty), `pkg/infra/metrics/events/event.go` (`AuthID json:"auth_id,omitempty"`), `pkg/app/metrics/builder.go:68-84`, `pkg/infra/telemetry/otlp/mapping.go:70-74,202-206` (`trustgate.auth.id`, not emitted when empty), `pkg/api/handler/http/proxy/proxy_handler.go:154,419` (`stampConsumerTrace(c, rc, authCtx)`).
- [ ] 1.5 `docs/telemetry/otlp-metadata-contract.md:52-56`: add the `trustgate.auth.id` row. The `trustgate.principal.subject` row says it holds the key owner for a personal key. Accept: `usage-auth-id-telemetry › Contract row present`.
- [ ] 1.6 Test `pkg/api/resolver/api_key_resolver_test.go` (fixed clock): an expired key on its own consumer gets the unknown-key status, `expires_at == now` is expired, and a future or absent expiry is accepted. Accept: `proxy-api-key-expiry › Expired key on its own consumer`, `› Expiry boundary`, `› Future or absent expiry`, `› Fixed clock in a unit test`.
- [ ] 1.7 Test `pkg/api/middleware/auth_test.go`: an expired key attached to another consumer → 401. A valid key attached to another consumer → 403. Accept: `proxy-api-key-expiry › Expired key of another consumer`, `› Valid key of another consumer`.
- [ ] 1.8 Test `invalidate_gateway_data_event_subscriber_test.go`: the event clears both `auth` and `auth_key`. Accept: the unit half of `llm-store-gateway › Rotation seen by another replica` and `› Stale key cache after a detach` (both end to end in 15a.7).
- [ ] 1.9 Test `pkg/app/metrics/builder_test.go` and `pkg/infra/telemetry/otlp/mapping_test.go`: the auth id is present when set and absent when empty. `principal_subject` is the key name for an application key. Accept: `usage-auth-id-telemetry › Application key on a consumer`, `› No auth id`, `› Application key subject`.
- [ ] 1.10 Test `tests/functional/proxy_api_key_expiry_test.go` (C, `functional`): an application key with a past `expires_at` → 401 on `/<slug>/v1/chat/completions`. A future one → 200.
- [ ] 1.11 PR body `## Release note`: application keys with a past `expires_at` stop working on `/<slug>/v1/*`, and rollback is a revert. Accept: `proxy-api-key-expiry › Release note present`.
- [ ] 1.12 Run VG and VF.

## Phase 2: S3a data model — `audience`, `owner_id` (base `develop`)

Depends: —. Est.: ≈345 (code 200 / test 145). Commit boundary: (a) `test`: capture the golden codec bytes for an application consumer and an application key on the base, before any struct change; (b) `feat`: migrations, domain, repos, adapters; (c) `chore`: mocks.

- [ ] 2.1 Create `pkg/infra/database/migrations/20261002120000_add_consumer_audience.go` and `20261002120100_add_auth_owner.go`. Use the SQL from the design and the template `20260922120000_add_auth_expires_at.go`: idempotent, one transaction per direction, no table.
- [ ] 2.2 Create `pkg/domain/consumer/audience.go`: `Audience`, `AudienceApplication`, `AudiencePersonal`, `ParseAudience` (`"application"` → `""`), `IsPersonal()`, `AudienceName()`. `consumer.go`: `Audience json:"audience,omitempty"`, `CreateParams.Audience`, `RehydrateParams.Audience`. `errors.go`: `ErrInvalidAudience`.
- [ ] 2.3 `pkg/domain/auth/auth.go`: `OwnerID json:"owner_id,omitempty"`, `IsOwned()`. `errors.go`: `ErrOwnedKeyExists` (wraps `ErrAlreadyExists`). `repository.go`: `FindByOwner(ctx, gatewayID, ownerID)`. Run `go generate ./pkg/domain/auth/...`.
- [ ] 2.4 `pkg/infra/repository/consumer/repository.go`: `c.audience` in `consumerSelectColumns` (`:50-58`), `INSERT` (`:118`) and `scanConsumer` (`:732`, `ParseAudience`). `Update` never writes `audience`.
- [ ] 2.5 `pkg/infra/repository/auth/repository.go`: one `authColumns` const replaces the six SELECT copies (`:140-288`) and adds `owner_id`. `INSERT` writes `NULLIF($n,'')`. A 23505 on `auths_gateway_owner_uniq` → `ErrOwnedKeyExists`. `UPDATE` stays unchanged, so it never writes `owner_id`. `scanAuth`. `FindByOwner`.
- [ ] 2.6 `pkg/runtimeconfig/snapshot/adapters/auth_repository.go`: `FindByOwner` scans the gateway's auths in the snapshot.
- [ ] 2.7 Test `pkg/infra/database/migrations/20261002120000_add_consumer_audience_test.go` and `…120100_add_auth_owner_test.go` (`PG_TEST_URL`): up twice, down twice. Existing rows get `application` and `NULL`. `audience='team'` hits 23514. A second owned key on G hits 23505, while the same owner on H succeeds. Accept: `personal-llm-consumers › Existing rows`, `› Invalid value refused by the database`; `owned-api-keys › Existing rows untouched`, `› Second owned key for the same user`; `llm-store-oss-invariance › Migrations create nothing personal`.
- [ ] 2.8 Test `pkg/domain/consumer/audience_test.go` and `pkg/domain/auth/auth_test.go`: `ParseAudience` table, `IsOwned`.
- [ ] 2.9 Test `pkg/infra/configsnapshot/codec_test.go`: golden bytes from 2(a) for the application consumer and the application key, with no `audience` and no `owner_id`. Round trips for a personal consumer and an owned auth. Accept: `personal-llm-consumers › Codec round trip`, `› Application consumer bytes`; `owned-api-keys › Codec round trip`, `› Application key bytes`; `llm-store-oss-invariance › Golden snapshot` (the version hash is unchanged).
- [ ] 2.10 Test `pkg/app/configsnapshot/compiler_test.go`: a gateway with one application key and one owned key compiles both, on the bulk and the per-gateway paths, and `AuthByAPIKeyHash` finds the owned key. Accept: `owned-api-keys › Compiler includes owned keys`.
- [ ] 2.11 Test `tests/functional/repositories/auth/repository_test.go`: `FindByOwner(G)` hits and `FindByOwner(H)` is not found. Two concurrent `Save`s for one owner → one row and one `ErrOwnedKeyExists`. `Update` leaves `owner_id` alone. `tests/functional/repositories/consumer/repository_test.go`: `audience` round trip; `Update` leaves `audience` alone. Accept: `owned-api-keys › Find by owner`; `personal-key-endpoints › Concurrent creates`, `› Another gateway` (repository half).
- [ ] 2.12 Run VG and VR.

## Phase 3: S3b consumer rules (base P2)

Depends: P2. Est.: ≈320 (code 120 / test 200). Commit boundary: (a) `feat`: domain and use-case rules, DTOs, wiring; (b) `chore(docs)`: `make docs`.

- [ ] 3.1 `pkg/domain/consumer/consumer.go` `Validate` (`:212`): `personal` ⇒ `TypeLLM`, and personal needs a concrete (non-glob) `ModelPolicies[r].Default` for some `r` in `RegistryIDs`; fallback backends do not count. `errors.go`: `ErrAudienceImmutable`, `ErrPersonalAuthsBulk`, `ErrHybridPersonal`, `ErrPersonalNoDefault`, `ErrAudienceMismatch`.
- [ ] 3.2 `pkg/domain/consumer/auth_rules.go` `ValidateAuthConfig` (`:37`): a personal consumer takes only owned auths, and an application consumer takes only unowned ones → `ErrAudienceMismatch`.
- [ ] 3.3 `pkg/app/consumer/creator.go`: carry `audience`. Personal plus non-empty `auths` → `ErrPersonalAuthsBulk`. Personal on a `ServedByHybridDataPlane()` gateway → `ErrHybridPersonal` (new gateway reader dependency). Run `ValidateAuthConfig` over the create `auths`.
- [ ] 3.4 `pkg/app/consumer/updater.go`: an `audience` different from the stored one → `ErrAudienceImmutable`. The `auths` field present on a personal consumer (`[]` included) → `ErrPersonalAuthsBulk`, before `replaceAuthLinks`. An owned auth in an application consumer's `auths` → `ErrAudienceMismatch`.
- [ ] 3.5 `pkg/app/consumer/associator.go`: detaching from a personal consumer the last registry with a concrete default → `ErrPersonalNoDefault`, and nothing is detached.
- [ ] 3.6 DTOs: `pkg/api/handler/http/consumer/request/create_consumer_request.go` (`Audience string json:"audience,omitempty"`), `update_consumer_request.go` (`Audience *string`), `response/consumer_response.go` (`Audience string json:"audience"`, always present). Swag `@Failure 422` on the create and update handlers. `auth_ids` is unchanged and `auth_links` is not exposed.
- [ ] 3.7 `pkg/container/modules/consumer.go`: wire the creator's gateway dependency.
- [ ] 3.8 Test `pkg/domain/consumer/consumer_test.go` and `auth_rules_test.go`: personal MCP 422, personal LLM ok, no default 422, glob default 422, a default only on a fallback 422, the audience × owned matrix.
- [ ] 3.9 Test `pkg/app/consumer/{creator,updater,associator}_test.go`: hybrid 422 with nothing saved; an application consumer on hybrid is created; create with keys 422; switch refused; same value accepted; `auths: []` on personal 422 with no repo write; detaching R1 (the only default) 422 while R2 detaches.
- [ ] 3.10 Test the handlers: the default `audience` is `application`; an invalid value → 422.
- Accept (3.1–3.10): `personal-llm-consumers › Default audience`, `› Personal MCP consumer`, `› Personal LLM consumer`, `› Personal consumer without a default`, `› Glob default does not count`, `› Detaching the only registry with a default`, `› Switch refused`, `› Same value accepted`, `› Create with keys`, `› Update with an empty list`, `› Hybrid gateway`, `› Application consumer on a hybrid gateway`; `owned-key-attachment › Owned key onto an application consumer` (create and PUT half).
- [ ] 3.11 Run VG and VR.

## Phase 4: S3c admin auth rules (base P2)

Depends: P2. Est.: ≈285 (code 120 / test 165). Commit boundary: (a) `feat`; (b) `chore(docs)`: `make docs`.

- [ ] 4.1 `pkg/domain/auth/repository.go`: `ListFilter.ExcludeOwned bool`, `ListFilter.OwnerID string` (A1). `pkg/infra/repository/auth/repository.go`: list and count add `AND ($k::boolean IS NOT TRUE OR owner_id IS NULL) AND ($m = '' OR owner_id = $m)`. The compiler keeps the unfiltered `List` (`compiler.go:462,725`).
- [ ] 4.2 `pkg/common/errors/errors.go`: `ErrManagedByOwner`. `pkg/domain/auth/errors.go`: `ErrOwnedKey`. `httpio/errors.go` `MapDomainError`: → 422 `owned_key` (DD10).
- [ ] 4.3 `pkg/api/handler/http/auth/list_auth_handler.go` (`:61-93`): always sets `ExcludeOwned`; `?owner_id=<sub>` sets `OwnerID` and clears `ExcludeOwned`. Swag `@Param owner_id`. `response/auth_response.go`: `OwnerID json:"owner_id,omitempty"`. The secret and hash are never present.
- [ ] 4.4 `pkg/app/auth/updater.go`: an owned key → `ErrOwnedKey`. `pkg/app/auth/rotator.go`: `RotateInput.OwnerID`; an owned key needs `OwnerID == existing.OwnerID`, else `ErrOwnedKey` (DD14). The admin rotate handler passes `""`. Swag `@Failure 422` on PUT and rotate.
- [ ] 4.5 The admin auth create DTO has no `owner_id`. Assert that the decoder drops it and that the creator never sets it.
- [ ] 4.6 `pkg/app/policy/warnings.go:285` `apiKeyAuths`: skip `IsOwned()`.
- [ ] 4.7 Test `tests/functional/repositories/auth/repository_test.go`: with 3 application keys and 2 owned keys, `ExcludeOwned` → 3 items and total 3. `OwnerID=alice` → 1 item. The default filter → 5.
- [ ] 4.8 Test `list_auth_handler_test.go`, `get_auth_handler_test.go` and the update/rotate handler tests: list hides owned keys, `?owner_id` lists the owner's key, get shows `owner_id` without the hash, and PUT and rotate → 422 `owned_key` with no repo write.
- [ ] 4.9 Test `pkg/app/auth/{updater,rotator}_test.go`: owner match and mismatch. Admin `DELETE` on an owned key goes through the deleter unchanged (detach, TTL eviction, invalidation, `Signal`). Test `pkg/app/policy/warnings_test.go`: owned keys only → no api-key warning.
- Accept (4.1–4.9): `owned-api-keys › List hides owned keys`, `› List by owner`, `› Get shows the owner`, `› Update and rotate refused`, `› Admin revocation` (unit half; the end-to-end check is in 10.8 and 15b.2), `› Owner in an admin create body`, `› Owned keys only`.
- [ ] 4.10 Run VG and VR.

## Phase 5: S3d `consumer_auth` link columns (base P2)

Depends: P2. Est.: ≈290 (code 120 / test 170). Commit boundary: (a) `test`: golden bytes for an application consumer with application links, captured on P2; (b) `feat`; (c) `chore`: mocks.

- [ ] 5.1 Create `pkg/infra/database/migrations/20261002120200_add_consumer_auth_grant.go`: three nullable columns and `consumer_auth_grant_check`, following the design.
- [ ] 5.2 Create `pkg/domain/consumer/auth_link.go`: `GrantLevel` (`user`/`group`/`all`), `ParseGrantLevel`, `Rank()`, `DefaultGrantPriority = 1`, `AuthLink{Level, Priority, GrantedAt}`, `Validate()`, and `ErrInvalidAuthLink` in `errors.go`.
- [ ] 5.3 `pkg/domain/consumer/consumer.go`: `AuthLinks map[ids.AuthID]AuthLink json:"auth_links,omitempty"`, `RehydrateParams.AuthLinks`. `repository.go`: `AttachAuth(ctx, consumerID, authID, link *AuthLink)`. Callers pass `nil` for now (behaviour-neutral). Run `go generate ./pkg/domain/consumer/...`.
- [ ] 5.4 `pkg/infra/repository/consumer/repository.go`: the `auth_links` `json_object_agg` subselect, filtered on `level IS NOT NULL`. `AttachAuth` (`:413-431`): `nil` keeps `ON CONFLICT DO NOTHING`; non-nil upserts the three columns. `replaceAuthLinks` is unchanged.
- [ ] 5.5 `pkg/runtimeconfig/snapshot/adapters/consumer_repository.go`: the new `AttachAuth` signature keeps the read-only error.
- [ ] 5.6 Test the migration (`PG_TEST_URL`): up and down twice; existing links stay `NULL`; a half-filled row → 23514. Accept: `owned-key-attachment › Existing links untouched`, `› Half-filled link refused`.
- [ ] 5.7 Test `auth_link_test.go`: level table, `Rank`, priority below 0, zero `granted_at`.
- [ ] 5.8 Test `codec_test.go`: golden bytes from 5(a) with no `auth_links`; a personal consumer round trips `{group, 2, 2026-10-01T09:00:00Z}` with the key in `auth_ids`. Accept: `owned-key-attachment › Codec round trip`, `› Application consumer bytes`.
- [ ] 5.9 Test `tests/functional/repositories/consumer/repository_test.go`: the upsert changes P1's priority and leaves P2's link alone; re-sending the same values is a no-op; `auth_links` holds personal rows only; deleting personal P1 cascades its links while the owned auth survives with its P2 link. Accept: `owned-key-attachment › Priority change` (repository half); `personal-llm-consumers › Delete` (repository half).
- [ ] 5.10 Run VG and VR.

## Phase 6: S3e attach with link attributes (base: the later of P3 and P5)

Depends: P3, P5. Est.: ≈280 (code 100 / test 180). Commit boundary: (a) `feat`; (b) `chore`: mocks; (c) `chore(docs)`: `make docs`.

- [ ] 6.1 Create `pkg/api/handler/http/consumer/request/attach_auth_request.go`: `{level?, priority?, granted_at? (RFC 3339)}` with `priority` defaulting to 1, and a `ToLink() (*AuthLink, error)` that returns nil for an empty body.
- [ ] 6.2 `pkg/api/handler/http/consumer/association_handler.go`: `AttachAuth` accepts an optional body. An empty body behaves as today. Swag `@Param body`, `@Failure 422`.
- [ ] 6.3 `pkg/app/consumer/associator.go` `AttachAuth(ctx, gatewayID, consumerID, authID, link)` (DD7): personal consumer plus owned key needs a non-nil link that passes `Validate`; an application consumer needs `link == nil`; `ValidateAuthConfig` catches the audience mismatch; the cross-gateway check stays as today. Run `go generate ./pkg/app/consumer/...`.
- [ ] 6.4 Test `association_handler_test.go`: empty body = today's status and body; `level` on an application consumer → 422; a missing `level` or `granted_at` → 422; `priority` defaults to 1.
- [ ] 6.5 Test `associator_test.go`: first attach; a second consumer leaves the first link alone; owned key onto an application consumer → 422; application key onto a personal consumer → 422; cross-gateway gets today's status; no repo write on any refusal.
- [ ] 6.6 Test `tests/functional/repositories/consumer/repository_test.go`: a personal consumer with 500 owned links reads 500 `AuthIDs` and 500 `AuthLinks`. Test `consumer_response_test.go`: the body has `auth_ids` and no `auth_links`.
- Accept (6.1–6.6): `owned-key-attachment › Owned key onto an application consumer` (attach half), `› Application key onto a personal consumer`, `› Application attach unchanged`, `› First attach`, `› Links are complementary`, `› Missing level`, `› Link fields on an application consumer`, `› Priority change`, `› Other gateway`; `personal-llm-consumers › Large personal consumer`.
- [ ] 6.7 Run VG and VR.

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

## Phase 9: S4a `PersonalKeys` use case (base P4, after P2)

Depends: P2, P4. Est.: ≈300 (code 145 / test 155). Commit boundary: (a) `feat`; (b) `chore`: mocks.

- [ ] 9.1 `pkg/domain/auth/auth.go`: `MaxOwnedKeyLifetime = 90 * 24 * time.Hour`, `NewOwnedAPIKeyAuth(gatewayID, ownerID, expiresAt, now)`, `ValidateOwnedExpiry(at, now)` (`now < at ≤ now + 90 d`). `errors.go`: `ErrOwnedExpiry`.
- [ ] 9.2 Create `pkg/app/auth/personal_keys.go`: the `PersonalKeys` interface plus implementation, with `//go:generate mockery`. The behaviour:
  - `Create`: run `ValidateOwnedExpiry`, refuse a hybrid gateway, pre-check with `FindByOwner` (409), build with `NewOwnedAPIKeyAuth`, then `Save`, where a race hits the unique index and gives `ErrOwnedKeyExists`. Then run the creator's side effects: `AuthTTLName` and `AuthKeyTTLName`, `invalidation.GatewayData`, `Signal`.
  - `Rotate`: `FindByOwner`, then `Rotator.Rotate{Expiry, OwnerID}`. An absent expiry keeps the current one; a present one must pass the cap. The links are untouched.
  - `Revoke`: `FindByOwner`, then `Deleter.Delete`, which detaches every link.
  - `Get`: `FindByOwner` plus the `consumers.ListByAuthID` ids, with `[]` when there are none.
- [ ] 9.3 `pkg/container/modules/auth.go`: provide `NewPersonalKeys` with `now = time.Now().UTC`. Register a view provider for `consumerdomain.Reader` if dig does not resolve it.
- [ ] 9.4 Test `pkg/domain/auth/auth_test.go`: `ValidateOwnedExpiry` edges (now, +90 d, +90 d +1 s, the past).
- [ ] 9.5 Test `personal_keys_test.go` (mocks, fixed clock, `cache.NewTTLMapManager`): the first key comes back with no links and the raw key; the 409 pre-check; the race 409 from the repository; hybrid 422; expiry bounds; rotate keeps the id and links and evicts the old hash; rotating an expired key works; rotate, revoke and get each → `ErrNotFound` without a key; revoke then re-create works.
- Accept (9.1–9.5): `personal-key-endpoints › First key`, `› Hybrid gateway`, `› Second key`, `› Concurrent creates` (use-case half), `› Bounds on create`, `› Rotate`, `› Rotate an expired key`, `› Nothing to rotate`, `› Revoke and re-create`, `› Nothing to revoke`.
- [ ] 9.6 Run VG.

## Phase 10: S4b self-only HTTP (base P9)

Depends: P9. Est.: ≈345 (code 130 / test 215). Commit boundary: (a) `feat`: handler, DTOs, routes, wiring; (b) `test`: functional; (c) `chore(docs)`: `make docs` (≈380 generated lines).

- [ ] 10.1 Create `pkg/api/handler/http/store/llm_key_handler.go`: GET, POST, POST rotate and DELETE on `callerSubject(c)` (`requests_handler.go:212`) only. An empty subject → 403. Full swag annotations (`@Success 200/201/204`, `@Failure 403/404/409/422`).
- [ ] 10.2 Create `store/request/create_llm_key_request.go` (`expires_at`, required) and `store/request/rotate_llm_key_request.go` (`expires_at?`). Body `owner_id`, `principal_sub` and `consumer_id` are not decoded. Create `store/response/personal_key_response.go`: `{id, consumer_ids, key (create and rotate only), key_prefix, key_suffix, expires_at, enabled, created_at, updated_at}`, with no hash and no link attributes.
- [ ] 10.3 `pkg/server/router/admin_router.go:225-247`: routes under `/:gateway_id/store` with `RequireInteractiveIdentity()` (`admin_authz.go:108`). Wire in `pkg/container/modules/{store,server_admin}.go`; `admin_router_wiring_test.go` must pass.
- [ ] 10.4 Test `llm_key_handler_test.go`: a service credential → 403; a body owner is ignored; the status codes; GET never returns `key`.
- [ ] 10.5 Run `make docs`. Test `docs/openapi_test.go`: the four paths, their DTOs and their status codes. Accept: `personal-key-endpoints › Paths in the document`.
- [ ] 10.6 `tests/functional/common_test.go`: add the `CreateLLMKey`, `RotateLLMKey` and `RevokeLLMKey` helpers (admin JWT with a `user_id`, `setup_test.go:128`).
- [ ] 10.7 Test `tests/functional/llm_key_test.go` (C), self flows: create → 201 with `consumer_ids: []`; GET → 200 without a secret; second create → 409; rotate → same id, new secret; DELETE → 204; re-create → 201; no key → 404 on GET, rotate and DELETE; a caller without registries access → 403; the same user on two gateways → two keys.
- [ ] 10.8 Same file, admin plane on an owned key: `GET /auths` hides it, `?owner_id` lists it, `GET /auths/:id` shows `owner_id`, PUT and rotate → 422 `owned_key`, and admin `DELETE` → 204.
- Accept (10.1–10.8): `personal-key-endpoints › Service credential`, `› Body owner ignored`, `› No registries access`, `› First key`, `› Second key`, `› Another gateway`, `› Metadata without the secret`, `› No key`, `› Rotate`, `› Nothing to rotate`, `› Revoke and re-create`, `› Nothing to revoke`; `owned-api-keys › List hides owned keys`, `› List by owner`, `› Get shows the owner`, `› Update and rotate refused`, `› Admin revocation` (admin-plane half).
- [ ] 10.9 Run VG and VF.

## Phase 11: S5a `Data` index + D11 rejections (base P5, rebased on P1)

Depends: P5 (rebase on P1, A3). Est.: ≈325 (code 110 / test 215). Commit boundary: (a) `feat(routing)`: `SourceFallback` and `FallbackOnly` (A2); (b) `feat`: `Data` index and D11.

- [ ] 11.1 `pkg/domain/routing/candidate.go`: `SourceFallback`, `Candidate.FallbackOnly()` (true when every source is `fallback`). `pkg/app/routing/resolver.go` uses the domain const instead of `sourceFallback`.
- [ ] 11.2 `pkg/app/consumer/consumer_data.go`: the `StoreLink` type; `storeLinks map[ids.AuthID][]StoreLink` and `personal int`, built in `NewData` over **active** personal consumers, each slice sorted once by `(Rank, Priority, GrantedAt, consumer id)`; an auth id with no `AuthLinks` entry is skipped; `HasPersonalConsumers()`, `StoreLinks(id)` (shared, never mutated). `indexBySlug` (`:124`) skips personal consumers.
- [ ] 11.3 `pkg/app/consumer/data_finder.go:349` `loadAuths`: skip the auth ids of personal consumers (DD12).
- [ ] 11.4 D11 rejections:
  - `pkg/api/middleware/auth.go:196` `apiKeyAttachedElsewhere` skips personal consumers.
  - `pkg/api/middleware/auth_chain.go:370` `resolveAPIKey` and `pkg/app/consumer/api_key_consumers.go:148-164` `ForAPIKey` treat `IsOwned()` as an unknown key.
  - `pkg/app/consumer/path_resolver.go:145`: a personal consumer is no match (DD13).
- [ ] 11.5 Test `pkg/domain/routing/candidate_test.go`: the `FallbackOnly` table.
- [ ] 11.6 Test `consumer_data_test.go`:
  - The order P4, P2, P1, P3.
  - An inactive consumer is left out, and a gateway with only inactive personal consumers gives `HasPersonalConsumers() == false`.
  - N = 0 gives an empty slice.
  - A personal slug is not in `bySlug`.
  - 64 concurrent readers under `-race`.
  - Accept: `llm-store-gateway › Index order`, `› No links` (index half), `› Inactive consumer is not a link` (index half); `personal-key-isolation › Personal consumer by slug` (unit).
- [ ] 11.7 Test `pkg/api/middleware/auth_test.go`: a personal key on an application slug → 401; an application key of another application consumer → 403. Test `auth_chain_test.go` and `api_key_consumers_test.go`: an owned key → 401 even without a path scope; an application key is unchanged. Test `path_resolver_test.go`. Accept: `personal-key-isolation › Personal key on an application consumer`, `› Application key of another consumer`, `› Personal key on MCP`, `› Application key on MCP`.
- [ ] 11.8 Run VG.

## Phase 12: S5b middleware store branch (base P11, after P7)

Depends: P11, P7. Est.: ≈300 (code 110 / test 190). Commit boundary: (a) `feat`; (b) `chore`: mocks.

- [ ] 12.1 `pkg/domain/consumer`: `StoreSlug = "store"`. Create `pkg/app/consumer/store_key_resolver.go`: `StoreKeyResolver` and `ErrStoreKeyRejected` with mockery. `FindByAPIKey`, then `Enabled ∧ api_key ∧ IsOwned() ∧ GatewayID == gw`. `ErrNotFound` (which includes `ErrExpired`) and every failed check → `ErrStoreKeyRejected`. Infra errors are wrapped with `%w`.
- [ ] 12.2 `pkg/api/middleware/auth.go:56-101,161-182`: `serveStore` runs hybrid → 404, then `Data` error → 500, then `!HasPersonalConsumers()` → 404 (byte-identical to the `MatchSlug` miss), then no key → 401, then resolve → 401 or 500. `attach` takes `Principal{Subject: owner_id, Method: api_key}` and `AuthContext{AuthID, OwnerID}`, and `rc == nil` skips the consumer locals. `NewAuthMiddleware` takes `storeKeys`.
- [ ] 12.3 `pkg/container/modules/consumer.go` `provideConsumerServices` (both planes, `core_data.go:106`): provide `NewStoreKeyResolver`.
- [ ] 12.4 `proxy_handler.go`: a guard (interim) makes the store slug with no store wiring answer 404 `not_found`. P14 replaces it.
- [ ] 12.5 Test `store_key_resolver_test.go`: the 401 matrix (unknown, disabled, expired, unowned, another gateway, non-`api_key`) and the 500 wrap.
- [ ] 12.6 Test `auth_test.go`:
  - The 404 cases (no personal consumers, only inactive ones, hybrid) with a counting `APIKeyFinder` fake that records zero calls, and a body equal to today's unknown-slug body.
  - Rejected keys → 401, including an application key.
  - The key in `X-AG-API-Key` and in `Authorization: Bearer`.
  - Principal and `AuthContext.OwnerID` in ctx.
  - Other slugs unchanged.
- Accept (12.1–12.6): `llm-store-gateway › Other slugs unchanged`, `› Gateway without personal consumers`, `› Only inactive personal consumers`, `› Hybrid gateway`, `› Valid personal key` (unit), `› Rejected keys`, `› Context of a personal request` (middleware half); `personal-key-isolation › Application key on the store`; `llm-store-oss-invariance › Fresh OSS gateway` (unit).
- [ ] 12.7 Run VG.

## Phase 13: S5c `StoreSelector` (base P11)

Depends: P11. Est.: ≈375 (code 130 / test 245). Commit boundary: (a) `refactor`: extract `candidatePipeline` from `forwarder.resolveRouting` (`routing.go:47-91`), behaviour-neutral, with the existing forwarder tests green; (b) `feat`: selector and scope; (c) `chore`: mocks.

- [ ] 13.1 Create `pkg/app/proxy/store_scope.go`: `storeScope(links) []scopedLink`. `S` = the lower-cased `Registry.Provider()` of the **primary** registries of `user` links only (OQ2). A `group`/`all` link gets `Keep(c) = provider(c) ∉ S` when `S ≠ ∅`. A link left with no primary registry is dropped. The helper is shared with `StoreModels`.
- [ ] 13.2 `pkg/app/proxy/routing.go`: `candidatePipeline(ctx, intent, needed, rc, data, keep, listingMode)` runs Resolve → Keep → capability → files → listing. The store mode drops a deferring candidate on `VerdictAbsent` with no keep-all fallback (DD17); `VerdictListed` and `VerdictUnknown` keep it (OQ3). The slug mode keeps `routing.go:115-117`.
- [ ] 13.3 Create `pkg/app/proxy/store_selector.go`: `StoreSelector`, `StoreSelectInput`, `StoreSelection`, `ErrNoStoreConsumer` (wraps `ErrModelDenied`), with mockery.
  - A link admits when a `!FallbackOnly()` candidate remains, and for a zero intent that candidate also has a `Default`.
  - Specificity: 0 for a literal allow entry, 1 for a glob, 2 with no allow-list, 0 for the other intent kinds.
  - The winner is the minimum of `(Rank, Priority, specificity, GrantedAt, id)`.
  - Pool alias: when every link refuses, the first resolver error decides, so an unknown alias → 400 and a known alias with no member left → 403.
  - The selector holds no state and never calls a repository, gRPC or Redis.
- [ ] 13.4 `pkg/container/modules/proxy.go`: provide `NewStoreSelector`.
- [ ] 13.5 Test `store_selector_test.go`, worked example table (mock `ModelListing`): `gpt-4.1` → denied, `gpt6` → D, `opus-5.5` → C, `opus-4.8` → B, empty → D, `@openai/gpt-4.1` → denied, `auto` → D, without D `gpt-4.1` → A with `Keep == nil`, without D `deepseek-chat` → denied, B at p0 → B. Accept: `store-consumer-selection › gpt-4.1 is denied`, `› gpt6 goes to D`, `› opus-5.5 goes to C`, `› opus-4.8 goes to B`, `› No model goes to D`.
- [ ] 13.6 Test substitution and admission: A's OpenAI is substituted while A's Mistral survives; a `user` consumer's fallback provider does not enter `S` (OQ2); fallback never admits. Accept: `› User link narrows a provider`, `› Other providers of a group consumer survive`, `› Fallback does not admit`.
- [ ] 13.7 Test listing and ordering: Anthropic with no allow-list does not capture `gpt-4.1` when the verdict is Absent; it is selected when the verdict is Unknown (OQ3); specificity applies at equal level; priority beats specificity; a glob beats no allow-list; the oldest grant wins. Accept: `› Anthropic without allow-list does not capture gpt models`, `› Unknown listing keeps the candidate`, `› Specificity at equal level and priority`, `› Priority before specificity`, `› Glob before no allow-list`, `› Oldest grant breaks a tie`.
- [ ] 13.8 Test intents: `pool:fast` → P1 and `pool:slow` → 400; `auto` → P2; `@anthropic/opus-5.5` → C and `@openai/gpt-4o` → 403; empty → D with `gpt6`; N = 0 → `ErrNoStoreConsumer`, which `errors.Is` matches against `ErrModelDenied` (OQ1). Accept: `› Pool alias`, `› Auto`, `› Qualified reference`, `› Empty model`; `llm-store-gateway › No links` (selector half).
- [ ] 13.9 Test 64 goroutines × different intents under `-race`, each equal to the sequential result, plus `BenchmarkStoreSelector_N10`. Accept: `› Concurrent selection`.
- [ ] 13.10 Run VG and measure the diff. If it is over 400, move 13.9 to P14.

## Phase 14: S5d handler store path + `StoreModels` (base P13, after P12, rebased on P1)

Depends: P12, P13 (rebase on P1). Est.: ≈290 (code 110 / test 180). Commit boundary: (a) `feat(proxy)`: `ForwardInput.Keep` and `ListModelsInput.Keep`, slug path byte-identical; (b) `feat`: `StoreModels` and handler store path; (c) `chore`: mocks.

- [ ] 14.1 `pkg/app/proxy/forwarder.go` and `routing.go`: `ForwardInput.Keep`. When it is set, resolve even for a zero intent, and make `nonCandidateRoutes` (`:455-475`) exclude the substituted LB routes and fallback backends. Empty after `Keep` → `ErrModelDenied`.
- [ ] 14.2 `pkg/app/proxy/list_models.go`: `ListModelsInput.Keep`. Create `store_models.go`: `StoreModels.List/Get`, the union of `ModelsLister.List` per effective link with `Keep` combined with `!FallbackOnly()`, deduplicated and sorted, with `[]` when there is nothing (OQ1).
- [ ] 14.3 `pkg/api/handler/http/proxy/proxy_handler.go:139-195`:
  - `WithStore(selector, models)` and `handleStore`, which replaces the 12.4 guard.
  - `/models` and `/models/{id}` go to `StoreModels` and stamp no consumer.
  - Otherwise `StoreSelector`; then set `authCtx.ConsumerID`, call `stampConsumerTrace(c, rc, authCtx)`, and run the shared forward tail with `Keep`.
- [ ] 14.4 `pkg/container/modules/proxy.go`: provide `NewStoreModels` and call `WithStore` on both planes.
- [ ] 14.5 Test `forwarder_test.go`: `Keep` excludes a substituted LB route and a substituted fallback; `Keep == nil` leaves the slug path unchanged (existing suite). Accept: `store-consumer-selection › Substituted fallback is not used`, `› Fallback serves the selected consumer` (unit).
- [ ] 14.6 Test `store_models_test.go`: the union with substitution is `gpt6`, `opus-4.8`, `opus-5.5`; without D it is `gpt-4.1`, `gpt6`, `opus-4.8`, `opus-5.5`; `deepseek-chat` never appears; N = 0 → `[]`; `Get` returns 200 for a listed id and 404 otherwise. Accept: `llm-store-gateway › Union with substitution (worked example)`, `› Union without a user link`, `› No links` (listing half).
- [ ] 14.7 Test `proxy_handler_test.go` (store path):
  - 403 with no upstream call.
  - `ConsumerID`, `consumer.id`, `auth_id` and `principal_subject = owner_id` stamped after selection.
  - The request ctx carries `AuthID` and `OwnerID`.
  - `/models` stamps no consumer.
  - The plan is the selected consumer's policies plus the globals, with no MCP-wide policies.
  - One balancer keyed `G:P` serves two users.
  - Accept: `llm-store-gateway › Allowed and denied models`, `› Context of a personal request`, `› Event fields`, `› Shared balancer`, `› Policies of the selected consumer`; `usage-auth-id-telemetry › Personal key subject`.
- [ ] 14.8 Run VG.

## Phase 15a: S5e full-plane end to end (base P14, after P6, P8 and P10)

Depends: P6, P8, P10, P14. Est.: ≈350 (test only). Commit boundary: one `test` commit.

- [ ] 15a.1 Create `tests/functional/llm_store_test.go`, setup helpers:
  - OpenAI, Anthropic and DeepSeek provider stubs (from `proxy_e2e_test.go`), with switchable failure.
  - A seeded catalog listing.
  - Personal consumers A–D created through the admin API (201 with `audience=personal`).
  - Ana's key through `POST /principal/llm-key`.
  - Links through `POST /consumers/:id/auths/:auth_id` with `{level, priority, granted_at}`.
- [ ] 15a.2 Worked example on chat: `gpt-4.1` → 403, `gpt6` → D, `opus-5.5` → C, `opus-4.8` → B, no model → D. `/store/v1/models` → `gpt6`, `opus-4.8`, `opus-5.5`. Accept: `store-consumer-selection › Worked example` (full plane), `llm-store-gateway › Union with substitution (worked example)`.
- [ ] 15a.3 Detach D: `gpt-4.1` → A. With the OpenAI stub failing, it falls back to DeepSeek. `deepseek-chat` → 403. Accept: `store-consumer-selection › Fallback serves the selected consumer`, `› Fallback does not admit`; `llm-store-gateway › Union without a user link`.
- [ ] 15a.4 Freshness on the full plane: re-attaching with a priority change re-selects; detach one of two, then the last one, leaves `[]` with chat → 403 (OQ1); deleting a personal consumer keeps the key (`GET /principal/llm-key` shows the remaining `consumer_ids`); an inactive linked consumer is skipped. Accept: `owned-key-attachment › Priority change`, `› Detach one of two`, `› Detach the last one`; `personal-key-endpoints › Linked by the reconcile`; `personal-llm-consumers › Delete`; `llm-store-gateway › No links`, `› Inactive consumer is not a link`.
- [ ] 15a.5 Isolation: an application key on `/store/v1` → 401; Ana's key on an application slug → 401; a personal consumer's slug → 404; Ana's key on MCP → 401; a gateway without personal consumers → 404 on `/store/v1/models`. Accept: `personal-key-isolation › Application key on the store`, `› Personal key on an application consumer`, `› Personal consumer by slug`, `› Personal key on MCP`; `llm-store-oss-invariance › Fresh OSS gateway`.
- [ ] 15a.6 Rejected keys end to end: no key, an unknown key, a revoked key and another gateway's key all → 401. Accept: `llm-store-gateway › Valid personal key`, `› Rejected keys` (full plane).
- [ ] 15a.7 Rotation across processes: the admin process rotates; after `InvalidateGatewayDataEvent` the old secret → 401 on the proxy and the new one → 200. Detaching in the admin process changes the proxy's `/models` after the event. Accept: `llm-store-gateway › Rotation seen by another replica`, `› Stale key cache after a detach`.
- [ ] 15a.8 Budget: a global `token_rate_limiter` with `partition: key` hits 429 across requests served by two consumers for one owner. Accept: `token-budget-key-partition › One owner across consumers` (end to end).
- [ ] 15a.9 Run VG and VF.

## Phase 15b: S5e DB-less + docs (base P15a)

Depends: P15a. Est.: ≈180 (test 110 / docs 70). Commit boundary: (a) `test`; (b) `docs`.

- [ ] 15b.1 `tests/functional/dbless_data_plane_test.go`: `TestDBLessDataPlane_LLMStore` reuses the 15a helpers. It runs the worked example rows and `/models` on the DB-less DP. It checks a priority change after the next snapshot apply. It checks the warm request: the DP's config-sync fetch count does not move across a second request (add a harness counter if none exists), and the DP has no DB by construction. Accept: `store-consumer-selection › Worked example` (DB-less), `llm-store-gateway › Warm request on DB-less`, `› Priority change on DB-less`.
- [ ] 15b.2 Same test: admin `DELETE /auths/:id` → 401 on the DP after the next apply; detaching one link → `/models` lists P2's models only. Accept: `owned-api-keys › Admin revocation`, `owned-key-attachment › Detach one of two` (DB-less half).
- [ ] 15b.3 Create `docs/llm-store.md`, covering:
  - the model (personal consumers, personal key, links, levels)
  - the selection rules and the worked example
  - the error table
  - self endpoints and admin attach
  - `partition: key`
  - rollout and rollback
- [ ] 15b.4 Same doc, behaviours to document: N = 0 → 403 and `[]` (OQ1); substitution uses primary registries only (OQ2); `VerdictUnknown` lets a registry without an allow-list admit any short model, so admins add allow-lists on such registries (OQ3); fail-closed 503 (OQ4); hybrid gateways are out of v1; `auth_ids` stays in admin responses.
- [ ] 15b.5 Run VG and VF.

## Phase 16: S6 snapshot metrics (base P5)

Depends: P5. Est.: ≈140 (code 75 / test 65). Commit boundary: one `feat` commit.

- [ ] 16.1 Create `pkg/app/configsnapshot/snapshot_metrics.go`, following the pattern in `tenant_caps_metrics.go:29`: `otel.Meter("trustgate/configsnapshot")`, `trustgate.configsnapshot.encoded_bytes{flavour, scope}` and `trustgate.configsnapshot.entities{kind=auths|owned_auths|personal_consumers|personal_links}`. An instrument error is logged and never returned.
- [ ] 16.2 `pkg/app/configsnapshot/dispatcher.go:231-319`: record on publish only, never on a dedup. The non-partitioned path records as `global`. The "published config snapshot" log stays.
- [ ] 16.3 Test `snapshot_metrics_test.go` (manual reader): the byte values equal the published lengths per flavour; the counts with 2 owned keys and 3 links; OSS data gives zero personal counts; nothing is recorded on a dedup; a no-op meter provider does not fail the publish. Accept: `config-snapshot-metrics › Partitioned publish`, `› Counts`, `› OSS data`, `› No meter provider`.
- [ ] 16.4 Run VG.

## Deploy order

| Step | Action | Where |
|------|--------|-------|
| 1 | DataCore D1 is in prod **before** P1 deploys: events start carrying `auth_id`. | out of repo |
| 2 | P1–P16 merge to `develop` in the merge order above and ship through the normal release train. There is no develop→main promotion. Each PR is inert on deploy, apart from S0 (release note). | TrustGate |
| 3 | **Every TrustGate plane** (admin, proxy, MCP, DB-less DPs, in EU and US) runs a build containing at least P2–P6 and P11–P14 **before the app creates any personal consumer**. Check the healthz `version` on every plane and region. An older DP ignores `audience`, `owner_id` and `auth_links`, and would serve a personal consumer at `/<slug>/v1` with its owned keys (D11 not enforced). | TrustGate |
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
