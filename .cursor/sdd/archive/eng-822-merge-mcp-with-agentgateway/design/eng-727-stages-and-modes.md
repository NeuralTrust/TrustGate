# ENG-727 — Standardize stages and modes in Gateway plugins

> Lightweight design doc (not SDD). Status: **implemented** (see §7).
> Linear: https://linear.app/neuraltrust/issue/ENG-727
> Branch: `educamacho/eng-727-estandarizar-acciones-y-stages-en-plugins-del-gateway`

## 1. Goal

Standardize how Gateway plugins expose **stages** and **modes**:

1. **Stages: kept as they are.** The current mechanism
   (`MandatoryStages`/`SupportedStages` + configurable `Policy.Stages`) is **not
   touched**, leaving the door open to per-policy stage customization later on.
2. **Uniform `mode` contract.** Every plugin exposes, as a frontend contract, a `mode`
   with three values: `enforce`, `throttle`, `observe`. Default is `enforce`.
3. **Mode implementation is each plugin's responsibility.** Not every plugin implements
   every mode. Receiving a mode the plugin does not implement is a **no-op** (the plugin
   keeps its default behavior). `throttle`, in particular, will only be implemented by
   some plugins.
4. **Consistent execution.** Each plugin runs on its mandatory stages (including the
   multi-stage case, e.g. token rate limit needing `pre_request` + `post_response`).

> Terminology note: the original issue says "actions". After review, the concept is
> renamed to **`mode`** to avoid confusion with other "actions" in the system.

> **Closed decisions (review, Jun 8):**
> - Stages: no changes; current configurability is preserved.
> - `mode` is a uniform frontend contract; implementation is up to each plugin and an
>   unimplemented mode is a no-op.

## 2. Current state

### Stages (partially done, but still kept configurable)

- The `Plugin` interface already declares `MandatoryStages()` and `SupportedStages()`
  (`pkg/app/plugins/plugin.go`).
- The stage enum lives in `pkg/domain/policy/plugin.go`: `pre_request`, `post_request`,
  `pre_response`, `post_response` (of which `post_request` is defined but **not
  executed** by the forwarder).
- The user can send `stages` via the API (`CreatePolicyRequest.Stages` /
  `UpdatePolicyRequest.Stages`), it is persisted in the JSONB column `policies.stages`,
  validated against `SupportedStages` (`pkg/app/plugins/stages.go`, `registry.go`), and
  exposed in the catalog (`pkg/app/plugins/catalog.go`).
- In the 5 current plugins `mandatory == supported`, so the user selection is currently
  **inert**. **This is intentionally left in place** for future per-policy stage
  customization.

### Modes (do not exist yet)

- There is no mode enum or method in the `Plugin` interface.
- The only similar thing: `rate_limiter` has an `actions.type` setting (`reject`/`block`)
  that is **not even applied** in `Execute` (always returns 429). See
  `pkg/infra/plugins/ratelimit/config.go` and `plugin.go` (lines ~104-117).
- Today the "block vs observe" behavior is implicit:
  - Block: return `*appplugins.PluginError` (429/403/413).
  - Observe: `Event.SetDecision(...)` + `Event.SetExtras(...)` for metrics/traces.

### Plugin inventory (5)

| Slug | Mandatory stages | Current blocking |
|------|------------------|------------------|
| `rate_limiter` | `pre_request` | 429 when limit exceeded |
| `request_size_limiter` | `pre_request` | 413 when size exceeded |
| `cors` | `pre_request` | 403 disallowed origin / 204 preflight |
| `token_rate_limiter` | `pre_request`, `post_response` | 429 when budget exhausted |
| `semantic_cache` | `pre_request`, `post_response` | cache-hit short-circuit (does not block) |

## 3. Design decisions

### 3.1 Mode: agreed semantics

`mode` is a **single value per policy** (not a set), restricted to the three contract
values, default `enforce`.

| Mode | Semantics | Example in rate_limiter |
|------|-----------|--------------------------|
| `enforce` | Apply the policy and **block** on violation (current behavior). | Returns 429 when exceeded. |
| `throttle` | Apply a **soft** penalty instead of rejection. Only some plugins implement it. | e.g. delay/backpressure instead of 429. |
| `observe` | **Never blocks.** Evaluate, emit metrics/headers/decision and let through (monitor/dry-run mode). | Counts and marks `decision=observe`, but responds 200. |

Contract rules:

- **The three mode values are a fixed vocabulary.** Default `enforce`.
- **Each plugin declares which modes it actually implements** via `SupportedModes()`
  (always includes `enforce`). The catalog exposes this per-plugin list so the frontend
  only offers meaningful options (decision P3).
- **Implementation is each plugin's responsibility.** A plugin only branches on the
  modes it implements.
- **An unimplemented mode is a no-op:** if a mode value outside the plugin's
  `SupportedModes()` is received, the plugin keeps its default behavior (the `enforce`
  one). Sending a valid-enum mode is never a validation error; the catalog list is
  guidance for the frontend, not a hard server-side allowlist.

### 3.2 Stages: no changes

Decision: the stages mechanism is **not modified**. We keep
`MandatoryStages()`/`SupportedStages()`, the `Policy.Stages` field, its validation, and
its catalog exposure (`mandatory_stages` + `supported_stages`), to allow per-policy
customization in the future. This task focuses solely on introducing `mode`.

## 4. Proposed changes (high level)

> Stages are out of scope (§3.2). All work revolves around `mode`.

### Domain (`pkg/domain/policy`)

- New `Mode string` type with `ModeEnforce`/`ModeThrottle`/`ModeObserve`, `IsValid()`,
  and `DefaultMode = ModeEnforce`.
- `Policy`: add a `Mode Mode` field (`Stages` untouched). Default `enforce` on create.

### Plugin contract (`pkg/app/plugins`)

- `ExecInput`: add `Mode policy.Mode` so each `Execute` can branch.
- `Plugin`: add `SupportedModes() []policy.Mode` (must include `enforce`). No mandatory
  stage changes.
- Catalog: `CatalogEntry` adds `supported_modes` (the plugin's implemented modes, per
  P3) and `default_mode` (`enforce`). `mandatory_stages`/`supported_stages` are kept.

### API (`pkg/api/handler/http/policy`)

- `CreatePolicyRequest`/`UpdatePolicyRequest`: add `mode` (optional, default `enforce`).
  Validate it ∈ {enforce, throttle, observe}.
- `PolicyResponse`: expose `mode`.

### Persistence (`pkg/infra/database/migrations`)

- Migration: add a single `mode` column to the existing `policies` table with default
  `enforce` (backfill existing rows to `enforce`). This stores only the *selected* mode
  per policy. The per-plugin set of supported modes is **not** persisted — it lives in
  code (`SupportedModes()`).

### Plugin implementations (`pkg/infra/plugins/*`)

- Pass `mode` from the plan/executor into `ExecInput` and have each plugin read it.
- Base behavior (all): `enforce` = current behavior.
- `observe` (where implemented): never return `PluginError`; record `decision`
  (e.g. `would_block`) and let through.
- `throttle`: only in plugins where it makes sense (see §6 P1).
- A mode not implemented by a plugin behaves as its default (no-op for that mode).
- `rate_limiter`: **deprecate and remove** the `actions.type` setting (reject/block)
  from the catalog schema; blocking-vs-observe behavior is now governed by `mode`
  (decision P2). `retry_after` stays as a setting.

## 5. Phased plan (reviewable commits/PRs)

1. **Domain:** `Mode` type, `DefaultMode`, `Policy.Mode` field. (+ tests)
2. **Contract + catalog:** `ExecInput.Mode`, `supported_modes`/`default_mode` in the
   catalog. (+ catalog tests)
3. **Persistence:** `mode` column migration (default/backfill `enforce`).
4. **API:** request/response + `mode` validation + swagger (`docs/`).
5. **Implementations:** wire `mode` through the executor and apply it in the relevant
   plugins (starting with `enforce`/`observe`; `throttle` where applicable).
6. **Cleanup + docs:** align `rate_limiter.actions.type`, update OpenAPI and this doc.

## 6. Open questions

- **P1 (DECIDED) — Per-plugin mode implementation scope.** Each plugin declares its
  supported modes **in code** via `SupportedModes()` (no DB table for this mapping).
  `throttle` is implemented now in the two rate limiters.

  | Plugin | `enforce` | `observe` | `throttle` |
  |--------|-----------|-----------|------------|
  | `rate_limiter` | current 429 | count + record, mark `would_block`, let through (200) | delay/backpressure instead of 429 |
  | `token_rate_limiter` | current 429 | check + account tokens, let through | delay when near/over budget |
  | `request_size_limiter` | current 413 | measure size, mark, let through | not supported |
  | `cors` | current 403 / 204 | evaluate origin, let through (log only) | not supported |
  | `semantic_cache` | cache active (serve hit + store) | no caching, metrics only | not supported |

- **P2 (DECIDED) — `rate_limiter.actions.type`:** deprecate and remove from the catalog
  schema; behavior governed by `mode`. `retry_after` kept.
- **P3 (DECIDED) — Catalog:** expose per-plugin *implemented* modes via
  `SupportedModes()` + `default_mode`, not a flat list.

## 7. Implementation notes (as built)

All six phases are implemented and unit-tested. Key points and any decision taken
during implementation that was not fully specified above:

- **Domain.** `pkg/domain/policy/mode.go` adds `Mode` (`enforce`/`throttle`/`observe`),
  `DefaultMode = ModeEnforce`, `IsValid()` and `Normalize()` (empty → `enforce`).
  `Policy.Mode` is normalized on construct/update and validated in `Policy.Validate()`.
- **Contract.** `Plugin.SupportedModes()` is required and verified at registration
  (`pkg/app/plugins/modes.go`): the list must be non-empty, valid, and contain
  `enforce`. `ExecInput.Mode` is wired from the policy through `chainEntry` in the plan
  and executor; the executor also records the mode on the trace span (`Event.SetMode`).
- **Decision labels.** On a detected violation a plugin records the trace decision via
  `DecisionForMode(mode)`: `enforce`/unimplemented → `block`, `observe` → `observe`,
  `throttle` → `throttle`.
- **Catalog.** `CatalogEntry` exposes `supported_modes` and `default_mode`.
- **Per-plugin modes (in code):** `rate_limiter` and `token_rate_limiter` =
  `{enforce, throttle, observe}`; `request_size_limiter`, `cors`, `semantic_cache` =
  `{enforce, observe}`.
- **Throttle semantics (decided during implementation):**
  - Shared helper `appplugins.Throttle(ctx, delay)` performs the context-aware sleep and
    applies the upper bound `MaxThrottleDelay = 2s`. Each plugin only computes its own
    mode-appropriate delay and delegates the waiting, so the cap and cancellation
    handling stay consistent across plugins.
  - `rate_limiter`: on an exceeded limit, instead of 429 it delays for the average
    request spacing `window / limit`, then lets the request through and records it. This
    smooths traffic toward the configured rate while bounding how long a request
    goroutine can be parked. When several limits are configured (e.g. `per_ip` + `global`)
    the delay is applied **once per request**, derived from the first (most granular)
    exceeded limit — delays are not summed across limits.
  - `token_rate_limiter`: on an over-budget pre-request, it delays for the window
    duration, then lets the request through. Throttle here is **backpressure only**: it
    does not recoup or shrink token consumption (tokens are still accounted on
    `post_response`). Under concurrency each request goroutine waits independently, each
    bounded by `MaxThrottleDelay`.
  - Both honor context cancellation while delaying (via the shared helper).
- **Observe semantics:**
  - `request_size_limiter` / `cors`: detect the violation, record extras + `observe`
    decision, return `200` (no block, no preflight short-circuit on violations).
  - `rate_limiter` / `token_rate_limiter`: do not reject; still record/account and
    return `200`.
  - `semantic_cache`: never serves a cached response (no short-circuit) and never
    writes to the cache; it only measures the would-be hit/similarity.
- **`actions.type` removal:** the `type` (reject/block) field was removed from the
  `rate_limiter` config struct, its validation, and the catalog settings schema.
  Unknown `type` keys in previously stored settings are ignored on decode (mapstructure
  `ErrorUnused: false`). `retry_after` is kept.
- **Persistence.** Migration `20260608090000_add_policy_mode` adds
  `policies.mode TEXT NOT NULL DEFAULT 'enforce'`; the repository reads/writes the
  column and normalizes empty → `enforce`.
- **Docs.** Swagger/OpenAPI regenerated (`make docs`); `mode` appears on the policy
  request/response and `supported_modes`/`default_mode` on the catalog entry.
