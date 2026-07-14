# Producer schema versioning & compatibility (`pkg/metrics`)

`pkg/metrics` is a **nested, independently versioned Go module** that carries the
producer-owned data contract for the raw telemetry store: the table name, the
row shape (`RawRecord`), the `SchemaVersion` constant, the `DataClass` values,
and the ordered migrations. TrustGate writes rows through it; downstream
consumers (DataCore / DataAgent, once they read the residency store) import it to
decode those rows. Because producer and consumers deploy independently, a change
here can break a consumer that is still running the previous version.

This document is the policy that keeps that from happening silently, plus the CI
gate that enforces it.

## Module boundary

- **Path:** `pkg/metrics` (own `go.mod`, module
  `github.com/NeuralTrust/TrustGate/pkg/metrics`).
- **Dependency-light:** the module must not depend on the DB driver or any of the
  service's dependencies. Consumers should inherit the contract, not TrustGate's
  runtime. The gate fails any `go.mod` that gains a `require`, `replace`, or
  `exclude` directive.
- **Versioning:** semver via **path-prefixed tags** `pkg/metrics/vX.Y.Z`, created
  automatically on merge to `main` by
  [`metrics-module-release.yml`](../../.github/workflows/metrics-module-release.yml)
  (ENG-1034). The bump level is derived from the Conventional Commit messages
  that touched the module (`feat` → minor, `type!:`/`BREAKING CHANGE` → major,
  otherwise patch).

## The two version numbers

| Number | Where | Meaning |
|---|---|---|
| Module semver (`pkg/metrics/vX.Y.Z`) | git tag | The Go API contract of the module. Bumps whenever the exported API changes. |
| `SchemaVersion` (int) | `pkg/metrics/version.go` | The wire/row schema generation stamped on every emitted record. Bumps when the persisted row shape changes in a way consumers must branch on. |

They move together for schema changes but answer different questions: semver
protects the *Go import*, `SchemaVersion` protects the *stored data*.

## Compatibility rules

1. **N / N-1 support window.** A consumer running schema version `N-1` must keep
   working against a producer at version `N`. Do not remove or repurpose a field
   that an in-window consumer still reads.
2. **Expand → migrate → contract.** Never change a column or field in place:
   - **Expand:** add the new column/field (nullable / optional). Additive changes
     are backward-compatible.
   - **Migrate:** backfill and switch readers/writers to the new shape; bump
     `SchemaVersion`.
   - **Contract:** only after no supported consumer needs the old shape, remove
     it (this is the breaking step and requires a major module bump).
3. **A breaking change must be acknowledged.** An API-incompatible change is only
   allowed together with either a `SchemaVersion` bump or a Conventional Commit
   breaking marker (`type!:` subject or a `BREAKING CHANGE` footer). The gate
   rejects an incompatible change that has neither.
4. **`SchemaVersion` never decreases.**

## The CI compatibility gate

Job **`metrics-compat-gate`** in [`ci.yml`](../../.github/workflows/ci.yml) runs on
every PR (it is safe to make it a required status). It self-skips when the PR does
not touch `pkg/metrics`.

When `pkg/metrics` changes, the gate:

1. Verifies `pkg/metrics/go.mod` is still dependency-light.
2. Picks a baseline: the latest `pkg/metrics/v*` tag, else the PR merge-base.
3. Runs [`apidiff`](https://pkg.go.dev/golang.org/x/exp/cmd/apidiff) in module mode
   between baseline and HEAD and looks for **incompatible** changes.
4. Reads `SchemaVersion` at both revisions and inspects the commit messages that
   touched the module for a breaking marker.
5. Applies the decision table below.

| apidiff | `SchemaVersion` | breaking marker | Result |
|---|---|---|---|
| compatible | any (not lower) | — | **pass** |
| incompatible | bumped | — | **pass** |
| incompatible | unchanged | present | **pass** |
| incompatible | unchanged | absent | **fail** |
| — | decreased | — | **fail** |

The pure decision logic lives in
[`.github/scripts/metrics-compat-lib.sh`](../../.github/scripts/metrics-compat-lib.sh)
and is unit-tested by `metrics-compat-lib.test.sh` (run in the `scripts-tests`
job). The orchestration (git, worktrees, apidiff) lives in
[`.github/scripts/metrics-compat-gate.sh`](../../.github/scripts/metrics-compat-gate.sh).

### Making a breaking change on purpose

Do the contract step, then acknowledge it so the gate stays green and the module
gets a major tag on merge:

- Bump `SchemaVersion` in `pkg/metrics/version.go`, **or**
- Land it under a breaking Conventional Commit (`feat(metrics)!: …` or a
  `BREAKING CHANGE:` footer).

Prefer bumping `SchemaVersion` whenever the *stored row shape* changed; use the
commit marker for Go-API-only breaks that do not alter persisted data.

## Deploy ordering

For a schema change that consumers must absorb:

1. Ship the **expand** migration (additive, backward-compatible).
2. Roll out the **producers** (TrustGate) writing the new shape.
3. **Bump the pinned `pkg/metrics` version in consumers** and roll them out.
4. Ship the **contract** migration only once every supported consumer is at the
   new version.

## Local multi-module workflow

`pkg/metrics` is its own module, so test and lint it on its own:

```bash
cd pkg/metrics
go build ./...
go vet ./...
go test -race ./...
```

The root module resolves it via a `replace` directive
(`replace github.com/NeuralTrust/TrustGate/pkg/metrics => ./pkg/metrics`) in the
root `go.mod`; run `go mod vendor` at the root after changing the nested module so
the vendored copy stays in sync.

## Consumer pinning (future)

Once DataCore / DataAgent import `pkg/metrics`, they pin an explicit
`pkg/metrics/vX.Y.Z` in their `go.mod` and bump it deliberately (via an explicit
PR or Renovate). At that point a **consumer-side build gate** — building the
consumer against the pinned producer version in the consumer's CI — becomes the
strongest guarantee and should be added there. Until a consumer imports the
module, this producer-side gate (API compatibility + version discipline +
dependency-light + written policy) is the enforceable contract.
