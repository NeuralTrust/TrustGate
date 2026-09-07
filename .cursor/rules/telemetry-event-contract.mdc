---
description: The OTLP product-event payload is a data contract, not debug output — additive-only attribute rules, class partition, pkg/metrics schema descriptor, and how ops signals stay separate
globs: ["pkg/infra/telemetry/**", "pkg/infra/metrics/**", "pkg/app/metrics/**", "pkg/metrics/**", "pkg/infra/o11y/**", "docs/telemetry/**"]
alwaysApply: false
---

# Telemetry is a data contract

TrustGate emits one OTLP **log record** per completed request (`pkg/infra/telemetry/otlp`).
Operators do not just read those records — they **load** them into typed tables and build
billing, usage and reporting on top. The attribute keys are effectively column names.

Treat every change under the globs above as a **schema migration on someone else's
database**, not as a refactor of log output.

## Why this needs a rule: the failure is silent

Consumers read attributes by literal key. Nothing in the pipeline validates the payload,
so a producer-side mistake does not raise an error anywhere:

| Producer change | What the consumer sees |
|---|---|
| Rename an attribute key | Column silently becomes empty / `0`, forever |
| Change a value's type (number → string, string → JSON) | Cast yields a zero value, or the row fails to parse |
| Stop emitting a join key | Records can no longer be correlated, or are discarded |
| Emit a body attribute on a metadata record | The record is reclassified and leaves the metadata stream |
| Reorder or retype `pkg/metrics` columns | Out-of-tree storage adapters generate different DDL |

There is no schema registry and no cross-repo contract test. **This rule and the tests in
`pkg/infra/telemetry/otlp` are the only guardrails.**

## Rules

1. **Additive only.** Never rename, remove or retype an attribute key that ships today.
   Add a new key beside the old one and keep emitting both until consumers have migrated.
2. **Keys are constants.** Attribute keys live as `const` in `pkg/infra/telemetry/otlp/mapping.go`.
   Never build an attribute key from request, tenant or plugin data — dynamic keys are
   unqueryable and blow up storage cardinality. Dynamic *values* are fine.
3. **The log body stays empty.** All payload travels in attributes. Do not start using the
   body as an escape hatch for structured data.
4. **The class partition is load-bearing.** `metadata` records carry no body attributes;
   `raw` records carry bodies plus join keys only. Consumers separate the two streams by the
   presence of `trustgate.request.body` / `trustgate.response.body`, so adding a body
   attribute to a metadata record does not "add a field" — it moves the record.
5. **Join keys are not optional.** Emit `trustgate.trace_id`, `trustgate.gateway_id` and
   `trustgate.tenant_id` whenever they are known, on both classes. A consumer that keys on
   tenant may drop a record that lacks it.
6. **Types are part of the key.** Numeric attributes stay numeric, bools stay bools, and
   the JSON-encoded string attributes (`trustgate.policy_chain`, `trustgate.attempts`) stay
   JSON strings — do not "improve" them into structured attributes.
7. **`event.name` is the routing key.** It is `trustgate.<schema>.<class>`, derived from
   `events.SchemaVersion`. Bumping that constant changes the event name for every record, so
   it is a deliberate, announced break — not the way to ship a new field.
8. **Update the contract doc in the same change.** `docs/telemetry/otlp-metadata-contract.md`
   is the published description of this payload; a code change that leaves it stale ships a
   lie to operators. Extend the mapping tests in the same commit.

## `pkg/metrics` is a published schema descriptor

`RawColumns()`, `InsertColumns()`, `TableName` and the `Column*` constants exist so that
storage adapters — including ones outside this repository — can generate DDL from the Go
package. Changing a name, type, nullability or **order** there changes those tables.

Bump `metrics.SchemaVersion` and add a migration under `pkg/metrics/migrations`; never edit
a column definition in place. Note that `metrics.SchemaVersion` (storage) and
`events.SchemaVersion` (event payload) are independent — do not assume they move together.

## Operational signals are a different pipeline

`pkg/infra/o11y` (traces + metrics, `OPS_*` env vars) exists to operate the process. It is
**not** the product-event path and must never become one:

- Never move a business field into an ops span or metric, and never make a product event
  depend on an ops provider being enabled.
- Ops attributes stay bounded — plane, route, outcome, status class. No tenant or consumer
  identifiers, no full URLs or query strings, no bodies. Unbounded labels are a cost and
  cardinality incident on the metrics backend.
- Product events must keep working when ops telemetry is off, and vice versa.

## Sensitive data

- Request/response bodies exist **only** on the `raw` class, and only after
  `events.SanitizeBody` / `RedactHeaders` / `SanitizeExtras`.
- Never add an attribute to the metadata class that can carry prompt or response content,
  credentials, or raw headers.
- Never bypass the sanitizers to "keep the payload faithful" — an operator's analytics
  store is not an appropriate place for unredacted credentials.

## Before you merge a telemetry change

- [ ] No existing attribute key renamed, removed or retyped
- [ ] New keys are constants, documented in `docs/telemetry/otlp-metadata-contract.md`
- [ ] Metadata records still carry no body attributes; raw records still carry no metadata
- [ ] `pkg/metrics` column list unchanged, or accompanied by a version bump + migration
- [ ] `go test ./pkg/infra/telemetry/... ./pkg/infra/metrics/... ./pkg/metrics/...` passes
