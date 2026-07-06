# Telemetry exporter split — design note (ENG-1015 spike)

Status: **design / decisions** · Epic: **ENG-1013** · Scope: TrustGate only.

This note is the technical design the rest of the TrustGate epic builds on. It answers the
seven spike questions grounded in the current telemetry code, and lists the impact on each
child issue. No production code is part of this spike.

## Goal recap

Split every runtime event into two **data classes** and route each to a different sink:

- **Metadata** → OTel connector (OTLP). Non-sensitive operational data.
- **Sensible** → PostgreSQL, **producer-owned** (exporter + schema + migrations in this repo).

Default exporters come from a **YAML file** (one place, deployment-mode friendly); per-gateway
`telemetry.exporters[]` still merge on top (override by name, no duplication).

> **Kafka is being retired.** The design must not preserve Kafka as a default or fallback; the
> metadata default is OTLP. Removing the Kafka exporter/wiring is a separate effort.

## Current state (what we build on)

| Concern | Where | Notes |
|---|---|---|
| Event model | `pkg/infra/metrics/events/event.go` | `Event` schema **v3**; carries bodies + headers |
| Redaction / caps | `pkg/infra/metrics/events/sanitize.go` | sensitive headers → `[REDACTED]`; bodies capped/multipart-stripped |
| Build | `pkg/app/metrics/builder.go` | folds spans → `*events.Event` |
| Exporter port | `pkg/app/metrics/pipeline.go` | `Exporter{ Name(); Publish(ctx, *Event); Close() }` |
| Template port | `pkg/infra/telemetry/exporter_locator.go` | `ExporterTemplate{ Name; ValidateConfig; WithSettings }` |
| Factory | `pkg/infra/telemetry/exporter_locator.go` | `ExporterLocator` maps `name → template` |
| Cache | `pkg/app/metrics/exporter_cache.go` | keyed by JSON of `ExporterConfig`; `once` build |
| Merge | `pkg/app/metrics/pipeline.go` `resolveTargets` | explicit + defaults, dedupe by `Exporter.Name()` |
| Config value object | `pkg/domain/telemetry/telemetry.go` | `Telemetry{Exporters []ExporterConfig}`, `ExporterConfig{Name, Settings}` |
| Boot defaults | `pkg/container/modules/telemetry.go` `buildPipeline` | single hardcoded **kafka** default (to be removed) |
| Config load | `pkg/config/config.go` | **env-only**; no YAML loader yet; `mapstructure` used for settings |
| Control-plane migrations | `pkg/infra/database/migrations_manager.go` | in-code `init()` registry, `migration_version` table, **no advisory lock** |
| DB | `pkg/infra/database/connection.go` | `pgxpool`; `DatabaseConfig` (host/port/user/pass/name/sslmode) |

Two structural facts drive several decisions below:

1. **`ExporterConfig.Name` is both the template type and the instance identity.** `ExporterLocator.Build`
   looks up `templates[cfg.Name]`, and `resolveTargets` dedupes by `Exporter.Name()` (== template name).
   So today you cannot have two instances of the same type, and "override by name" actually means
   "override by type".
2. **The exporter port receives the whole `*events.Event`.** There is no notion of a partial/projected
   event. The OTLP mapper already carries sensible content (`trustgate.request.body`, record body =
   response body), so today metadata and sensible are **not** separated.

---

## Q1 — Data classification (field-level partition of `events.Event`)

Partition is by field, computed from a **single built event** (no second builder). Correlation keys
are duplicated into **both** views so the sensible row can be joined back to the metadata record.

**Decision (narrowed): sensible data is ONLY the request input and the response output — i.e. the two
payload bodies.** Everything else is metadata.

**Correlation keys (in both views):** `SchemaVersion`, `TraceID`, `GatewayID`, `TeamID`, `OccurredOn`
(+ `Timestamp`).

**Sensible (→ Postgres):** `Request.Body` (input) and `Response.Body` (output). Nothing else.

**Metadata (→ OTLP):** everything except the two bodies — including `Request.Headers`,
`Response.Headers`, `IP`, `Consumer{ID,Name}`, `SessionID`, `TurnID`, `Status`, `IsFlagged`, `Security`,
`Latency`, `Usage`, `Cost`, `Attempts`, `PolicyChain`, the non-body request/response fields, and the
full `MCP` struct.

Rationale / edge calls:

- **Headers → metadata.** `RedactHeaders` already masks known credentials before the event is built,
  so header values in metadata are already redacted; they are not treated as sensible payload.
- **`IP` → metadata.** No longer classified as sensible.
- **`MCP.Prompt` → metadata (decided).** The MCP prompt originates from the MCP server, not from the
  end-user request payload, so it is treated as metadata, not sensible.

**Implementation shape (ENG-1018):** add two projections on the event, returning shallow copies so we
never mutate the built event and never re-run the builder:

```go
func (e *Event) MetadataView() *Event  // Request.Body / Response.Body zeroed
func (e *Event) SensibleView() *Event  // keeps only correlation keys + the two bodies
```

The `Exporter` port stays `Publish(ctx, *events.Event)` — the pipeline just hands each exporter the
projection matching its class. This is the lowest-risk option: no port change, exporters can't leak
across classes because the fields simply aren't present in the struct they receive.

---

## Q2 — Exporter data-class contract

**Invariant (decided): the data class is an intrinsic, fixed property of the exporter *type* — it is
never user-configurable.**

- `type DataClass string` with `DataClassMetadata = "metadata"`, `DataClassSensible = "sensible"`.
- `postgres` is the **only sensible sink**: it receives **sensible data only** and can never be
  reused as a metadata exporter.
- **Every other exporter is metadata-only.** By default any exporter receives metadata.
- There is therefore **no `data_class` field** in `ExporterConfig` or the YAML — nothing to configure,
  nothing to misconfigure, no cross-class leakage possible.

Contract shape: the class lives on the template/exporter, not the config.

```go
// on ExporterTemplate and on the built Exporter
func (t *Template) DataClass() metrics.DataClass // otlp → metadata; postgres → sensible
```

- `otlp` (and any future metadata exporter) → `DataClassMetadata`, hardcoded.
- `postgres` → `DataClassSensible`, hardcoded.

The pipeline reads `exporter.DataClass()` at routing time to pick the projection (Q4). Because the
class is bound to the type, a `postgres` target **always** gets `SensibleView()` and a metadata target
**always** gets `MetadataView()` — the invariant is structural, not a validation rule.

---

## Q3 — YAML defaults schema + `ExporterConfig` evolution

Introduce a `type` field so **identity (`name`) and template (`type`) are separable**, fixing structural
fact #1 while staying backward compatible.

```go
type ExporterConfig struct {
    Name     string                 `json:"name"`           // unique identity + override key
    Type     string                 `json:"type,omitempty"` // template; defaults to Name
    Settings map[string]interface{} `json:"settings"`
}
```

- No `data_class` field: the class is intrinsic to `type` (Q2).
- `Build`/`Validate` look up `templates[cfg.effectiveType()]` where `effectiveType()` returns `Type`
  or, if empty, `Name`. Existing gateway configs (only `name`+`settings`) keep working: `name` doubles
  as type.
- This unlocks multiple instances of one metadata type (e.g. two `otlp` exporters with different
  endpoints and distinct `name`s) — needed once SaaS vs Hybrid want different metadata sinks.

**YAML file** (`config/telemetry.example.yaml`, path from `TELEMETRY_EXPORTERS_FILE`):

```yaml
exporters:
  - name: metadata-otlp        # metadata-only (every non-postgres exporter is metadata)
    type: otlp
    settings:
      endpoint: ${OTEL_EXPORTER_OTLP_ENDPOINT}
      protocol: grpc
  - name: sensible-pg          # postgres → sensible-only, fixed; cannot be a metadata sink
    type: postgres
    settings:
      dsn_env: SENSIBLE_PG_DSN   # env var NAME, not the DSN — keeps secrets out of the file
      table: sensible_records
```

**Loader (ENG-1016):** new YAML loader (add `gopkg.in/yaml.v3`) → `[]telemetrydomain.ExporterConfig`;
each entry validated via `ExporterFactory.Validate`. Absent/empty file → **no defaults** + a clear
warning (no Kafka fallback). Invalid file → fail fast at boot.

Deployment-mode routing (Hybrid vs SaaS) is expressed **only** by shipping a different YAML per
environment — no code branching. That is the whole point of "config in one place".

---

## Q4 — Merge semantics

Rule: **union of file-defaults + per-gateway exporters, deduped by `name`, gateway wins on collision.**

Required correction to `resolveTargets`: today it dedupes by `Exporter.Name()` (== template type).
With the `name`/`type` split, dedupe must be on the **config `name`** (identity). The pipeline must
therefore carry the config identity alongside the built exporter instead of relying on
`Exporter.Name()`:

- Keep defaults as `[]struct{ cfg ExporterConfig; exp Exporter }` (or a `map[name]Exporter` with a
  parallel class lookup).
- Merge: start from gateway-resolved (by `name`), then append each default whose `name` is not already
  present.
- Routing per target: read `exporter.DataClass()` (intrinsic to type, Q2) — `postgres` → `SensibleView()`,
  every other exporter → `MetadataView()`.

Matrix to test (ENG-1017/1021):

| Gateway defines | Result |
|---|---|
| nothing | all file defaults run, each with its class projection |
| `name` X that is also a default | gateway X used, default X dropped (no dup) |
| new `name` Y | defaults + Y run |
| empty defaults + no gateway exporters | no targets (no implicit Kafka) |

---

## Q5 — `pkg/metrics` nested module + sensible table

**Module:** `github.com/NeuralTrust/TrustGate/pkg/metrics`, its own `go.mod`, **dependency-light**
(stdlib only — no `pgx`, no gateway packages). Parent module adds `require` + a local
`replace ./pkg/metrics` for dev. Imported by this repo's `infra/telemetry/postgres` **and** by
DataCore/DataAgent (consumer→producer only).

Package layout:

```
pkg/metrics/
  go.mod
  record.go      // SensibleRecord (row type, db/json tags)
  schema.go      // TableName, column names, Migrations []Migration (DDL as strings)
  allowlist.go   // columns exposed to the read path (filter/select allow-list)
  version.go     // SchemaVersion const
```

`Migration` is a **driver-free** value so the module stays dependency-light; the pgx-based runner lives
in `infra/telemetry` (Q on migrations below):

```go
type Migration struct { ID, Name, UpSQL, DownSQL string }
```

**Sensible table (v1):**

```sql
CREATE TABLE IF NOT EXISTS sensible_records (
    trace_id         TEXT        NOT NULL,
    gateway_id       TEXT        NOT NULL,
    team_id          TEXT,
    occurred_on      BIGINT      NOT NULL,          -- epoch millis, from Event.OccurredOn
    schema_version   INT         NOT NULL,
    request_body     TEXT,                          -- input
    response_body    TEXT,                          -- output
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (trace_id)
);
CREATE INDEX IF NOT EXISTS idx_sensible_gateway_time ON sensible_records (gateway_id, occurred_on);
```

`trace_id` is the join key back to the metadata record in ClickHouse. `INSERT` is built from the
column contract in `schema.go` (parameterized only). `SchemaVersion` (module) is written into every
row so consumers can adapt across versions.

---

## Q6 — Versioning & coherence

- The nested module is versioned **independently** with path-prefixed tags: `pkg/metrics/vX.Y.Z`
  (Go versions at module granularity; a subpackage cannot carry its own version — hence the nested
  module). CI auto-tags on merge to `main` (**ENG-1034**).
- `SchemaVersion` const in the module + `schema_version` column per row.
- **Expand → migrate → contract**, N/N-1 support so a producer schema bump doesn't break consumers
  mid-deploy (**ENG-1033** owns the cross-repo compatibility gate).
- Migrations are **additive** wherever possible (new nullable columns / new tables); destructive
  changes span two releases.

---

## Q7 — DSN: SaaS vs Hybrid

The write path is **identical** in both modes; only the injected DSN differs, so there is no code
branching on deployment mode.

- **Secrets stay out of the YAML.** Settings reference an **env var name** (`dsn_env: SENSIBLE_PG_DSN`),
  not the DSN literal. The exporter reads that env var at build time. (A raw `dsn` key may be allowed
  for local/dev, but env-name is the documented default and satisfies the `.env` / no-secrets rule.)
- **SaaS:** `SENSIBLE_PG_DSN` points to the SaaS-managed sensible Postgres (own DB/cluster, per
  database-per-service).
- **Hybrid:** TrustGate runs inside the customer boundary and writes to a **customer-side** Postgres;
  `SENSIBLE_PG_DSN` points there. DataAgent later reads that same DB in-boundary. TrustGate never
  reaches out of the boundary for this.

---

## Migrations on-enable (sensible DB)

The sensible Postgres is a **different database** from the control-plane DB and may be provisioned
lazily (and, in Hybrid, inside the customer boundary), so we **cannot** reuse
`database.MigrationsManager` (it targets the control-plane pool + `migration_version`, and has **no
advisory lock**). ENG-1020 adds a dedicated runner in `infra/telemetry/postgres`:

- Opens the sensible pool via `pgx` from the resolved DSN.
- Takes a **Postgres advisory lock** (`pg_advisory_lock(<const key>)`) so multiple replicas don't race
  the first-time DDL.
- Ensures a `schema_migrations` table in the sensible DB and applies pending `Migration.UpSQL` from the
  module in order, idempotently (`CREATE TABLE IF NOT EXISTS`).
- Runs **only when the `postgres` exporter is enabled** (first build), not at global boot.

---

## Child-issue impact

| Issue | Refinement from this spike |
|---|---|
| **ENG-1016** load YAML defaults | add `gopkg.in/yaml.v3`; map to extended `ExporterConfig`; no-file → no defaults + warning |
| **ENG-1017** merge | dedupe by config **`name`** (not `Exporter.Name()`); carry identity+class in the pipeline |
| **ENG-1018** classify | add `MetadataView()`/`SensibleView()` projections; sensible = request+response bodies only (headers/IP/MCP → metadata); class is intrinsic to exporter type (default metadata) |
| **ENG-1019** OTLP metadata | metadata-only exporter (`DataClass()==metadata`); consume `MetadataView()`; drop `trustgate.request.body` + response-body-as-record-body from the metadata path |
| **ENG-1020** Postgres exporter | sensible-only, fixed `DataClass()==sensible`, never a metadata sink; dedicated advisory-locked runner + DDL from module; parameterized INSERT from column contract |
| **ENG-1021** routing + API | route by `exporter.DataClass()`; extend `validateExporters` for `type`/`postgres` (no `data_class` field); docs + example |
| **ENG-1034** CI auto-tag | tag `pkg/metrics/vX.Y.Z` on merge to main |

## Resolved decisions

1. **`MCP.Prompt` → metadata.** It comes from the MCP server, not the end-user request payload.
2. **Add `type` to `ExporterConfig` now** (separate identity `name` from template `type`).
3. **Module name: `pkg/metrics`** (`github.com/NeuralTrust/TrustGate/pkg/metrics`).

## Decided invariants (not up for change)

- Data class is **intrinsic to the exporter type**, never a config field.
- `postgres` is **sensible-only** and can never be reused as a metadata exporter.
- Every other exporter is **metadata-only**; the default class any exporter receives is metadata.
- Sensible data = **request input body + response output body only**; everything else is metadata.
