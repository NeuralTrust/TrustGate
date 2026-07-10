# Telemetry sink examples

Per-sink example records for one gateway request fanned out to the three data-class sinks.

> These are **schema-accurate representative** records derived from the OTLP mapping
> (`pkg/infra/telemetry/otlp/mapping.go`) and the postgres exporter
> (`pkg/infra/telemetry/postgres/exporter.go`), not a live capture. The scenario is an
> OpenAI chat completion whose request contains an email that a DLP policy masks.

**Live verification:** run the exhaustive 3-sink check (metadata OTLP, raw OTLP, postgres)
against a local compose stack:

```bash
bash scripts/telemetry/verify_three_sinks.sh
```

The script boots postgres/redis/kafka/otel-collector, starts admin+proxy with
`config/telemetry.verify.yaml`, drives a proxy request, and asserts **51 checks**
including `EventName: trustgate.3.metadata` / `trustgate.3.raw`, body presence/absence
per class, and a `trustgate_data` row.

Routing is **config-driven**: the YAML **group** (`metadata` vs `raw`) picks the data class;
the exporter **type** (`otlp` vs `postgres`) picks the transport.

| Sink | YAML path | Goes to |
|------|-----------|---------|
| metadata OTLP | `exporters.metadata[].type: otlp` | `OTEL_EXPORTER_OTLP_ENDPOINT` → OpenTelemetry Collector |
| raw OTLP | `exporters.raw[].type: otlp` | Same OTLP endpoint, `EventName: trustgate.<version>.raw` |
| postgres | `exporters.raw[].type: postgres` | `dsn` → Postgres `trustgate` DB → table **`trustgate_data`** |

## Sinks at a glance

| Sink | Type | Event name | Bodies? | `policy_chain` | `is_flagged` | File |
|------|------|-----------|:------:|:--------------:|:------------:|------|
| 1 — metadata OTLP | `otlp` (metadata) | `trustgate.3.metadata` | ❌ | ✅ | ✅ | [`sink-1-metadata-otlp.json`](./sink-1-metadata-otlp.json) |
| 2 — raw OTLP | `otlp` (raw) | `trustgate.3.raw` | ✅ | — | — | [`sink-2-raw-otlp.json`](./sink-2-raw-otlp.json) |
| 3 — postgres | `postgres` (raw) | — | ✅ | — | — | [`sink-3-postgres.json`](./sink-3-postgres.json) |

Notes:

- The event name uses `trustgate.<version>.<verb>` where `<version>` is the **event** schema
  version (`events.SchemaVersion`, currently `3`) and `<verb>` is the data class
  (`metadata` / `raw`). One trace emits both `trustgate.3.metadata` and `trustgate.3.raw`.
- The `trustgate_data` row's `schema_version` column is the **storage** schema version
  (`metrics.SchemaVersion`, currently `1`) — it tracks the table shape, not the event schema.
- The email is in clear text in the raw sinks (2 and 3) and masked (`[MASKED_EMAIL]`) in the
  transformed response, so raw sinks must land on a restricted destination.
- Join sink 1 (metadata) to sinks 2/3 (raw) on `trace_id`.

See the full field-by-field mapping in [`../otlp-metadata-contract.md`](../otlp-metadata-contract.md).
