# OTLP metadata export contract

TrustGate emits one OTLP **log record** per gateway request. This contract describes the
**metadata** data class: the pipeline passes `events.MetadataView(evt)` so request/response
**bodies are not exported**. Raw bodies are available when an `otlp` exporter is declared
with `"class": "raw"` on the gateway — see dual-export below.

## Event name

`trustgate.<version>.<verb>` (`resource.version.verb`):

| Class | EventName example |
|-------|-------------------|
| metadata | `trustgate.3.metadata` |
| raw | `trustgate.3.raw` |

Version tracks `schema_version` on the event (currently `3`). Downstream consumers route on
`EventName`.

## Invariants

| Rule | Detail |
|------|--------|
| Log body | Always empty |
| Bodies (metadata) | Not emitted (no `trustgate.request.body` / `trustgate.response.body`) |
| Bodies (raw) | Emitted as attributes when exporter `class` is `raw` |
| `policy_chain` | AlertEngine-facing projection (`source.plugin`, `signal`, `outcome`, `report_only`) |
| `plugin_chain` | Full plugin chain without `extras` (debug / HyperDX) |
| `is_flagged` | `trustgate.is_flagged` (bool), computed at event build time |

## Dual export (gateway config)

Unlike TrustGuard's YAML groups, TrustGate configures exporters per gateway in
`telemetry.exporters[]`. Set `class` on each exporter:

```json
{
  "telemetry": {
    "exporters": [
      {
        "name": "otlp",
        "class": "metadata",
        "settings": { "endpoint": "collector:4318", "protocol": "http/protobuf" }
      },
      {
        "name": "otlp",
        "class": "raw",
        "settings": { "endpoint": "collector:4318", "protocol": "http/protobuf" }
      }
    ]
  }
}
```

When `class` is omitted, it defaults to **`metadata`** (no bodies).

The process-level **Kafka** default exporter uses `class: raw` so the full event JSON is
unchanged for the ClickHouse path.

## Routing

```text
POST /gateway
       │
       ▼
  events.Event (full, sanitized)
       │
       ├── exporter class metadata  →  MetadataView  →  trustgate.3.metadata
       ├── exporter class raw       →  full event    →  trustgate.3.raw
       └── kafka (default, raw)     →  full JSON to topic
```
