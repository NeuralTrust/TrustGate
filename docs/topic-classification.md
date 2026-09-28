# Topic classification

TrustGate can classify the topic of the prompt of every chat request of a
gateway against **topic-guard**, the customer-defined topic model served by the
firewall. It is a gateway feature with its own async process: it never blocks,
delays or alters a request, and it is not a policy plugin.

## Turning it on

It is set on the gateway, through the create and update gateway API, and
reaches the data planes in the config snapshot. There is no environment flag.

```json
{
  "topic_classification": {
    "enabled": true,
    "topics": [
      {"name": "billing", "definition": "Refunds, invoices and charges"},
      {"name": "legal", "definition": "Contracts and terms of service"}
    ],
    "threshold": 0.6,
    "message_window": 3,
    "sampling_rate": 1.0
  }
}
```

| Field | Meaning |
|---|---|
| `enabled` | Classify this gateway's chat requests |
| `topics` | 1 to 10 topics, unique `name`, non-empty `definition` |
| `threshold` | Optional. Without it topic-guard applies its calibrated operating point |
| `message_window` | How many of the latest `user` messages are classified. Default 3, max 50. The system prompt is never sent |
| `sampling_rate` | Fraction of requests to classify, 0 to 1. Default 1 |

Sending `{"enabled": false}` turns it off; the change reaches the data planes
with the next snapshot.

## How a request flows

```
Auth → HybridGatewayGuard → Session → Metrics → TopicClassification → handler
                                                        │
          body copy (capped) + non-blocking send to an in-memory buffer
                                                        │
      dispatcher: decode, last N user messages, truncate to 10,000 chars,
                  sample, per-gateway quota + XADD to a Redis stream
                                                        │
      worker: read, cache by text + catalog + threshold + model version,
              batch per gateway and catalog, POST /v1/topic-guard
                                                        │
      topic_classification event through the gateway's OTLP exporters
```

- The middleware runs before any plugin, so requests a guardrail blocks are
  classified too. Only `chat` routes are offered; embeddings, rerank, files,
  images and audio are not.
- Nothing on the request path decodes JSON or reaches Redis. A full buffer
  drops the candidate and counts it.
- The worker keeps a fixed number of calls in flight per replica. A 503 from
  topic-guard pauses the whole worker for `Retry-After` without counting as a
  failure; real errors retry with backoff behind a circuit breaker.
- Entries left pending by a pod that dies are reclaimed by the others. An entry
  handed out too many times is dropped.

## What leaves TrustGate

- **To topic-guard** (the firewall): the text of the latest user messages and
  the gateway's catalog.
- **To Redis**: the same text, in the stream, for at most
  `TOPIC_CLASSIFIER_STREAM_RETENTION` (1 h by default), and the classification
  in the cache for `TOPIC_CLASSIFIER_CACHE_TTL`.
- **To the OTel collector**: the classification and the trace id, never the
  prompt. See the [event contract](telemetry/otlp-metadata-contract.md#topic-classification-event).
  Downstream, a view keyed on the event name routes these records to their
  own table; the attributes stay out of the `trustgate_events` namespace so
  they are never counted as requests.

## Tuning

The `TOPIC_CLASSIFIER_*` variables in `.env.example` tune buffers, the stream,
the per-gateway quota, concurrency, batching and retries. None of them turns
the feature on or off.

The `worker` plane (`trustgate worker`) runs only the consumer, without an HTTP
server, for deployments that need to scale classification apart from the
proxies. The `proxy` and `run` planes run both the intake and a worker.

## Rollback

- Per gateway: `topic_classification.enabled = false`.
- Globally: revert the deploy. The `topic_classification` column is nullable
  and older code ignores it, so the migration does not need reverting.
