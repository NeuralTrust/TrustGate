# `ratelimit` — Request Rate Limiting

Catalog slug: `rate_limiter`

Sliding-window request counter backed by Redis. Whether the budget is
gateway-wide or per consumer is decided by the policy scope
(`Policy.Global`) at runtime, not by configuration.

Source:

- `pkg/infra/plugins/ratelimit/config.go`
- `pkg/infra/plugins/ratelimit/plugin.go`
- `docs/policies.json` (`Traffic Control` → `rate_limiter`)

Stages: `pre_request` (mandatory and only supported stage).
Protocols: `LLM`, `MCP`.
Modes: `enforce`, `throttle`, `observe`.

## Configuration fields

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `limit` | integer | yes | — | Max requests allowed inside `window`. Must be `> 0`. |
| `window` | string (Go duration) | yes | — | Sliding window, e.g. `1s`, `1m`, `1h`. Parsed with `time.ParseDuration`; must be `>= 1s` (requests are counted at 1-second resolution). |
| `retry_after` | string (seconds) | no | window in seconds (ceiling) | Value sent in the `Retry-After` header on `429`. E.g. `1m` → `"60"`, `10s` → `"10"`, `1500ms` → `"2"`. |
| `group_by_header` | string | no | `""` | Optional request header (e.g. `X-User-Id`) that sub-partitions the counter inside the policy scope. Each distinct header value gets its own budget. Empty or absent header falls back to the scope subject (gateway or consumer); an empty header value is treated as absent. |

Scope: a global policy shares one counter across the gateway;
a consumer policy gives each consumer an independent budget for the same
policy ID. With `group_by_header`, a global policy shares the header bucket
across consumers, while a consumer policy isolates it per consumer.

## Example JSON

Policy `settings` object:

```json
{
  "limit": 100,
  "window": "1m",
  "retry_after": "60"
}
```

Minimal (uses the default `retry_after`):

```json
{
  "limit": 100,
  "window": "1m"
}
```

Per-end-user partition inside a consumer scope:

```json
{
  "limit": 20,
  "window": "1m",
  "group_by_header": "X-User-Id"
}
```

Full policy object (Admin API):

```json
{
  "name": "rate-limit-global",
  "slug": "rate_limiter",
  "enabled": true,
  "priority": 10,
  "parallel": false,
  "stages": ["pre_request"],
  "settings": {
    "limit": 100,
    "window": "1m",
    "retry_after": "60"
  }
}
```

Create it against `make up` (admin on `:8080`):

```bash
ADMIN="http://localhost:8080"
curl -s -X POST "$ADMIN/v1/gateways/$GW_ID/policies" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"rate-limit-global","slug":"rate_limiter","enabled":true,"priority":10,"parallel":false,"stages":["pre_request"],"settings":{"limit":100,"window":"1m"}}'
```

## Behavior

- Under the limit the request passes with
  `X-RateLimit-<consumer|global>-Limit`,
  `X-RateLimit-<...>-Remaining` (budget left once this request is counted),
  and `X-RateLimit-<...>-Reset` (unix time) headers.
- Over the limit in `enforce` mode: `429` with `Retry-After` and a JSON body
  (`error: "rate limit exceeded"`, `reason`/`scope`, `limit`, `window`,
  `retry_after_seconds`).
- `throttle` mode delays by `window / limit` instead of rejecting;
  `observe` mode never rejects but still records the decision and
  `RateLimiterData` extras.
- Fail-closed: invalid config, a non-global policy without a consumer ID, and
  Redis count/record errors return an error instead of bypassing the limit.
  See also the gateway-plane vs middleware discussion in
  [#519](https://github.com/NeuralTrust/TrustGate/issues/519).
