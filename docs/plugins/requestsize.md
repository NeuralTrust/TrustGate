# `requestsize` — Request Size Guard

Catalog slug: `request_size_limiter`

Rejects requests whose body exceeds a byte limit or a UTF-8 character limit,
optionally requiring a `Content-Length` header.

Source:

- `pkg/infra/plugins/requestsize/config.go`
- `pkg/infra/plugins/requestsize/plugin.go`
- `docs/policies.json` (`Traffic Control` → `request_size_limiter`)

Stages: `pre_request` (mandatory and only supported stage).
Protocols: `LLM`, `MCP`.
Modes: `enforce`, `observe`.

## Configuration fields

| Field | Type | Required | Default | Effect |
|---|---|---|---|---|
| `allowed_payload_size` | integer | yes | `10` (Admin UI schema) | Max payload size in `size_unit` units. Must be `> 0`. |
| `size_unit` | enum `bytes` \| `kilobytes` \| `megabytes` | no | `megabytes` | Unit for `allowed_payload_size`. Effective byte limit is `size × 1`, `× 1024`, or `× 1024 × 1024`. |
| `max_chars_per_request` | integer | no | `100000` when omitted | Max UTF-8 characters (rune count) in the body. Must be `> 0` when set; `0` is rejected instead of silently taking the default. |
| `require_content_length` | boolean | no | `false` | When `true`, requests without a `Content-Length` header are rejected with `411` in `enforce` mode. |

## Example JSON

Policy `settings` object (1 KB cap):

```json
{
  "allowed_payload_size": 1,
  "size_unit": "kilobytes",
  "max_chars_per_request": 50000,
  "require_content_length": false
}
```

10 MB default-style cap:

```json
{
  "allowed_payload_size": 10,
  "size_unit": "megabytes"
}
```

Full policy object (Admin API):

```json
{
  "name": "request-size-guard",
  "slug": "request_size_limiter",
  "enabled": true,
  "priority": 10,
  "parallel": false,
  "stages": ["pre_request"],
  "settings": {
    "allowed_payload_size": 1,
    "size_unit": "kilobytes",
    "max_chars_per_request": 50000,
    "require_content_length": false
  }
}
```

Create it against `make up` (admin on `:8080`):

```bash
ADMIN="http://localhost:8080"
curl -s -X POST "$ADMIN/v1/gateways/$GW_ID/policies" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"request-size-guard","slug":"request_size_limiter","enabled":true,"priority":10,"parallel":false,"stages":["pre_request"],"settings":{"allowed_payload_size":1,"size_unit":"kilobytes"}}'
```

## Behavior

- Byte check runs first (`received %d bytes`), then the character check
  (`received %d characters`). Either exceeded limit returns `413` in
  `enforce` mode; missing `Content-Length` with `require_content_length`
  returns `411`.
- Allowed requests carry `X-Request-Size-Bytes`, `X-Request-Size-Chars`,
  `X-Size-Limit-Bytes`, and `X-Size-Limit-Chars` headers.
- `observe` mode never blocks; it records the decision and size extras.
- Fail-closed in `enforce` mode (oversize/missing-length requests are
  rejected before upstream); fail-open only in `observe` mode.
