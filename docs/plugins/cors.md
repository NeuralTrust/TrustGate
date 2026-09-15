# `cors` — Cross-Origin Resource Sharing

`cors` is not a policy plugin: there is no `cors` slug in
`docs/policies.json` and no per-policy `settings`. It is global Fiber
middleware applied to the admin and proxy servers, configured only via
environment variables.

Source:

- `pkg/config/config.go` (`CORSConfig`, `getCORSConfig`, defaults)
- `pkg/api/middleware/cors.go` (`CORSMiddleware`)
- `.env.example` (`CORS_*`)

## Configuration fields

Set via environment (CSV = comma-separated list). All are optional.

| Env var | Type | Default | Effect |
|---|---|---|---|
| `CORS_ALLOW_ORIGINS` | CSV string | `*` | Allowed `Origin` values. `*` allows any origin (without credentials). Otherwise the request `Origin` must match an entry (case-insensitive) to get CORS headers. |
| `CORS_ALLOW_METHODS` | CSV string | `GET,POST,PUT,PATCH,DELETE,OPTIONS` | Methods advertised on preflight (`Access-Control-Allow-Methods`). |
| `CORS_ALLOW_HEADERS` | CSV string | `Content-Type,Authorization,X-AG-Trace-Id` | Headers advertised on preflight when the request does not echo its own `Access-Control-Request-Headers`. |
| `CORS_EXPOSE_HEADERS` | CSV string | `X-AG-Trace-Id` | Headers exposed on actual responses (`Access-Control-Expose-Headers`). |
| `CORS_ALLOW_CREDENTIALS` | boolean (`true`/`false`) | `false` | When `true`, the response echoes the request origin with `Access-Control-Allow-Credentials: true` instead of `*`. |
| `CORS_MAX_AGE` | string (seconds) | `600` | Preflight cache lifetime (`Access-Control-Max-Age`). Parsed as a plain string; e.g. `3600`. |

`.env.example` block:

```bash
# CORS Configuration (applied to both admin and proxy servers)
CORS_ALLOW_ORIGINS=*
CORS_ALLOW_METHODS=GET,POST,PUT,PATCH,DELETE,OPTIONS
CORS_ALLOW_HEADERS=Content-Type,Authorization,X-AG-Trace-Id
CORS_EXPOSE_HEADERS=X-AG-Trace-Id
CORS_ALLOW_CREDENTIALS=false
CORS_MAX_AGE=600
```

Restrictive example (browser app + credentialed requests):

```bash
CORS_ALLOW_ORIGINS=https://app.example.com,https://admin.example.com
CORS_ALLOW_METHODS=GET,POST,OPTIONS
CORS_ALLOW_HEADERS=Content-Type,Authorization
CORS_EXPOSE_HEADERS=X-AG-Trace-Id
CORS_ALLOW_CREDENTIALS=true
CORS_MAX_AGE=3600
```

There is no policy `settings` JSON for CORS. For reference, the equivalent
JSON shape of the server config is:

```json
{
  "allow_origins": ["https://app.example.com"],
  "allow_methods": ["GET", "POST", "OPTIONS"],
  "allow_headers": ["Content-Type", "Authorization"],
  "expose_headers": ["X-AG-Trace-Id"],
  "allow_credentials": true,
  "max_age": "3600"
}
```

Apply with `make up` by exporting the variables (or editing `.env`) before
booting the admin/proxy planes.

## Behavior

- Requests without an `Origin` header pass through untouched.
- Origins not in the allowlist pass through without CORS headers
  (fail-closed for cross-origin access, open for same-origin/non-browser
  traffic).
- Allowed origins always get `Vary: Origin`. With
  `allow_credentials: true` the response echoes the request origin plus
  `Access-Control-Allow-Credentials: true`; with `*` in the allowlist (and
  no credentials) it returns `Access-Control-Allow-Origin: *`; otherwise it
  echoes the matched origin.
- Preflight (`OPTIONS` + `Access-Control-Request-Method`) returns `204`
  with `Allow-Methods`, `Allow-Headers` (echoes the request's
  `Access-Control-Request-Headers` when present), and `Max-Age`.
- Do not use `CORS_ALLOW_ORIGINS=*` together with
  `CORS_ALLOW_CREDENTIALS=true` in production; browsers reject
  wildcard + credentials. List explicit origins instead.
