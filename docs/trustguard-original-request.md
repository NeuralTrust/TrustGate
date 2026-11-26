# Original request metadata sent to TrustGuard

TrustGate captures request metadata at the HTTP handler boundary for both LLM proxy and
native MCP requests. All evaluate calls for that request, including response inspection,
carry the same `original_request` snapshot:

```json
{"original_request":{"ip":"203.0.113.42","headers":{"User-Agent":["client/1.0"],"Content-Type":["application/json"]}}}
```

The IP defaults to the connection peer observed by TrustGate. Deployed GCP environments
use the trusted ingress resolution below. The header allowlist is Accept, Content-Type,
User-Agent and X-Request-Id.
Each header carries at most four values, each at most 512 bytes, with no CR/LF.
Credentials and arbitrary custom headers are excluded before the internal call. The
snapshot survives later plugin mutations and does not depend on telemetry being enabled.
End-user identity continues to use `attributes.user`, separate from `consumer_id`.
Streaming response inspection retains this context after the HTTP request finishes, with
its own bounded timeout.

TrustGuard accepts this field only for authenticated platform callers. It uses the original
metadata for `trustguard.ip` and `trustguard.request.headers`; direct/legacy callers retain
their evaluate connection metadata. Deploy the compatible TrustGuard version first because
older strict evaluate decoders reject unknown fields.

## The end user's ID token

An application that calls TrustGate with its own API key can have its user verified by
TrustGuard by sending the user's ID token in the `X-NeuralTrust-User-Token` request
header. The TrustGuard v2 plugin forwards it as `assets.user.token`, and TrustGuard
verifies it against the `settings.identity_provider` of the integration, taking the user
from the token's claims. Without an identity provider on the integration the token is not
verified.

- `Authorization` is not used: it carries the application's own credential.
- Only the v2 plugin (`trustguard_v2`) reads and forwards the header, on LLM and MCP
  requests; the v1 plugin ignores it and its wire never carries it. An integration that
  sets `require_user_token` therefore needs the v2 plugin.
- A token with no authenticated principal still sends `assets.user` with just the token.
- Each stream segment re-verifies the token: one that expires mid-stream cuts the stream
  with a 403.
- It is not part of `original_request.headers` (the allowlist above), is never relayed to
  the model provider or MCP server (a registry cannot list it in `forward_client_headers`),
  and is redacted in telemetry headers.
- If the header carries more than one distinct value (several lines or casings) it is
  ignored as a whole.
- The header is client-controlled, so TrustGuard refusing it is a block, not a failure of
  the guard: `user_token_not_configured`, `invalid_user_token`, `user_mismatch`,
  `asset_conflict` and `user_token_required` (classified by TrustGuard's error `code`, never by the status alone; a codeless 403 is
  the gateway's own credential being refused and follows `failure_mode`) answer 403 `trustguard_user_token_rejected` whatever the `failure_mode`, and the
  gateway's own service token is not refetched. `user_token_unavailable` (503) stays an
  availability failure and follows `failure_mode`.
- The declared `X-NeuralTrust-End-User` header is unchanged: it never reaches TrustGuard's
  gate attributes.

## Trusted GCP ingress

`ORIGINAL_REQUEST_IP_MODE=peer` is the default and ignores forwarding headers.
`ORIGINAL_REQUEST_IP_MODE=gcp` requires explicit `ORIGINAL_REQUEST_TRUSTED_PROXY_CIDRS`.
The resolver reads the raw socket peer, even if Fiber has a separate proxy-header setting.
It accepts `X-Forwarded-For` only when that peer belongs to a configured proxy range.
For a direct GCP Application Load Balancer backend, Google appends the client IP and
forwarding-rule IP as the final two entries. Both must parse as valid IP addresses;
the resolver takes the penultimate entry and ignores all caller-supplied entries to its left.
Missing, malformed or oversized chains fall back to the socket peer. No forwarding header
is included in the exported metadata.

The deployment overlays configure:

| Environment | Trusted socket peer ranges | Ingress |
| --- | --- | --- |
| dev | `10.129.0.0/23` | Regional external/internal managed proxy |
| prod, prod-us | `10.129.0.0/23`, `130.211.0.0/22`, `35.191.0.0/16` | Regional internal proxy and global external GFE |

These ranges come from `cloud-infrastructure/gcp/{dev,prod,prod-us}.tfvars` and
`gcp/network.tf` (`REGIONAL_MANAGED_PROXY`), plus the GFE ranges for zonal NEG backends.
`core-infrastructure/gateway` selects a regional external Gateway in dev and a global
external Gateway in prod/prod-us; `gateway-internal` uses regional internal Gateways.
The mode assumes a direct load-balancer-to-TrustGate connection. An additional reverse
proxy or a load-balancer rule that rewrites the header requires updating this contract.

References: [Google X-Forwarded-For contract](https://docs.cloud.google.com/load-balancing/docs/https#x-forwarded-for_header),
[Google backend source ranges](https://docs.cloud.google.com/load-balancing/docs/https#firewall_rules),
[Internal Application Load Balancer headers](https://docs.cloud.google.com/load-balancing/docs/l7-internal#target-proxies).

## Full service regression

`TestSIEMRealTrustGuard` in `tests/functional` starts the real TrustGate admin, proxy and
MCP processes and provisions a collector/detector/policy through a running TrustGuard's
control API. It checks an allowed request and an actual code-injection block. The test
is opt-in through `FUNCTIONAL_TRUSTGUARD_BASE_URL`, `FUNCTIONAL_TRUSTGUARD_CONTROL_URL`,
`FUNCTIONAL_TRUSTGUARD_ADMIN_TOKEN`, `FUNCTIONAL_TRUSTGUARD_CLIENT_ID` and
`FUNCTIONAL_TRUSTGUARD_CLIENT_SECRET`. Configure TrustGuard's metadata OTLP exporter to
the collector under test on both services; the test prints the collector and request identifiers to verify
persisted records and drive downstream alert evaluation. Set `FUNCTIONAL_CLICKHOUSE_URL`,
`FUNCTIONAL_CLICKHOUSE_USER` and `FUNCTIONAL_CLICKHOUSE_PASSWORD` to assert persisted rows
in both materialized tables (including Gate IP migration 0241).
`FUNCTIONAL_SIEM_TENANT_ID` must match the Guard admin token tenant; the fixture uses a
shared session across both services and verifies RSA-authenticated user ID/email.

The Gate harness requires `DB_NAME` to match the explicitly disposable `FUNCTIONAL_DB_NAME`
(default `trustgate_functional`), uses the configured Postgres and Redis endpoints, and
refuses occupied server ports. `FUNCTIONAL_SERVER_BINARY` can reuse an explicitly built executable. `FUNCTIONAL_CONFIG_SYNC_GRPC_PORT` overrides its gRPC port.
For a local simulated GCP hop, explicitly trust only loopback CIDRs and send the appended
client/forwarding-rule pair; deployed overlays retain their actual ingress proxy ranges.

Both producers export security labels as a JSON-string attribute (`trustgate.security` /
`trustguard.security`). Native OTLP string arrays are flattened by the production collector,
so they cannot populate the exact ClickHouse attribute key consumed by the materialized views.
TrustGate telemetry uses the same trusted-ingress IP resolver as the original request snapshot.
