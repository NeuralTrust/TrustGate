# Original request metadata sent to TrustGuard

TrustGate captures request metadata at the HTTP handler boundary for both LLM proxy and
native MCP requests. All evaluate calls for that request, including response inspection,
carry the same `original_request` snapshot:

```json
{"original_request":{"ip":"203.0.113.42","headers":{"User-Agent":["client/1.0"],"Content-Type":["application/json"]}}}
```

The IP is the connection peer observed by TrustGate. Unverified X-Forwarded-For values
cannot override it. The header allowlist is Accept, Content-Type, User-Agent and X-Request-Id.
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
