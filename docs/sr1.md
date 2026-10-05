# Frozen SR-1 routing

Opt in on a consumer's load balancing configuration:

```json
{
  "algorithm": "smart-routing",
  "smart_routing": {
    "sr1": {"cache_ttl_seconds": 300},
    "tiers": [
      {"min_score": 0, "registry_id": "<cheap registry UUID>", "model": "<cheap model>"},
      {"min_score": 0.187, "registry_id": "<workhorse registry UUID>", "model": "<workhorse model>"},
      {"min_score": 0.45, "registry_id": "<strong registry UUID>", "model": "<strong model>"}
    ]
  }
}
```

For two rungs use thresholds `0` and `0.45`. Models must be explicitly named,
with distinct registry/model pairs. The owner supplies the order of capability.
The four frozen difficulty bands (`0.187`, `0.3037`, `0.45`) map to rungs
`[0,0,0,1]` or `[0,1,1,2]`. Cut equality enters the higher band.

Configure session extraction and send a stable `X-Session-Id` for the whole
conversation. Without a session ID each request is a cold decision. Redis state
is scoped by gateway, consumer, session and ladder configuration; no message
text is stored. A changed ladder creates a fresh lifetime. Set the TTL to the
provider cache lifetime used by this deployment (1–86400 seconds).

At a cold point, select the desired rung. While warm, stay committed. On a new
user turn, a higher desired rung permits **one one-rung increase** per lifetime
(`K=1`). Lower scores never reduce the committed rung while warm. The lifetime
resets after a strictly greater-than-TTL idle gap. Redis server time and an
atomic Lua update enforce the budget across replicas. Repeated requests and
tool continuations do not consume a further escape. Turn identity uses the
latest user message's position/text and Responses `previous_response_id`;
clients sending only standalone strings cannot distinguish a retry from a new
identical prompt. Send conversation history for that distinction.

The scorer consumes latest user text only, including OpenAI/Responses text
blocks and Anthropic text blocks. Tool-only Anthropic envelopes and Responses
function-call outputs are continuations. A continuation lacking user history
uses its existing warm commitment, or the strongest rung if cold.

SR-1 requires Firewall responses carrying raw scores from
`9619f81d9db28141fc1cc0a3833c8446260ce603`. Missing provenance, invalid input,
scorer failures and Redis failures use the strongest configured available rung.
The client omits Firewall's conversation ID to bypass legacy EWMA smoothing.
Backend health and request exclusions are applied before selecting a route;
a missing committed rung can lead upward, never downward. With no available
route at or above it, routing returns an error.

This is demand-based routing, not answer verification or a guarantee of quality.
Legacy `smart-routing` configurations without `sr1` keep their existing policy.
Merge and deploy the compatible code before enabling `sr1` on consumers. The
HF production tag must be changed separately and the Firewall image rebuilt;
existing images do not reload mutable tags.

Rollback: restore the prior consumer configuration (remove `sr1`), then restore
previous image digests. Preserve the previous HF production content commit.
