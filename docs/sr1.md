# Frozen cold-point smart routing

Smart routing has one policy. Its default keeps the conversation's committed
model while warm (`K=0`). The optional escape hatch permits one one-rung upgrade
on a harder distinct new user turn (`K=1`). Both settings use the same frozen
scorer and fixed ladder cuts. The internal `sr1` envelope remains for API
compatibility:

```json
{
  "enabled": true,
  "algorithm": "smart-routing",
  "members": [
    {"registry_id": "<budget registry UUID>", "model": "<budget model>"},
    {"registry_id": "<balanced registry UUID>", "model": "<balanced model>"},
    {"registry_id": "<strong registry UUID>", "model": "<strong model>"}
  ],
  "smart_routing": {
    "sr1": {"cache_ttl_seconds": 300, "escape_hatch_enabled": false},
    "tiers": [
      {"min_score": 0, "registry_id": "<budget registry UUID>", "model": "<budget model>"},
      {"min_score": 0.187, "registry_id": "<balanced registry UUID>", "model": "<balanced model>"},
      {"min_score": 0.45, "registry_id": "<strong registry UUID>", "model": "<strong model>"}
    ]
  }
}
```

Each tier must match a member with the same registry and model. The Admin API
response retains `smart_routing.sr1` with an explicit `escape_hatch_enabled`
boolean. New API writes default an omitted flag to false; a null flag is invalid.

For two models use cuts `0` and `0.45`. For three use `0`, `0.187` and `0.45`.
Models must be concrete, with distinct registry/model pairs. The owner supplies
increasing capability order. The four frozen difficulty bands (`0.187`,
`0.3037`, `0.45`) map to rungs `[0,0,0,1]` or `[0,1,1,2]`. Cut equality enters
the higher band.

## Historical configurations

A supported two/three-model configuration without an `sr1` envelope migrates
to these fixed cuts, preserving its sorted route order and setting the hatch
to false with a 300-second lifetime. A historical explicit `sr1` envelope with
an omitted flag retains its previously enabled hatch as a read compatibility
rule. Valid stored lifetimes remain unchanged. New saves serialize the setting
explicitly.

A missing historical model pin resolves only from an unambiguous declared pool
member, a compatible explicit consumer default, or a singleton concrete member
model list. The gateway never guesses the first model of a larger list.
Unsupported sizes, ambiguous models and invalid configurations retain all
stored targets for inspection; configuration writes reject them, and routing
fails with policy exhaustion. Raw invalid historical configurations remain
serializable so they cannot block unrelated consumers or config-sync snapshots.
The previous per-request routing strategy is no longer a serving option.

## Conversation state

Configure session extraction and send a stable `X-Session-Id` for the whole
conversation. Without a reusable session ID each request is a cold decision.
Redis state is scoped by gateway, consumer, session and ladder configuration,
including the hatch setting; no message text is stored. Changing the ladder or
hatch starts a fresh lifetime. The console manages new lifetimes automatically;
operators can retain a valid provider-specific lifetime of 1–86400 seconds.

At a cold point, select the desired rung and reset the escape budget. While
warm, retain the commitment. With the hatch disabled, warm requests atomically
reuse and touch state without invoking the scorer. With the hatch enabled,
score only a distinct eligible new user turn while an escape is still possible.
One higher desired rung permits one one-rung increase per lifetime. Tool
continuations, identical-turn retries, spent budgets and strongest commitments
reuse state. The committed floor never decreases while warm.

The lifetime resets after a strictly greater-than-TTL idle gap. Redis server
time and atomic Lua updates enforce the budget across replicas. Turn identity
uses the latest user message's position/text and Responses
`previous_response_id`; clients sending only standalone strings cannot
distinguish a retry from a new identical prompt. Send conversation history for
that distinction.

The scorer consumes latest user text only, including OpenAI/Responses and
Anthropic text blocks. Tool-only Anthropic envelopes and Responses function-call
outputs are continuations. A trailing assistant text prefill keeps the latest
user turn eligible for an enabled escape. A cold continuation lacking user
history uses the strongest rung.

## Failures and bounds

Scoring requires raw scores from revision
`9619f81d9db28141fc1cc0a3833c8446260ce603`. The routing client never sends a
Firewall conversation ID or consumes a session-modulated score. Missing
provenance, invalid cold input, scorer failures and Redis failures use the
strongest configured available rung. When state remains readable, failures
respect its committed floor and cannot spend a quality escape.

Backend health and exclusions apply before route selection. Serve the first
available declared rung at or above the policy commitment. Operational health
or failure fallback can temporarily serve a higher model without changing that
commitment; recovery may return to the original committed model. This exception
does not lower the stored policy floor or consume the optional escape budget.
If Redis is unavailable, the prior floor cannot be recovered.

With no route satisfying the bound, routing returns a policy exhaustion error.
Legacy fallback chains cannot bypass the ladder, including during upstream
failover, even for historical configurations without an explicit `sr1` envelope.
Registry deletion retains smart routing only when the surviving fixed ladder
still validates; otherwise the surviving pool uses round robin. Reconfigure
its ladder explicitly.

This routes demand and does not verify answers or guarantee output quality.
Deploy the compatible gateway and frozen scorer together. The HF production
tag and Firewall image must be updated separately; existing images do not
reload mutable tags. Rollback requires the prior image digests and their
matching complete consumer configurations. Removing `sr1` now selects the
sole policy with the hatch off; it does not restore the retired per-request
router. Preserve the previous HF production content commit.
