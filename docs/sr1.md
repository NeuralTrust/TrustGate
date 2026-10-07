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

The registered `20261007120000_canonicalize_smart_routing` database migration
preflights every stored smart configuration, including disabled pools, inside a
transaction. Supported historical two/three-model ladders without an `sr1`
envelope receive fixed cuts by threshold rank; JSON array order, route targets
and unrelated metadata are preserved. Their hatch defaults to false and their
lifetime to 300 seconds. An existing explicit envelope with an omitted hatch
flag retains its historical true setting only during this migration. Valid
stored lifetimes remain unchanged.

A missing historical model pin resolves only from one unambiguous declared
member, a compatible explicit consumer default, or a singleton concrete member
model list. The migration rejects unsupported sizes, ambiguous models, invalid
explicit cuts and unresolved registry references before writing any consumer.
Owners must repair those configurations before rollout. The migration backs up
original and canonical JSON plus update timestamps. Its transactional rollback
refuses to overwrite later edits or deletions.

Reading, validating and serializing configurations never migrate them. Disabled
stored pools permit unrelated consumer edits without rewriting routing. Explicit API routing edits must be canonical even when disabled, including
changes to model policies, registry associations and fallback references. The previous
per-request smart router is no longer a serving option.

## Conversation state

Configure session extraction and send a stable `X-Session-Id` for the whole
conversation. Without a reusable session ID each request is a cold decision.
Redis state is scoped by gateway, consumer, session and ladder configuration,
including the hatch setting; no message text is stored. Changing the ladder or
hatch starts a fresh lifetime. The console manages new lifetimes automatically;
operators can retain a valid provider-specific lifetime of 1–86400 seconds.
Each distinct client-supplied session ID can create another Redis key. TTL bounds
retention, not key creation rate or cardinality. Require authenticated consumers
and configure the gateway's rate and plan limits; reuse IDs per conversation and
size/monitor Redis for the permitted request rate and lifetime.

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

The scorer consumes latest user text only from OpenAI/Responses, Anthropic,
Bedrock Converse text blocks and Gemini `contents`/`parts`. Tool-only Anthropic envelopes and Responses function-call
outputs are continuations. A trailing assistant text prefill keeps the latest
user turn eligible for an enabled escape. A cold continuation lacking user
history, image-only input or otherwise unreadable user text uses the strongest
available rung for that request and creates no commitment.

## Failures and bounds

Scoring requires raw scores matching `FIREWALL_COMPLEXITY_MODEL_REVISION`,
which defaults to the frozen revision
`9619f81d9db28141fc1cc0a3833c8446260ce603`. The routing client never sends a
Firewall conversation ID or consumes a session-modulated score. Missing
provenance, invalid cold input, scorer failures and Redis failures use the
strongest configured available rung. When state remains readable, failures
respect its committed floor and cannot spend a quality escape. A failed cold
request does not create or reset a commitment: the next healthy request scores
again. Fallback reads do not extend the lifetime; a warm request's normal probe
still refreshes its idle clock. Fallback retains the greater of the probed floor
and a fresh readable floor, including a commitment made by another replica.

Backend health and exclusions apply before route selection. Serve the first
available declared rung at or above the policy commitment. Operational health
or failure fallback can temporarily serve a higher model without changing that
commitment; recovery may return to the original committed model. This exception
does not lower the stored policy floor or consume the optional escape budget.
A passive-unhealthy backend becomes eligible for another attempt after its
configured health-check interval (30 seconds for historical missing settings),
so it can recover before the one-hour health record expires. A fresh failure
restarts cooldown; successful traffic restores healthy status. Explicit
request exclusions still apply. If Redis is unavailable, a floor already read
for this request is retained; an unreadable prior floor cannot be recovered.

With no route satisfying the bound, routing returns a policy exhaustion error.
Legacy fallback chains cannot bypass the ladder, including during upstream
failover, even for historical configurations without an explicit `sr1` envelope.
Registry deletion retains smart routing only when the surviving fixed ladder
still validates; otherwise the surviving pool uses round robin. Reconfigure
its ladder explicitly.

These availability bounds are deliberate: a declared stronger route may absorb
failure, but an undeclared backup or weaker rung cannot. When the strongest
commitment has no eligible provider, return policy exhaustion rather than change
its floor. Choose resilient providers within the declared ladder.

This routes demand and does not verify answers or guarantee output quality.
Deploy the compatible scorer first, then the gateway migration and runtime, then
the console. Roll out the admin plane first and verify its compiled snapshots
contain canonical configurations before new proxies accept traffic; older admin
replicas can retain snapshots until their next recompile. Development Firewall already serves the frozen revision; no HF
`production` ref change is needed for this development rollout. Production
promotion remains separate. Preserve matching prior image digests and the
migration backup for rollback. Removing `sr1` cannot restore the retired router;
new API writes without a canonical session configuration are rejected.
