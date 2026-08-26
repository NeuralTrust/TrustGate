# Registry pricing and cost estimates

TrustGate prices each request in **USD per token**, the same unit stored in the
models.dev catalog (`llmcost.CustomPrice`). There is no monthly aggregator in
the gateway. Downstream rollups that sum `cost.total_usd` (or
`trustgate.cost.total_usd`) over a period are only as accurate as the rates
used on each event.

## Registry `pricing`

Configure contract rates on an LLM registry (admin API field `pricing`, also
nested on `llm_target` in snapshots):

```json
{
  "pricing": {
    "discount": 0.2,
    "overrides": {
      "gpt-4o": { "input": 0.0000015, "output": 0.000006 },
      "gpt-4o-mini*": { "input": 0.0000001, "output": 0.0000004 }
    }
  }
}
```

- `overrides`: absolute USD **per token**. Keys are exact slugs or `*` globs.
  The most specific match wins (`BestMatch`: exact > most literal characters).
- `discount`: optional fraction off the models.dev list price (`0.2` = 20% off).
  Applied only when no override matches that model.

`discount` is **not** a multiplier. A comment that used `0.8` for “20% off”
is the inverse of this contract.

## Precedence

For a given request, input/output rates resolve as:

1. LLM Budget `custom_pricing` on the policy (explicit per-policy overlay)
2. Registry absolute override (exact slug, then best glob)
3. Registry `discount` × models.dev catalog price
4. models.dev catalog as-is
5. Unpriced (no `cost` on the event; dollar budgets accrue zero)

The same function (`llmcost.Resolve`) is used for:

- per-request metrics `cost.prompt_usd` / `cost.completion_usd` / `cost.total_usd`
- LLM Budget dollar mode (and cost-cap evaluation)

Two registries can publish different rates for the same model slug. The
**served** registry (stamped on the request after routing) is the one that
applies.

## Monthly estimates

TrustGate does not compute a monthly invoice. To estimate period spend:

`sum(usage.tokens × resolved_per_token_rate)` over the window, which is the
same as summing `cost.total_usd` on telemetry events.

Those estimates match the customer invoice only when registry `pricing`
matches the contract (enterprise list discount and/or committed per-model
rates). List prices from models.dev diverge from reserved/committed deals.

## Cache tokens

Prompt tokens served from, or written to, a provider's cache bill at their own
rate. The catalog carries `cache_read_price` and `cache_write_price` alongside
the input and output rates, synced from models.dev, and a registry
`pricing.overrides` entry may set `cache_read` / `cache_write` to a negotiated
rate.

```
prompt_usd = (prompt - cached - cache_written) * input
           + cached        * cache_read
           + cache_written * cache_write
```

`InputTokens` is the **whole prompt**, and the cache counts are subsets of it.
Providers that report their cache counts beside the prompt rather than inside it
— Anthropic does, where `input_tokens` is only the uncached remainder — are
normalised by their adapter, so this one expression is correct everywhere.

**An unset cache rate bills at the plain input rate**, which is what the gateway
charged for those tokens before cache rates existed. That applies to a model
models.dev publishes no cache rate for, and to a registry override that names
only `input` and `output`. Reading unset as zero would silently make most of a
cached prompt free, which is the worse way to be wrong. An explicit
`"cache_read": 0` is honoured as a real "free under my contract".

Rates differ sharply by provider, so they are never derived from a ratio: on
current list prices Anthropic reads at 0.1x input, OpenAI's `gpt-4o` at 0.5x,
`gpt-5` at 0.1x, xAI Grok at 0.25x.

Anthropic's one-hour cache TTL bills above its five-minute default, and no
catalog publishes a rate for it. The one-hour share is reported separately on the
usage view and priced from `cache_write_1h` when an override sets it, falling
back to the five-minute rate otherwise. Set it explicitly on any registry whose
traffic uses the long TTL — without it those writes are under-billed, and the
multiplier is deliberately not inferred, because it is an Anthropic fact rather
than a universal one.

Streaming providers report usage in pieces: Anthropic sends the prompt and both
cache buckets on the first event and the completion on the last. Usage is merged
field-wise across events, keeping the larger of each count, so an event that
omits a field cannot erase it.

If the sub-counts ever exceed the prompt they claim to be part of — which is what
a provider silently changing its wire shape looks like — the whole prompt is
billed at the plain input rate and a warning is logged. That is the safe
direction for money, and it is no longer silent.

## Smart-routing savings

When a consumer's pool uses the `smart-routing` algorithm and the tier table
chose the route, the event's `cost` object also carries `savings_usd`: the same
token counts repriced at the **highest configured tier**, minus the actual cost.
It lives inside `cost` rather than in a block of its own, so the counterfactual
total is `cost.total_usd + cost.savings_usd`.

The full emission rules — when the field is absent rather than zero, and why —
live in [the OTLP metadata contract](./telemetry/otlp-metadata-contract.md#savings-semantics).
What matters for pricing:

- The baseline resolves through the same `llmcost.Resolve` ladder as the actual
  cost, but with the **baseline tier's own registry** overlay, which is not
  necessarily the served registry's — a tier can point anywhere in the pool.
- `discount` applies only to catalog-resolved prices, while explicit `overrides`
  return before it. If one leg is priced by an override and the other by a
  discounted catalog rate, the two follow different rules.
- "Highest tier" means the greatest `min_score`, not the highest price. Nothing
  validates that the top tier is the most expensive model, so a ladder that puts
  a premium model at a low threshold produces a negative `savings_usd`. That is
  left unclamped: it surfaces the misconfiguration instead of hiding it.
- Cached-input and reasoning-output tokens are priced at the plain rate on both
  legs, because no separate rate exists for them anywhere in the model.

It is a modelled counterfactual, not a measurement: it assumes the premium model
would have consumed the same tokens. It will not reconcile against a provider
invoice, and it does not cover cost-cap model downgrades, which are a different
mechanism.
