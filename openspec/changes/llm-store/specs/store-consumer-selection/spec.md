# Delta for store-consumer-selection

Change `llm-store` (RUN-1763), slice S5 (decisions B7, D13). New capability. A personal key is linked to N ≥ 0 personal consumers, each link carrying `level` (`user` / `group` / `all`), `priority` and `granted_at` (`owned-key-attachment`). For every `/store/v1/*` request other than the model listing, `appproxy.StoreSelector` picks exactly one of them, or none. It reuses the existing routing resolver per consumer (`approuting.Resolver.Resolve`) and the catalog listing check, so every intent kind of `pkg/domain/routing/intent.go` is handled the way a consumer's own route handles it. Nothing here applies to `/<slug>/v1/*`.

## ADDED Requirements

### Requirement: User-level links substitute group and all links per provider

Let `S` be the set of providers (`Registry.Provider()`, lower-cased) of the primary registries of every `user`-level linked consumer of the key. For a `group`- or `all`-level link, every registry, primary or fallback, whose provider is in `S` MUST be ignored for this request. A `group`/`all` link with no primary registry left MUST NOT take part in selection or in the model listing. `user`-level links MUST NOT be filtered. Fallback backends of `user`-level consumers MUST NOT add providers to `S`.

#### Scenario: User link narrows a provider

- GIVEN `ana`'s key linked to A (`group`, OpenAI, no allow-list) and D (`user`, OpenAI `["gpt6"]`)
- WHEN she requests `model: gpt-4.1`
- THEN 403 `model_not_allowed`, even though A alone would allow it

#### Scenario: Other providers of a group consumer survive

- GIVEN `ana`'s key linked to A (`group`, registries OpenAI and Mistral, no allow-lists) and D (`user`, OpenAI `["gpt6"]`), with a catalog listing `mistral-large` for Mistral and not for OpenAI
- WHEN she requests `model: mistral-large`
- THEN A serves it, and the forward set holds A's Mistral registry and not its OpenAI registry

#### Scenario: Substituted fallback is not used

- GIVEN A (`group`, Mistral, fallback OpenAI) and D (`user`, OpenAI `["gpt6"]`), and A selected for `mistral-large`
- WHEN the Mistral upstream fails
- THEN the request is not retried on A's OpenAI fallback

### Requirement: A consumer admits a request only through its primary registries

For each effective link the selector MUST run, in order: `Resolve(intent, consumer)`, the substitution filter, the capability filter of the route (embeddings, rerank, files, images, audio) and the files-id filter, as the forwarder does. A resolver error MUST mean the consumer does not admit the request. The consumer admits the request only when at least one remaining candidate is not fallback-only (`Candidate.FallbackOnly()`). A consumer's fallback backends MUST NOT make it admit a request; once it is selected they MUST stay available to that request as today.

#### Scenario: Fallback does not admit

- GIVEN `ana`'s key linked only to A (`group`, OpenAI, no allow-list, fallback DeepSeek), with a catalog listing `deepseek-chat` for DeepSeek only
- WHEN she requests `model: deepseek-chat`
- THEN 403 `model_not_allowed`

#### Scenario: Fallback serves the selected consumer

- GIVEN the same key and a catalog listing `gpt-4.1` for OpenAI
- WHEN she requests `model: gpt-4.1` and the OpenAI upstream fails
- THEN A is selected and the request falls back to DeepSeek as A's own route would

### Requirement: Short models use the catalog listing check with no keep-all fallback

For a short-model intent (including a bare `provider/model`, which is a native short model), a candidate without an allow-list MUST be dropped when the catalog listing for its provider answers `VerdictAbsent` for the model (`appcatalog.ModelListing.Lists`). Unlike `filterCandidatesByProviderListing` on the slug path, the store MUST NOT restore the dropped candidates when every candidate was dropped. `VerdictListed` and `VerdictUnknown` MUST keep the candidate. Qualified intents MUST NOT be checked against the listing, as today.

#### Scenario: Anthropic without allow-list does not capture gpt models

- GIVEN `ana`'s key linked only to B (`group`, Anthropic, no allow-list), with a catalog that lists Anthropic models and not `gpt-4.1`
- WHEN she requests `model: gpt-4.1`
- THEN 403 `model_not_allowed`

#### Scenario: Unknown listing keeps the candidate

- GIVEN the same key and no catalog listing for Anthropic
- WHEN she requests `model: gpt-4.1`
- THEN B is selected

### Requirement: Ordering

Among the effective links that admit the request, the selector MUST pick the minimum of, in this order: level rank (`user` < `group` < `all`), `priority` (lower first), match specificity, `granted_at` (older first), consumer id. Specificity applies to qualified and short-model intents and is the best over the consumer's admitting primary candidates: 0 when the model is a literal entry of the allow-list, 1 when it matches only a glob of the allow-list, 2 when the registry has no allow-list. For every other intent kind specificity MUST be equal for all links. When no link admits, the request MUST fail before any upstream call and before the gateway's plan rate limit is charged. When every evaluated link refused it for the same non-model reason (a capability no linked provider supports, no backend left), the error MUST be that reason, answered as on `/<slug>/v1` (400 for an unsupported capability, 503 for no backend); otherwise it MUST wrap `routingdomain.ErrModelDenied` (403 `model_not_allowed`).

#### Scenario: Specificity at equal level and priority

- GIVEN B (`group`, priority 1, Anthropic, no allow-list) and C (`group`, priority 1, Anthropic `["opus-5.5"]`), C granted after B, and a catalog listing `opus-5.5`
- WHEN `opus-5.5` is requested
- THEN C serves it

#### Scenario: Priority before specificity

- GIVEN B (`group`, priority 0, no allow-list) and C (`group`, priority 1, `["opus-5.5"]`) on Anthropic
- WHEN `opus-5.5` is requested
- THEN B serves it

#### Scenario: Glob before no allow-list

- GIVEN E (`all`, priority 1, OpenAI `["gpt-4*"]`) and F (`all`, priority 1, OpenAI, no allow-list), F granted first, and a catalog listing `gpt-4.1`
- WHEN `gpt-4.1` is requested
- THEN E serves it

#### Scenario: Oldest grant breaks a tie

- GIVEN G1 and G2, both `group`, priority 1, OpenAI `["gpt-4.1"]`, G2 granted before G1
- WHEN `gpt-4.1` is requested
- THEN G2 serves it

#### Scenario: Every link lacks the capability

- GIVEN `alice`'s only link is a user-level consumer on Anthropic, which serves no embeddings
- WHEN she calls `/store/v1/embeddings`
- THEN 400, the answer `/<slug>/v1/embeddings` gives on that consumer, not 403 `model_not_allowed`, and no plan rate-limit token is spent

### Requirement: Every intent kind

The selector MUST handle each intent kind as follows, with the admission and ordering rules above.

| Intent | Admits when |
|---|---|
| empty | a primary candidate has a default model (not needed on a capability route without a model); ordering by level, priority, age |
| `auto` | `Resolve` succeeds with a primary candidate (it already requires a default) |
| `pool:<alias>` | the consumer's LB pool alias equals the alias and a member survives substitution |
| `@provider/model` | `Resolve` succeeds with a primary candidate of that provider allowing the model |
| short model | `Resolve` succeeds and a primary candidate survives the listing check |

An invalid model reference MUST answer 400 `invalid_model` as today. A pool alias that no effective consumer defines MUST answer 400 `invalid_model`: every effective link refused it as an unknown alias. As soon as one effective link defines the alias with no surviving primary member, the answer MUST be 403, whatever the other links answered. A key with no effective link (N = 0) MUST answer 403 for every intent, pool aliases included: N = 0 takes precedence over the 400 for an unknown alias.

A request without a model on a capability route (embeddings, images, audio) MUST NOT need a default model. There the capability filter decides admission, and the empty-model row applies only to routes without a capability. The Files API is not a store route (`llm-store-gateway`), so no store request reaches the files-id filter.

#### Scenario: Pool alias

- GIVEN P1 (`group`) with an LB pool alias `fast` and P2 (`user`) without pools
- WHEN `model: pool:fast` is requested, and then `model: pool:slow`
- THEN P1 serves the first, and the second answers 400 `invalid_model`

#### Scenario: Auto

- GIVEN P1 (`group`, default `gpt-4o`) and P2 (`user`, default `gpt6`)
- WHEN `model: auto` is requested
- THEN P2 serves it

#### Scenario: Pool alias with no surviving member

- GIVEN D (`user`, OpenAI, no pools) and P (`group`, Mistral and OpenAI, LB pool alias `fast` whose only member is the OpenAI registry)
- WHEN `model: pool:fast` is requested
- THEN 403 `model_not_allowed`, not 400, because P defines the alias and D substitutes its only member

#### Scenario: Files route refused

- GIVEN D (`user`, OpenAI `["gpt6"]`) and B (`group`, Anthropic, no default)
- WHEN `GET /store/v1/files/file_011abc` is sent with the key
- THEN 404, byte-identical to `/store/v1/zz-unknown`, and no consumer is selected

#### Scenario: Qualified reference

- GIVEN B (`group`, Anthropic, no allow-list) and C (`group`, Anthropic `["opus-5.5"]`)
- WHEN `model: @anthropic/opus-5.5` is requested, and then `model: @openai/gpt-4o`
- THEN C serves the first, and the second answers 403 `model_not_allowed`

### Requirement: Personal consumers have a default model

The empty-model rule relies on every personal consumer having a concrete (non-glob) default model on at least one of its primary registries (`personal-llm-consumers`). With an empty model the selector MUST pick the first effective link, in level, priority and age order, that has a default on a primary registry surviving substitution.

#### Scenario: Empty model

- GIVEN `ana`'s key linked to A (`group`, default `gpt-4o`) and D (`user`, default `gpt6`)
- WHEN a request without `model` is sent
- THEN D serves it with `gpt6`

### Requirement: Worked example

The following MUST hold end to end on a DB-less and on a full-plane proxy. `ana`'s key is linked to A (`group`, priority 1, OpenAI without allow-list, fallback DeepSeek), B (`group`, priority 1, Anthropic without allow-list), C (`group`, priority 1, Anthropic `["opus-5.5"]`) and D (`user`, priority 1, OpenAI `["gpt6"]`, default `gpt6`), granted in that order. The catalog lists `gpt-4.1` and `gpt6` for OpenAI and `opus-5.5` and `opus-4.8` for Anthropic.

#### Scenario: gpt-4.1 is denied

- WHEN `ana` requests `model: gpt-4.1`
- THEN 403 `model_not_allowed`, because D substitutes OpenAI

#### Scenario: gpt6 goes to D

- WHEN `ana` requests `model: gpt6`
- THEN D serves it

#### Scenario: opus-5.5 goes to C

- WHEN `ana` requests `model: opus-5.5`
- THEN C serves it

#### Scenario: opus-4.8 goes to B

- WHEN `ana` requests `model: opus-4.8`
- THEN B serves it

#### Scenario: No model goes to D

- WHEN `ana` sends a request without `model`
- THEN D serves it with `gpt6`

### Requirement: Concurrency and cost

`StoreSelector` MUST hold no mutable state and MUST be safe for concurrent use. It MUST run at most one `Resolve` per effective link and MUST NOT call a repository, gRPC or Redis.

#### Scenario: Concurrent selection

- GIVEN one `Data` and one selector
- WHEN 64 goroutines select for different intents under `go test -race`
- THEN every result equals the sequential result and the race detector reports nothing
