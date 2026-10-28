# Proposal: Group-scoped personal keys for cost attribution (ENG-2610)

Linear: [ENG-2610](https://linear.app/neuraltrust/issue/ENG-2610/group-scoped-personal-api-keys-for-cost-attribution). Repos: TrustGate (Go, this change), DataCore (cost reports per group and member) and the console (who may hold which key, the Portal). Base `develop` @ `e8cbaba5`. Builds on [`llm-store`](../llm-store/proposal.md): personal keys, personal consumers, links and `partition: key` budgets are unchanged unless this file says so. `design.md` and `specs/` follow this file.

## Intent

A person who belongs to several directory groups spends on models for each of them, and the console must report and cap that spend per group. Today a user holds one personal key per gateway, so every request they make is theirs alone and nobody can tell which group's work it was. This change lets the console issue a **group key**: a personal key held for one of the owner's directory groups. Spend through it is attributed to the group, held to the group's monthly budget, and its MCP Store reach is the group's. The console stays the authority on who may hold a key for which group; TrustGate stores the group and enforces what it implies.

## Binding design

| # | Rule |
|---|---|
| G1 | `auths` gains nullable `group_id` (the console's `DirectoryGroup.id`, fixed for the key's life) and `group_name` (its directory name, the string in `owner_groups` and in Store grants; required with `group_id`, renamable, trimmed, ≤ 256). A personal key with a group is a **group key**; one without is the **personal key**. |
| G2 | At most one key per (gateway, owner, group) and one personal key per (gateway, owner): the partial unique index `auths_gateway_owner_uniq (gateway_id, owner_id)` becomes `auths_gateway_owner_group_uniq (gateway_id, owner_id, COALESCE(group_id, '')) WHERE owner_id IS NOT NULL`. A violation keeps answering 409. |
| G3 | A personal key's `expires_at` is optional (none = never expires); when set it is in (now, now + 366 days]. Rotation keeps the expiry unless told otherwise (`expires_at`, or `never_expires: true`); an expired key needs one of them. The MCP Store's personal key page keeps issuing 90-day personal keys. |
| G4 | Group keys are issued only by the admin route (the console calls it after its own checks). The owner lists, rotates and revokes every key of theirs through new self routes; the existing `…/llm-key` routes keep acting on the personal key alone. |
| G5 | Model reach is unchanged: a key reaches the personal consumers it is linked to. The console links a group key only to its group's consumer. |
| G6 | On the MCP Store a group key is its group: Store mode and grants are evaluated for `group_name` only (no subject, no other group); MCP policies scoped to groups still see every group of the owner. Installs and connected accounts stay the owner's. |
| G7 | LLM events carry `trustgate.auth.kind` (`personal` / `application`) and, for a group key, `trustgate.auth.group_id`. |
| G8 | A group budget per (gateway, group): the group's monthly total, a per-member default and per-member overrides, in USD over the UTC calendar month, with action `alert` or `block`. Enforced on `/store/v1` for group keys on every proxy plane; the first limit reached applies. The first time a counter reaches its limit in a month the proxy tells the console (`key_group_budget_reached`), at most once per (gateway, group, scope, member, month). |

## Scope

| Slice | What ships | Commit |
|---|---|---|
| **K1** Group on the auth | Migration `20261022120000_add_auth_key_group`, domain `KeyGroup`, repository `FindByOwnerAndGroup` / `ListByOwner`, snapshot read model by (gateway, owner, group), DTOs, `trustgate_store_models` answers for the key used. | `8f24515d` |
| **K2** Expiry | Optional expiry, 366 days, `never_expires` on rotate, 90-day page unchanged. | `8a050196` |
| **K3** Routes | Admin create with a group, `GET /auths?owner_id=` lists every key, `PUT /auths/{id}/groups` renames a group, self `GET …/llm-keys`, `POST …/llm-keys/{auth_id}/rotate`, `DELETE …/llm-keys/{auth_id}`. | `54a10a8b` |
| **K4** MCP reach | `key_group` claim on a personal key's principal, `Principal.StoreSubject` / `StoreGroups`, read by the Store's mode, scoper, installer and tools. | `190b9fea` |
| **K5** Telemetry | `auth_kind`, `auth_group_id` on events and OTLP; `group_id` on personal key events. | `dcb58021` |
| **K6a** Budgets: storage | `key_group_budgets`, admin routes, snapshot `key_group_budgets`, budgets loaded with the gateway's data. | `33d5a54d` |
| **K6b** Budgets: enforcement | `key_group_budget` stage on the token_rate_limiter's counters and pricing, joined to a group key's store requests; `key_group_budget_reached` console event. | `d74e4e85` |
| **K7** Docs | Swagger / OpenAPI, `docs/llm-store.md`, this change. | — |

### Data model

| Table | Change | Wire form (snapshot) |
|---|---|---|
| `auths` | `group_id text NULL`, `group_name text NULL`; index swap (G2). | `group_id`, `group_name` in the auth JSON, `omitempty`: other keys encode as before. |
| `key_group_budgets` (new) | `gateway_id uuid` (FK `gateways` ON DELETE CASCADE), `group_id text`, `monthly_limit_usd double precision NULL`, `member_monthly_limit_usd double precision NULL`, `member_overrides jsonb NULL`, `action text CHECK (action IN ('alert','block'))`, `created_at`, `updated_at`; PK `(gateway_id, group_id)`. | `repeated KeyGroupBudget key_group_budgets = 16` (`bytes json = 1`). Absent when a gateway has none. |

## Decisions

| # | Topic | Decision | Rejected (why) |
|---|---|---|---|
| D1 | Uniqueness | One index over `COALESCE(group_id, '')`, so the personal key and each group key are each unique per owner. | Two partial indexes: twice the conflict mapping for the same rule. |
| D2 | Personal-key routes | `…/llm-key` (GET / POST / rotate / DELETE) and the `PersonalKeys` gRPC service act on the key with no group. | Making them group-aware: breaks the Portal and the Store page, which only know one key. |
| D3 | Self routes by id | `…/llm-keys/{auth_id}` act only on a key of the caller on the gateway; any other answers 404, as an unknown id. | 403 for another user's key: tells the caller the id exists. |
| D4 | MCP identity | A gateway-built `key_group` claim, honoured only on `MethodPersonalKey`, so no token can claim it. `StoreSubject()` is empty and `StoreGroups()` is `[group_name]` for a group key. | Rewriting the subject: installs and vault accounts would split per group. |
| D5 | MCP policies | Keep evaluating group-scoped MCP policies with every group of the owner (plus the key's group). | Only the key's group: a narrower reach would skip a policy meant for the owner. |
| D6 | Budget enforcement | A stage outside the plugin registry (`key_group_budget`), compiled once into a one-entry inert plan and unioned into the selected consumer's plan for a request that carries a budget, at priority -1 (ahead of every admin policy). It reuses the token_rate_limiter's counters, pricing, usage decoders, Redis-failure and unpriced semantics. | A registered plugin: an admin could attach it as a policy. A new middleware: would miss post-response and streaming accrual. |
| D7 | Counters | Micro-USD on `kgb:<gw>:<group>:p:<YYYY-MM>` and `kgb:<gw>:<group>:owner:<owner>:p:<YYYY-MM>`, expiring at month end; a request is charged to the month that admitted it. | Per-policy `trl:` keys: a budget is not a policy and has no id. |
| D8 | Action → mode | `block` behaves as a `partition: key` budget in enforce (429 / 503 / 403), `alert` as one in observe (records, never refuses). | Separate semantics: two failure models for the same counters. |
| D9 | Notification | Redis `SETNX kgb:notified:<gw>:<group>:<scope>:<member>:<period>` (TTL month end + 24 h) before one background POST (10 s) to `CONSOLE_EVENTS_URL`, signed as the personal key events. | Notify from the control plane: it does not see the counters. Retrying: needs a queue for a best-effort notice the console can reconcile from DataCore. |
| D10 | Distribution | Budgets ride consumer `Data` (Postgres or snapshot), invalidated by `InvalidateGatewayDataEvent` and snapshot recompiles, as keys are. | A Redis or DB read per request. |
| D11 | Budget writes | Gateway access on `auths`; PUT and DELETE need an interactive identity (403 for a service credential), GET does not. | Consumers resource: a budget holds keys, not consumers. |

## Error codes (new or changed)

| Surface | Condition | Status |
|---|---|---|
| `POST …/store/users/{user_id}/llm-key` | key for the group (or personal key) exists / `group_id` without `group_name` or the reverse, bad expiry, hybrid | 409 `already_exists` / 422 |
| `POST …/llm-key`, `POST …/llm-key/rotate`, `POST …/llm-keys/{auth_id}/rotate` | expiry outside (now, now + 366 d]; `expires_at` with `never_expires`; expired key rotated with neither | 422 `validation_failed` |
| `…/llm-keys/{auth_id}` | not the caller's key on the gateway | 404 `not_found` |
| `PUT /auths/{id}/groups` | `group_name` for a key with no group | 422 `personal_key` |
| `PUT …/key-groups/{group_id}/budget` | no limit, negative or non-finite limit, bad action / service credential | 422 `validation_failed` / 403 |
| `DELETE …/key-groups/{group_id}/budget` | no budget | 404 `not_found` |
| `/store/v1/*`, group key, `block` | a limit reached / counters unreadable / unpriced model | 429 `budget_exceeded` / 503 `budget_unavailable` / 403 `model_unpriced` |

## Deviations from the cross-repo contract

| Contract | Implemented |
|---|---|
| Budget writes "console JWT, gateway access on auths/consumers as appropriate" | Gateway access on `auths`; service credentials may list and never write (D11). |
| Budget entity | Answers also carry `created_at` and `updated_at`; `member_overrides` is `{}` when empty, an unset limit `null`. |
| 429 `budget_exceeded` | Body `{"error": {"type", "code", "message", "scope", "group_id", "window", "limit_usd", "spent_usd", "resets_at"}}` with the dollar budget headers. Also 503 `budget_unavailable` and 403 `model_unpriced` under `block`, from the token_rate_limiter's rules (D8). |
| Telemetry "on LLM events from /store/v1" | Also on the consumer routes, where an application key gets `application`. MCP records carry no auth id and so neither attribute. |
| Admin create 422 "when group_id is set without group_name" | Also `group_name` without `group_id`. |

## Out of scope

- Eligibility (who may hold a key for which group), the reconcile that links a group key to its group's consumer and revokes it, the Portal: console.
- Reporting per group and member: DataCore, from `trustgate.auth.group_id` and the principal subject.
- Budgets on personal keys with no group (`partition: key` key budgets cover those), on application keys, and on the MCP Store.
- Group keys on the MCP Store's personal key page.

## Rollout

1. TrustGate on every plane (admin first: it runs the migrations). Set `CONSOLE_EVENTS_URL` on the proxy planes.
2. DataCore reads the new attributes.
3. The console issues group keys and sets budgets.

An older data plane reads a group key as a personal key (it ignores `group_id`) and enforces no group budget, so step 1 must finish before step 3.

## Rollback

| Step | Action |
|---|---|
| 1 | Stop issuing group keys and setting budgets in the console. |
| 2 | Revert the binaries. `key_group_budgets` can stay: nothing older reads it. |
| 3 | The group key migration's down deletes every group key with its links and restores one key per owner. |

## Risks

| Risk | Mitigation |
|---|---|
| A budget lowered mid-month below the spend refuses the next request with no charge crossing the limit | The gate announces the limit then, once (D9). |
| Redis unavailable | `block` fails closed with 503 and `Retry-After`; `alert` fails open. Same as `partition: key`. |
| Notice lost (console down) | Best effort by design; the console can reconcile from DataCore's per-group spend. |
| Plan union per request | Only for requests that carry a budget; both plans are already compiled. |

## Success criteria

- A user holds a personal key and one key per group; a second key for the same group answers 409.
- A group key's MCP Store is its group's; its MCP policies still see all of the owner's groups.
- LLM events of a group key carry `trustgate.auth.kind=personal` and `trustgate.auth.group_id`.
- On a full and a DB-less proxy, a `block` budget answers 429 once a limit is reached, names the scope, and the console hears once per limit and month.
