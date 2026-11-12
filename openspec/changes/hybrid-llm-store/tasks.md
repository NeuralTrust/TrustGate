# Tasks: LLM Store on hybrid gateways

One PR per repo (TrustGate, app). Merge TrustGate first.

## TrustGate (release N)

- [x] 1.1 `StoreAvailability` + `MinStoreVersion` with a tolerant semver parser, plus a table test for every reason in D2 (no instances, stale `last_seen`, mixed versions, empty version, `dev`, below N, hosted).
- [x] 1.2 `GET /v1/gateways/{gateway_id}/store/llm-availability` (T5). Reads connections for hybrid gateways only.
- [x] 1.3 `AllowsPersonal()` true for hybrid (T1). Update the unit tests of creator, personal_keys, the MCP Store tools and the personal key page that asserted the refusal.
- [x] 1.4 `serveStore` without the hybrid veto (T2). Middleware test: hybrid gateway + personal key → served.
- [x] 1.5 F5 confirmed in code and unit tests; the scoped-plane path moves to QA 3.1 (T6). `go vet -tags functional` passes.
- [x] 1.6 `docs/llm-store.md`, and `make docs` in its own commit.

## app

- [x] 2.1 `llmStoreAvailability` helper + the TrustGate client.
- [x] 2.2 A1, A2, A7: access always writable; keys on the helper, refusal by reason. Update the tests that expect "not available on hybrid gateways".
- [x] 2.3 A3–A6b: reconcile, sweeps, owner seed + backfill, revoke and `syncPersonalKeyGroups` on hybrid.
- [x] 2.4 A8, A9: Everyone and bulk actions with Models on hybrid.
- [x] 2.5 A10: Store base URL from the operator origin.
- [x] 2.6 A11, A12: notices in the Access and Portal UI.

## QA

- [ ] 3.1 Local: TrustGate CP + a local hybrid plane with `APPLICATION_VERSION=v0.83.0` (a local build reports a `git describe` prerelease or `0.0.0-dev`, which reads as outdated) + app turbopack. Grant a model to a group, have the user create a key in the Portal, call `/store/v1` at the hybrid origin, and see the cost under the user.
- [ ] 3.2 Local: a plane at v0.76.0 or later but below N → `data_plane_outdated` (vX / vN). A plane with no heartbeat (empty version) → `version_unknown`. In both cases the admin can save Models access and the Portal shows the notice.
- [ ] 3.3 DEV with a throwaway hybrid gateway, its plane on `APPLICATION_VERSION=v0.83.0` (DEV images report a commit sha, which reads as `version_unknown`).
- [ ] 3.6 On the hybrid plane, open the TrustGate personal-key page (MCP Store `store_personal_key` link): it builds its LLM URL from `gw.Domain` or `<slug>.<proxyDomain>` and its snippets carry no `X-AG-Gateway-Slug`. Confirm what it shows works against the operator origin, or fix it.
- [ ] 3.7 Confirm on a real hybrid plane (DEV, then the prod query of 3.4) that its `config_sync_connections.scope` is its gateway id. Tokens minted today use `instanceId` = gateway id; an older token with a tenant `scope` claim would leave the gateway at `no_data_plane`.
- [ ] 3.4 Prod inventory, read-only: hybrid gateways × `config_sync_connections` (version, last_seen) in EU and US, to confirm no plane is below v0.64.0 and to list who has to upgrade.
- [ ] 3.5 Before the TrustGate release: confirm `dataplane.MinStoreVersion` (`v0.83.0`) is the release that ships T2, and bump it if another release goes out first.
