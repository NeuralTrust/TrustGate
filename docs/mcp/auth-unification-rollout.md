# Identity-provider compatibility rollout

This delivery is tracked by RUN-1300 and recovers the runtime improvements from #481 (RUN-1184) while
preserving the existing OIDC API, database rows and snapshot representation.
The retirement work originally folded into #481 through #485 (RUN-1185) is a
separate release. No OIDC data migration is registered in this delivery.

## Release order

1. Deploy the compatible TrustGate release to every admin, proxy and MCP
   instance, including disconnected snapshot consumers. Keep OIDC rows and
   responses in their original shape. Do not start using OAuth2 role-based
   proxy consumers, OIDC MCP consumers or OAuth2 inline keys while old data
   planes can still receive their traffic.
2. Deploy the compatible App release. Its identity-provider selector accepts
   both types, and editing preserves inline keys, subject claims and existing
   provider configuration. Exercise both the Identity routes and the consumer
   editor reused by Access.
3. In a separate release, switch API responses to the canonical OAuth2 shape
   and migrate stored OIDC configurations only after all readers support it.
   Keep accepting legacy requests and snapshots during the rollback window.
4. Remove legacy request aliases and runtime adapters only after observing no
   remaining legacy writers for an agreed window. Inventory external API
   clients as well as App before removing an accepted request shape.

App must not expose the newly accepted consumer combinations before step 1
has completed. Hiding an old navigation entry does not retire its routes or
its API contract.

## Subject and token compatibility

An explicitly configured `subject_claim` must be a non-empty string claim.
Both JWT verification paths use it, and reject a missing or incorrectly typed
claim instead of silently selecting another identity. A configured claim does
not also require `sub` to be present. Audit existing custom-claim tokens before
deploying: previously MCP could silently fall back when that claim was absent.

Without an explicit claim, existing defaults remain: proxy uses `sub`; MCP
prefers Entra `oid` and falls back to `sub`. Changing that default requires a
separate inventory and migration of subject-keyed permissions, connections,
consents and vault entries. This release does not rewrite those identities.

The unified type does not imply identical protocol support: the proxy JWT
verifier requires an explicit JWKS URL or inline public keys. Discovery-only,
opaque-token introspection and brokered sessions retain their existing MCP
scope. Providers without login capability may still validate supplied tokens.

## Retirement preflight

Run `scripts/auth-unification-preflight.sql` with an approved database
connection. It opens a read-only transaction, bounds statement duration and
returns aggregate counts only. Its overlap report is a candidate inventory,
not proof that two credentials can be merged or that tokens are valid.

Before enabling the later migration:

- Record deployed versions of every database and snapshot reader. All must
  understand the canonical representation; an old role-based proxy expects
  `oidc` and cannot safely consume a renamed row.
- Inventory OIDC rows per gateway and validate their issuer, audiences and key
  material. Report malformed or dual-payload rows for explicit remediation.
- Compare OIDC and OAuth2 providers within each gateway for overlapping issuer
  and audience coverage, including the `api://` audience alias and missing or
  empty audience lists (which accept any audience). Resolve overlaps
  deliberately rather than merging credentials.
- Verify create, get, list, update and consumer association with old requests
  and new responses. A rename-only App edit must preserve the full config.
- Rehearse the migration and rollback against a disposable PostgreSQL copy,
  including rows edited, deleted or newly created after migration. Preserve a
  record of converted IDs so native OAuth2 rows are never demoted by rollback.
- Test propagation to a database-less data plane, restart it from a saved
  snapshot, and verify role-based proxy access and MCP access again.

The migration must not run implicitly merely because a compatibility binary
starts. Its registration belongs to the later retirement release.

### Production inventory sampled on 2026-09-07

A read-only repeatable-read inspection found 17 enabled OAuth2 providers and
one enabled OIDC provider. The OIDC provider had no consumer associations.
Four OAuth2 providers configured a custom subject claim. There were no inline
keys, dual-payload configurations, missing issuers, malformed audience shapes
or overlapping issuer/audience pairs within a gateway. One provider lacked a
client ID. This sample does not verify issued tokens or deployed reader
versions; repeat the preflight before the retirement release.

## Verification and rollback

The compatible release needs unit coverage for role-based authorization,
legacy provider projection without cache mutation, inline keys, explicit
subjects and broker capability. Exercise tokenless and token-bearing requests
for both explicit providers and the built-in provider, and ensure an attached
credential cannot be bypassed through platform login.

Run the functional API/repository suites against disposable PostgreSQL and
verify the App round trip against the deployed compatible API before release.
CI success is not evidence that an actual fleet has completed the rollout.

Before canonicalization, rollback is possible only if configurations using new
runtime capabilities have been removed or routed away from old instances.
After canonicalization, keep the compatible release as the minimum rollback
target. Reverting directly to an older binary is unsafe; restoring legacy
storage alone does not undo cached snapshots or new OAuth2 consumer usage.

No live data conversion, deployment, rollback or deletion of the legacy
contract is performed by the compatible code changes.

### Local implementation verification

- TrustGate: `go test ./pkg/...`, `go vet ./...`, `make lint`, focused race
  tests for middleware/resolver/auth/OAuth/JWT validation, and frontend
  typecheck passed.
- Functional authentication/OAuth/role-based tests passed against local
  PostgreSQL using a disposable `trustgate_functional` database, which the
  harness removed after completion. Production was not a functional-test
  target.
- The preflight SQL passed with temporary local fixtures exercising inline
  keys, custom subjects, legacy consumer associations and audience aliases.
- App: 47 Identity/Consumers suites (369 tests) passed, along with focused
  lint. The full typecheck reported the same 49 Prisma-client diagnostics on
  the clean develop baseline and the changed worktree; no new diagnostics.
- Independent review completed without unresolved findings. Browser-level
  end-to-end validation and an actual fleet rollout remain release checks.
