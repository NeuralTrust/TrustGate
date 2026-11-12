# Proposal: LLM Store on hybrid gateways

## Intent

Hybrid gateways cannot use the LLM Store today. On a hybrid gateway the
console refuses model access ("The LLM Store is not available on hybrid
gateways"), the Portal lists no models, and TrustGate refuses personal
consumers and personal keys. This change opens the LLM Store on hybrid
gateways whose data plane runs a build that serves it. The current behavior
stays for every other hybrid gateway.

## Why it was closed

RUN-1763 (2026-10-05) closed it with one reason: "its data plane predates them
and would serve a personal consumer at its slug"
(`pkg/domain/gateway/gateway.go`, `AllowsPersonal`). Two things have changed
since then:

- v0.64.0 is the first release that knows personal consumers. The one hybrid
  plane we have checked (BV) runs v0.70.0. The rest of the prod inventory is
  unchecked (QA 3.4). A plane older than v0.76.0 cannot report its version,
  so it stays closed anyway (D2).
- Serving a personal consumer at its slug is not a hazard. A hosted plane does
  it today: `consumerAdmitsCaller` admits an API-key caller, and the personal
  key attached to the consumer is that caller.

What is missing is the `/store/v1` route on hybrid planes. Every plane refuses
it with a 404 (`serveStore`, `pkg/api/middleware/auth.go:125`). Evidence and
file references: `design.md` § Facts.

## Scope

### In Scope
- **TrustGate control plane:** lift the hybrid veto on personal consumers and
  personal keys.
- **TrustGate data plane:** lift the hybrid veto on `/store/v1`.
- **Data plane builds:** expose, per gateway, whether every connected
  data-plane build serves the Store.
- **Console:** replace the hybrid checks of the LLM Store with that capability,
  in these places:
  - access
  - keys
  - Portal
  - reconcile
  - Everyone
  - bulk actions
  - owner seed
  - background sweeps
- **Console:** use the operator-set origin as the Store base URL on hybrid.
- **Console:** admins can set Models access on hybrid at any time. Only Portal
  key creation waits until the plane can serve the Store, and the console says
  why.

### Out of Scope
- **Group limits and key budgets on hybrid:** they stay off (decision D3).
- **Raw payload handling:** unchanged; prompts stay inside the customer
  boundary.
- **Upgrading customer planes:** that is the customer's job; we only tell them
  the minimum version.
- **Dedicated gateways:** they already allow personal consumers.

## Capabilities

### New Capabilities
- `hybrid-llm-store`: the conditions under which a hybrid gateway serves the
  LLM Store, and what the console shows when it does not.

### Modified Capabilities
- `llm-store` (RUN-1763): drops "personal consumers and personal keys are
  unavailable on hybrid gateways".

## Rollout

The work spans two repositories, and the order matters:

1. TrustGate release N, on the control plane and hosted planes.
2. Console, with the gate added.
3. Hybrid customers upgrade their plane to N or later.

The hosted planes and the console need no flag: a hybrid gateway stays closed
until its own plane reports N.
