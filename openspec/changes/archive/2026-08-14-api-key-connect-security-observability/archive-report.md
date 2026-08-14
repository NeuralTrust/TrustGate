# Archive Report: API-key connect security and observability

## Closure

- Change: `api-key-connect-security-observability`
- Linear: RUN-1142
- Final Linear state: In Review
- Artifact mode: hybrid
- Archive date: 2026-08-14
- Delivery: PR #438 merged into the RUN-1141 integrator branch before the additional review completed; final fixes are in PR #442, open against `feat/api-key-self-service-connect-endpoint`.
- Review budget: approved `size:exception`.

## Specification Promotion

- Updated `openspec/specs/api-key-self-service-connect/spec.md` by replacing the four matching requirements from the delta:
  - Secure form and caching
  - Ticket creation and redirect
  - Secret non-disclosure
  - Existing security boundaries
- Created `openspec/specs/mcp-connect-security-observability/spec.md` from the complete new capability specification.
- Preserved all unrelated requirements in the existing API-key self-service connect specification.

## Final Verification

The final state passed:

- license check
- formatting (`gofmt`, `goimports`, and diff formatting check)
- focused and full race tests
- `go vet ./...`
- `golangci-lint run` with no issues
- code review with no findings
- security review with no findings

No critical verification issue remains.

## Decisions and Preserved Invariants

- The approved size exception remains the delivery decision for the coupled security hardening.
- Connect tickets retain a reusable fifteen-minute TTL.
- OAuth state retains a ten-minute TTL and atomic one-time `GETDEL` consumption.
- API-key provider visibility and lifecycle operations remain constrained to the authorization-time provider snapshot, with explicit legacy compatibility.
- Lifecycle audit data remains identifier-only and persistence-success-only.
- Rate-limit keys and telemetry remain bounded and secret-free.

## Operational Limitation

`MCP_CONNECT_TRUSTED_PROXY_CIDRS` remains empty until Infrastructure/SRE confirms the immediate GKE proxy CIDRs. This safe default prevents trusting spoofable forwarding headers but can group traffic by the immediate proxy peer and therefore reduce source-level granularity.

## Traceability

| Artifact | Engram observation |
|---|---:|
| proposal | #644 |
| spec | #645 |
| design | #646 |
| tasks | #648 |
| apply progress and final command verification | #652 |
| archive report | #658 |
| verify report | Not persisted as a standalone observation |

The missing standalone `verify-report` observation is not represented by an invented ID. Final verification is traceable through observation #652, successful local command records, and the user-confirmed final review state captured by this report.

## Archive Integrity

The archive contains the complete active change contents: `proposal.md`, `exploration.md`, `design.md`, `tasks.md`, both delta specs, and this `archive-report.md`. Pre/post SHA-256 hashes matched for every moved source artifact; the report's final hash was recalculated after adding its Engram ID. The active change path no longer exists, while both promoted main specifications remain under `openspec/specs/`.
