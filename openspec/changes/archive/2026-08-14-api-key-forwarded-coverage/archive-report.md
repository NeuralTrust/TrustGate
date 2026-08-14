# Archive Report: API-key forwarded authorization coverage

## Closure

- Change: `api-key-forwarded-coverage`
- Linear: RUN-1139 (`test(mcp-auth): cover API-key forwarded authorization end to end`), parent epic RUN-1136
- Artifact mode: hybrid
- Archive date: 2026-08-14
- Worktree: `/Users/edu/Neuraltrust/TrustGate-api-key-forwarded-coverage`, branch `test/api-key-forwarded-coverage`
- Delivery: draft PR #448 against the integration branch `feat/api-key-self-service-connect-endpoint`. Never `develop` — the epic is merged manually after end-to-end validation.
- Review budget: 462 changed lines under the recorded `size-exception`. Indivisible: the provider stub is dead code without the test that drives it.

## Specification Promotion

**Nothing was promoted, by design.** No file under `openspec/specs/` was created, modified or deleted.

The delta spec declares the capability `mcp-api-key-forwarded-verification`, whose Purpose states that
archiving it MUST NOT modify either canonical spec. The proposal records `New Capabilities: None` and
`Modified Capabilities: None`: this change proves that `api-key-self-service-connect` and
`mcp-connect-security-observability` hold end to end, it does not alter them.

The capability was also **not** filed as a new spec under `openspec/specs/`, because:

- Its requirements are verification obligations over the test suite ("The functional suite MUST prove…"),
  not product behavior. Both existing specs in `openspec/specs/` define gateway behavior
  ("Define a browser flow that…", "Bound public API-key connect attempts…"). Filing a verification
  capability beside them would assert a third product capability that the proposal explicitly denies.
- The repo precedent supports promotion only for product capabilities: `2026-08-13-api-key-self-service-connect-endpoint`
  promoted a new behavior capability, and `2026-08-14-api-key-connect-security-observability` promoted one new
  behavior capability plus four modified requirements. Neither establishes a convention for verification-only specs.

The verification spec therefore lives in this archive as its permanent record. Discoverability is preserved
through `docs/mcp/testing-guide.md` §5 and §5.1, which is on the main documentation path rather than in the
SDD archive, and which names both new tests and the scenario-10 regression note.

## Final Verification

No standalone verify phase ran for this change; verification is the change. The recorded green state
(observation #678, plus the local re-checks performed at archive time) is:

- `gofmt -l` clean
- `go vet -tags functional ./tests/functional/...` clean
- `go test -tags functional -c -o /dev/null ./tests/functional/` compiles
- `golangci-lint run --build-tags functional ./tests/functional/...` — 0 issues
- Adversarial review applied: two blockers, one secret-hygiene hole, one investigation, five suggestions (Phase 5b)
- `git diff --stat 8c5cd730 -- pkg` empty — no production code change
- `tests/functional/mcp_e2e_test.go` untouched
- Zero comments in the new test file; the only comment-shaped line is the `//go:build functional` directive

`make test-functional` cannot run locally because an agent may not create `.env.functional`. The green-light
gate is CI's Functional Tests job on PR #448, which is outside this archive's control.

No critical verification issue remains.

## Decisions and Preserved Invariants

- Scenario 10 stays a regression obligation, not new test code: `TestMCPOAuth_SharedHostScopesChallengeAndResolvesConsumerIdP`
  and `TestMCPServer_RoleBasedConsumer*` must keep passing unmodified.
- `MCP_CONNECT_RATE_LIMIT_ENABLED=false` in `.env.functional.example` is load-bearing: the connect limiter's
  per-source bucket would otherwise make the suite order-dependent. CI copies the example file verbatim.
- Principal identity is `principal.Subject = auth.Name` and the vault is keyed `(gatewayID, subject, provider)`,
  so a second API-key auth on the *same* consumer is a distinct principal. That is how scenario 8 proves
  principal isolation with the consumer held constant.
- `require.Zero(seen)` is the only sound isolation observable: `askUpstream` resolves the credential before
  dialing, so a consent-required outcome means zero requests reach the upstream and any bearer comparison
  passes vacuously.
- `idp.tokenExchanges() == 1` is the observable separating "reused the stored grant" from "ran consent again".
- Secret hygiene is structural: `requireRPCSucceeded`, `requireBearerMatches` and `requireConsentRequired`
  exist because `rpcResult`, `require.Equal` and `require.Nil` all render their operands, and a
  consent-required payload embeds a live connect ticket in both its message and `data.connect_url`.
- Extra auths must be attached before the first MCP request so the propagation gate covers the new binding.

## Traceability

| Artifact | Engram observation |
|---|---:|
| explore | #672 |
| proposal | #673 |
| spec | #674 |
| design | #675 |
| tasks | #676 |
| apply progress and final command verification | #678 |
| archive report | #692 |
| verify report | Not persisted as a standalone observation |

No verify-report observation is invented. Verification is traceable through observation #678, the local
command records above, and CI on PR #448.

## Archive Integrity

The archive contains the complete active change contents — `exploration.md`, `proposal.md`, `design.md`,
`tasks.md`, `specs/mcp-api-key-forwarded-verification/spec.md` — plus this report. The move was performed with
`git mv`, so content is byte-identical and the rename is recorded rather than reconstructed. The active path
`openspec/changes/api-key-forwarded-coverage/` no longer exists. `openspec/specs/` is unchanged.

`tasks.md` was updated before the move to close Phase 6 (6.1–6.4) against delivered evidence and to record the
final 462-line measurement; every other artifact was moved verbatim. Nothing is committed — the branch is left
staged for the user to review and commit.
