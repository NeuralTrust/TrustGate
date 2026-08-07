# Tasks: Dual-era northbound MCP protocol boundary

## Review Workload Forecast

| Field | Value |
|---|---|
| Estimated changed lines | 950–1120 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (340–390) → PR 2 (280–340) → PR 3 (330–390) |
| Delivery strategy | auto-chain |
| Chain strategy | stacked-to-main |

Decision needed before apply: No
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|---|---|---|---|
| 1 | Classify, validate, reject before routing | PR 1 | Current branch; base `origin/main` |
| 2 | Normalize and sanitize modern results | PR 2 | Base PR 1 branch; merge after PR 1 |
| 3 | Add scoped discovery and integration matrix | PR 3 | Base PR 2 branch; merge after PR 2 |

Each child PR must show only its slice; merge to `main` in order and retarget the next PR after its parent merges.

## Phase 1: Protocol boundary (PR 1)

- [x] 1.1 Create `protocol_era.go` and `protocol_era_test.go` with newest-first versions and table-driven precedence. Depends: none. Done: legacy/modern/unknown cases pass.
- [x] 1.2 Create `modern_validation.go` and tests for `_meta`, capabilities, mirrored headers, exact Base64 sentinel, and modern-only `Mcp-Param-*`. Depends: 1.1. Done: errors/status/data match spec.
- [x] 1.3 Reorder `mcp_handler.go`; add era-aware early writers. Extend `mcp_handler_test.go` to prove failures skip lookup, scoping, limiter, plugins, composer, spans, and preserve legacy. Depends: 1.1–1.2.
- [x] 1.4 Run `clean-comments` on phase files; retain tooling directives only.
- [x] 1.5 Run `/reviewer` against PR 1 scope; resolve correctness, boundary, and regression findings.
- [x] 1.6 Run `/verifier`: `go test -race ./pkg/api/handler/http/mcp ./pkg/app/mcp`, `go vet ./...`, `golangci-lint run`. Done: all green.

## Phase 2: Modern response adapter (PR 2)

- [ ] 2.1 Create `modern_response.go` and tests for copied object normalization, universal server info, private TTLs, and non-object HTTP 500/`-32603`. Depends: Phase 1.
- [ ] 2.2 Add recursive `x-mcp-header` sanitization and concurrent immutability tests in `modern_response_test.go`. Done: modern copy changes only; legacy/cached payload remains intact under `-race`.
- [ ] 2.3 Wire modern success/error adaptation in `mcp_handler.go`; test list/read/tool-call fields and legacy byte-shape compatibility in `mcp_handler_test.go`. Depends: 2.1–2.2.
- [ ] 2.4 Run `clean-comments` on phase files; retain tooling directives only.
- [ ] 2.5 Run `/reviewer` against PR 2 scope; resolve cache, mutation, and status findings.
- [ ] 2.6 Run `/verifier` with the Phase 1 command set. Done: all green.

## Phase 3: Scoped discovery and transport closure (PR 3)

- [ ] 3.1 Create `server_discover.go` and tests for scoped kinds, newest-first versions, fingerprinted identity, private 300000 TTL, and zero upstream targets. Depends: Phases 1–2.
- [ ] 3.2 Wire local discovery and telemetry in `mcp_handler.go`; prove no limiter, plugin, consent, composer, or upstream effects for `server/discover`.
- [ ] 3.3 Extend `mcp_handler_test.go` (and `pkg/server/router/mcp_router_test.go` if needed) for modern 404/`-32601`, resource `-32602`, notification 202, ignored/unemitted session ID, POST path, GET/DELETE 405, and legacy regressions.
- [ ] 3.4 Run `clean-comments` on phase files; retain tooling directives only.
- [ ] 3.5 Run `/reviewer` against the complete stack; resolve role-leakage, telemetry, and compatibility findings.
- [ ] 3.6 Run `/verifier` with focused race tests, `go vet ./...`, and `golangci-lint run`. Done: complete chain green; composer contracts unchanged.
