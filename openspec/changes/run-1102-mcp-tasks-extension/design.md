# Design: RUN-1102 support the MCP Tasks extension

**Change**: `run-1102-mcp-tasks-extension` · **Linear**: [RUN-1102](https://linear.app/neuraltrust/issue/RUN-1102/featmcp-support-the-mcp-tasks-extension)
**Branch**: `feat/run-1102-mcp-tasks-extension` · **Base**: `feat/run-1103-dual-era-northbound-protocol-boundary` @ `8b87f8da`
**Inputs**: `exploration.md`, `proposal.md` (decisions 1–10 locked), `spec.md`

## Technical Approach

A direct transposition of the RUN-1101 MRTR ticket. `mrtr_ticket.go`'s crypto is extracted into a
package-private `signedEnvelope`; `TicketSigner` and a new `TaskHandleSigner` become typed wrappers
with separate claim structs, separate secrets, and separate purpose tags in the MAC input. Tasks wire
types are hand-rolled in `pkg/app/mcp` on the existing `marshalEnvelope`/`unmarshalEnvelope` helpers
so unknown upstream fields survive. `tasks/get|update|cancel` become supported modern methods routed
through `rpc_dispatcher.go`; the composer gains four task use cases that unwrap the handle, run the
full policy pass, re-authorize, and dial only the bound registry with the real `taskId`.

## Architecture Decisions

| # | Decision | Chosen | Rejected | Rationale |
|---|---|---|---|---|
| D1 | Envelope shape | Package-private `signedEnvelope` operating on `[]byte` payloads (`seal`/`open`); typed wrappers own JSON + claim semantics | Generic `signedEnvelope[T]`; envelope owning claim marshalling | Keeps one audited crypto path with zero generics churn; `TicketSigner`'s exported surface and error identity stay byte-identical |
| D2 | MRTR MAC compatibility | Envelope accepts a `legacyPurposes []string` at verify time only; MRTR passes `[""]` (the untagged MAC used today), mints with `mcp.mrtr.ticket.v1` | Flip MRTR's MAC with no fallback | Spec mandates the purpose tag, but the proposal's rollback plan requires tickets minted before the deploy (and before a revert) to stay valid. Verify-only fallback satisfies both; a task handle can never reach it because the version prefix (`tg1k`) is checked before the MAC |
| D3 | Task upstream contract | New optional `TaskUpstream` interface, type-asserted by the composer | Add three methods to `Upstream` | `Upstream` is implemented by the legacy `Session` and by every composer/discovery test fake. `TaskUpstream` leaves `client.go` and all fakes untouched, models "task support is per-upstream", and keeps the diff inside the 400-line exception |
| D4 | Where the exposed tool name comes from for plugins | `Composer.UnwrapTaskHandle` — MAC + `exp` + gateway/consumer/principal binding only, no compose, no dial | Run `compose()` in the dispatcher; pass a plugin hook into the composer | The dispatcher needs `expn` *before* `PreRequest`/`PreResponse`. Registry-attachment and toolkit checks stay inside the use cases where `compose()` runs; both paths return the same sentinel, so the split leaks nothing |
| D5 | `resultType` preservation | `normalizeModernResult` computes `isTask` **once**, before the `_meta` block, and gates both `applyMRTRFields` and the unconditional `delete(normalized, "ttlMs")` | Only guard `applyMRTRFields` | The existing `delete(normalized, "ttlMs")` at `modern_response.go:71` would strip a task's `ttlMs` even after the `resultType` fix. Both scrubs are the blocker |
| D6 | Southbound header scope | `Mcp-Method` + `Mcp-Name` carried on a request-context value read by `modernRoundTripper` | Thread headers through `sdk.StreamableClientTransport` args (impossible) | Headers are only reachable from the round tripper. Scoped to `tasks/*` in this change; extending to the other modern methods is an Open Question, not silent scope creep |
| D7 | Fail-closed choke point | `mcp_handler.go` drops `extensions` from the declared capabilities when `!tasks.Signer.Enabled()` | Gate in `AllowlistedClientCapabilities` (no signer access) or in `modern_upstream` (too late) | One place decides the whole feature is off, so unsetting `MCP_TASK_HANDLE_SECRET` is byte-identical to today with no code change |

## Interfaces / Contracts

### `pkg/app/mcp/signed_envelope.go` (new)

```go
const (
	envelopeKidCurrent  = "c"
	envelopeKidPrevious = "p"
)

// signedEnvelope is the shared HMAC framing behind MRTR tickets and task
// handles: <version>.<kid>.<b64url(payload)>.<b64url(hmac)>.
type signedEnvelope struct {
	version        string   // wire prefix: "tg1" | "tg1k"
	purpose        string   // domain separator inside the MAC input
	legacyPurposes []string // additionally accepted at verify time only
	current        []byte
	previous       []byte
	ttl            time.Duration
	maxBytes       int // 0 = unbounded
	now            func() time.Time
}

func newSignedEnvelope(version, purpose string, secret, prev string,
	ttl time.Duration, maxBytes int, legacyPurposes ...string) *signedEnvelope

func (e *signedEnvelope) enabled() bool                       // len(current) > 0 — fail closed
func (e *signedEnvelope) withClock(now func() time.Time)
func (e *signedEnvelope) expiry(explicit int64) int64          // min(now+ttl, explicit) when explicit != 0
func (e *signedEnvelope) expired(exp int64) bool
func (e *signedEnvelope) seal(payload []byte) (string, error)  // errEnvelopeTooLarge past maxBytes
func (e *signedEnvelope) open(token string) ([]byte, error)    // errEnvelopeRejected on every failure

// macInput keeps the untagged form byte-identical to the pre-change MRTR MAC.
func (e *signedEnvelope) macInput(purpose, kid, payload string) string {
	if purpose == "" {
		return e.version + "." + kid + "." + payload
	}
	return purpose + "|" + e.version + "." + kid + "." + payload
}
```

`open` enforces `maxBytes` before any decode, rejects a version-prefix or `kid` mismatch, then tries
`current` then `previous`, each against `purpose` then every `legacyPurposes` entry, with
`hmac.Equal`. Sentinels are package-private (`errEnvelopeDisabled`, `errEnvelopeRejected`,
`errEnvelopeTooLarge`); each wrapper maps them to its own domain error.

### `pkg/app/mcp/mrtr_ticket.go` (behaviour-preserving refactor)

`TicketClaims`, `Binds`, `NewTicketSigner(secret, prev, ttl, maxRounds)`, `WithClock`, `Enabled`,
`MaxRounds`, `Mint`, `Unwrap` keep their exact signatures and their exact error (`ErrMRTRReplayRejected`
for every failure). `ticketVersion = "tg1"` stays; `ticketKidCurrent = envelopeKidCurrent` stays as a
one-line alias because `mrtr_ticket_test.go:56` references both. `ticketKidPrevious`, `verifyMAC`, and
`hmacSHA256` move into the envelope. `TicketSigner` becomes `struct{ env *signedEnvelope; maxRounds int }`
built with `newSignedEnvelope(ticketVersion, mrtrTicketPurpose, secret, prev, ttl, 0, "")`.

**Behaviour-preservation argument**: every existing MRTR test is a mint→unwrap round trip
(`mrtr_ticket_test.go`, `composer_mrtr_test.go`, `plugin_runner_mrtr_test.go`) — none asserts frozen
signature bytes — so all pass unchanged. Cross-binary validity is preserved by D2's verify-only
untagged fallback: a `tg1` ticket minted by the pre-change binary still opens, and a ticket minted by
the new binary still opens after a `git revert` because its MAC prefix is only ever produced for
`purpose != ""`… which the reverted binary would reject. **Therefore forward-only compatibility holds;
reverting invalidates handles minted post-deploy, bounded by the 5-minute MRTR TTL.** Recorded in
Open Questions.

### `pkg/app/mcp/task_handle.go` (new)

```go
const (
	taskHandleVersion         = "tg1k"
	taskHandlePurpose         = "mcp.task.handle.v1"
	taskHandleClaimVersion    = 1
	DefaultTaskHandleTTL      = time.Hour
	MaxTaskHandleTTL          = 24 * time.Hour
	DefaultTaskHandleMaxBytes = 1024
)

// TaskHandleClaims binds a mediated upstream task to the exact caller, surface,
// and registry it was created for.
type TaskHandleClaims struct {
	V        int    `json:"v"`
	GID      string `json:"gid"`  // gateway id
	CID      string `json:"cid"`  // consumer id
	RID      string `json:"rid"`  // registry id
	Sub      string `json:"sub"`  // principal fingerprint, "" when no principal
	Exposed  string `json:"expn"`
	Upstream string `json:"upn"`
	TaskID   string `json:"tid"`  // real upstream task id
	Created  int64  `json:"iat"`  // additive; not part of Binds — RUN-1104 forward compat
	Exp      int64  `json:"exp"`
}

// Binds reports whether the claims match the request being served. Every field
// must match; a mismatch is indistinguishable from a forged handle.
func (c TaskHandleClaims) Binds(gatewayID, consumerID, registryID, principal, exposed, upstream string) bool

type TaskHandleSigner struct{ env *signedEnvelope }

func NewTaskHandleSigner(secret, prev string, ttl time.Duration, maxBytes int) *TaskHandleSigner
func (s *TaskHandleSigner) WithClock(now func() time.Time) *TaskHandleSigner
func (s *TaskHandleSigner) Enabled() bool
func (s *TaskHandleSigner) Mint(claims TaskHandleClaims) (string, error)
func (s *TaskHandleSigner) Unwrap(handle string) (*TaskHandleClaims, error)
```

`NewTaskHandleSigner` clamps `ttl` to `(0, MaxTaskHandleTTL]` and `maxBytes` to
`DefaultTaskHandleMaxBytes` when non-positive, so the `24h` ceiling holds regardless of caller.
`Mint` sets `V`, computes `Exp = env.expiry(claims.Exp)` (the caller passes `createdAt + ttlMs` when
the upstream declared one — decision 5), and maps `errEnvelopeTooLarge → ErrTaskHandleTooLarge`
(`-32603`, decision 7). `Unwrap` maps everything to `ErrTaskHandleRejected` (`-32602`).

`principalFingerprint(ctx) (string, bool)` is extracted from `discovery.go:277`
(`hex(sha256(issuer|subject)[:8])`) and reused by both `discoveryKey` — byte-identical — and the
signer, so there is one fingerprint definition in the package.

### `pkg/app/mcp/tasks.go` (new)

go-sdk v1.7.0 has no Tasks types (verified: no `tasks.go`, no `CreateTaskResult`, no
`io.modelcontextprotocol/tasks` symbol). Three envelope-preserving types, built on the existing
`unmarshalEnvelope`/`marshalEnvelope`/`stringField` helpers in `protocol.go`:

```go
const (
	MetaKeyTasksExtension = "io.modelcontextprotocol/tasks"
	MethodTasksGet        = "tasks/get"
	MethodTasksUpdate     = "tasks/update"
	MethodTasksCancel     = "tasks/cancel"
	ResultTypeTask        = "task"
)

type TaskStatus string // working | input_required | completed | cancelled | failed
func BoundTaskStatus(raw string) TaskStatus // "" when unknown
func (s TaskStatus) Terminal() bool         // completed | cancelled | failed

// Task is the extension's Task shape. Unknown upstream fields round-trip.
type Task struct {
	TaskID, CreatedAt, LastUpdatedAt string
	Status                           TaskStatus
	TTLMs, PollIntervalMs            *int64
	payload                          map[string]json.RawMessage
}

// CreateTaskResult is a tools/call result carrying resultType: "task".
type CreateTaskResult struct{ Task; ResultType string }

// DetailedTask is a tasks/get result: a Task plus exactly one of result, error,
// or inputRequests depending on status.
type DetailedTask struct {
	Task
	Result, Error, InputRequests json.RawMessage
}

func (t Task) MarshalJSON() ([]byte, error)   // marshalEnvelope(t.payload, "taskId", …, "status", …)
func (t *Task) UnmarshalJSON([]byte) error

// Raw-JSON helpers mirroring composer.go's replaceRequestState idiom.
func TaskResultFields(raw json.RawMessage) (resultType string, status TaskStatus, taskID string, ok bool)
func RewriteTaskEnvelope(raw json.RawMessage, handle string, pollFloorMs, ttlMsCeiling int64) json.RawMessage
func TerminalTaskResult(raw json.RawMessage) (json.RawMessage, bool) // status==completed → inner result
func ReplaceTaskResult(raw, result json.RawMessage) json.RawMessage
func StripTaskResult(raw json.RawMessage) json.RawMessage            // non-declaring client fallback
```

`numberField`/`setNumberField` are added next to `stringField` so `ttlMs` and `pollIntervalMs`
(nullable numerics that `marshalEnvelope`'s `...string` signature cannot carry) are read and clamped
without dropping siblings. `RewriteTaskEnvelope` always emits `pollIntervalMs = max(upstream, floor)`
(decision 6) and never re-mints (decision 4 — the caller passes the handle to echo).

### `pkg/app/mcp/protocol.go` + `composer.go`

```go
// TaskRef is the resolved, re-authorized coordinates of one upstream task.
type TaskRef struct {
	RegistryID, Exposed, Upstream, TaskID string
	Exp                                   int64
}

// TaskUpstream is implemented only by modern upstreams. The composer asserts it;
// a legacy Session never satisfies it and a task can never be served over legacy.
type TaskUpstream interface {
	GetTask(ctx context.Context, ref TaskRef) (json.RawMessage, error)
	UpdateTask(ctx context.Context, ref TaskRef, inputResponses json.RawMessage) (json.RawMessage, error)
	CancelTask(ctx context.Context, ref TaskRef) (json.RawMessage, error)
}

// Composer gains:
UnwrapTaskHandle(ctx, rc, handle string) (TaskRef, error)
GetTask(ctx, rc, handle string) (json.RawMessage, error)
UpdateTask(ctx, rc, handle string, inputResponses json.RawMessage) (json.RawMessage, error)
CancelTask(ctx, rc, handle string) (json.RawMessage, error)
```

`composer` gains `tasks *TaskHandleSigner` and `pollFloorMs int`.
`NewComposerWithMediation(dialer, creds, discovery, logger, ticket, tasks, pollFloorMs)` is added;
`NewComposerWithSigner` delegates with `nil, 0` so `composer_test.go` and `composer_mrtr_test.go`
compile unchanged. `CallTool`'s `wrapContinuation` gains a task branch ahead of the MRTR branch:
`resultType == "task"` → mint (or, when `!tasks.Enabled()`, `StripTaskResult`). A shared
`resolveTask(ctx, rc, handle)` does unwrap → `compose()` → assert `claims.RID ∈ mcpRegistries(rc)` →
assert the binding still maps `expn → upn` on that registry → assert `claims.Sub` matches
`principalFingerprint(ctx)` → `target()` (credentials for that registry only) → `dialer.Connect` →
`up.(TaskUpstream)`. Every failure, including `creds.Apply` failure and a non-`TaskUpstream` upstream,
returns `ErrTaskHandleRejected`.

### `pkg/app/mcp/errors.go`

```go
var (
	ErrTaskHandleRejected     = fmt.Errorf("mcp: task rejected")
	ErrTaskCapabilityRequired = fmt.Errorf("mcp: task capability required")
	ErrTaskHandleTooLarge     = fmt.Errorf("mcp: task handle too large")
)

const (
	CodeTaskCapabilityRequired int64 = -32025
	CodeTaskHandleRejected     int64 = -32602
)

func TaskHandleRejectedRPCError() *RPCError     // constant message, Data == nil, always
func TaskCapabilityRequiredRPCError() *RPCError // Data: {"requiredCapabilities":["io.modelcontextprotocol/tasks"]}
func MapTaskError(err error) error              // mirrors MapMRTRError
```

### `pkg/app/mcp/mrtr_caps.go`

```go
const capabilityKindExtensions = "extensions"

// AllowlistedClientCapabilities keeps elicitation, sampling, roots, and a
// bounded extensions object.
func AllowlistedClientCapabilities(raw map[string]any) map[string]any // + extensions branch
func allowlistedExtensions(raw any) map[string]any                   // MetaKeyTasksExtension only, value forced to {}
func DeclaredTasksExtension(caps map[string]any) bool
```

Forcing the value to `map[string]any{}` bounds what is forwarded southbound so a client cannot smuggle
a payload through the extension object. `InputRequestKind` never returns `"extensions"`, so
`declaredInputRequests` is unaffected.

## Data Flow

```
        northbound POST                       app layer                          southbound
 ┌────────────────────────────┐   ┌──────────────────────────────┐   ┌────────────────────────┐
 │ mcp_handler   (era, caps)  │   │ Composer  (compose, re-authz)│   │ modernUpstream         │
 │ modern_validation (Mcp-*)  │──▶│ TaskHandleSigner (mint/open) │──▶│ Mcp-Method / Mcp-Name  │
 │ rpc_dispatcher (limit, rl) │◀──│ PluginRunner (PreReq/PreResp)│◀──│ _meta extensions       │
 │ modern_response (shape)    │   └──────────────────────────────┘   └────────────────────────┘
 └────────────────────────────┘
```

**1 · create** — `tools/call` with `_meta.clientCapabilities.extensions["io.modelcontextprotocol/tasks"]={}`.
`declaredClientCapabilities` keeps `extensions` **only** when `tasks.Signer.Enabled()` (D7).
`checkRateLimit` → `PreRequest` → `composer.CallTool` → `compose()` picks the binding → `target()` +
`creds.Apply` → `modernUpstream.CallTool`, whose `metadataForToolCall` now forwards `extensions`
because the allowlist preserves it. Upstream answers `{resultType:"task", taskId:"u-123",
status:"working", createdAt, ttlMs:600000}`. `wrapContinuation` mints
`tg1k.c.<claims{gid,cid,rid,sub,expn,upn,tid:"u-123",iat,exp}>.<mac>` with
`exp = min(now+MCP_TASK_HANDLE_TTL, createdAt+600000ms)`, then `RewriteTaskEnvelope` swaps
`taskId → handle` and clamps `pollIntervalMs`. No `PreResponse`: there is no tool output yet.
`normalizeModernResult` sees `isTask` and preserves `resultType` and `ttlMs` (D5).

**2 · poll** — `tasks/get {taskId: handle}` with `Mcp-Name: <handle>`, `Mcp-Method: tasks/get`.
`validateModernRequest` matches `Mcp-Name` against `params.taskId` and bounds its length.
`requireTasksCapability` → `checkRateLimit` (the consumer's existing MCP bucket, decision 9) →
`UnwrapTaskHandle` yields `ref.Exposed` → `composer.GetTask` runs `resolveTask` and dials **only**
`claims.RID` with `tid`. Upstream returns `{status:"working", pollIntervalMs:200}`; the response echoes
the **inbound** handle (decision 4) and `pollIntervalMs` becomes `1000`. `modern_response` sets
`resultType:"complete"` and filters `inputRequests` through `declaredInputRequests`.

**3 · terminal** — upstream returns `{status:"completed", result:{content:[…]}}`.
`TerminalTaskResult` extracts the inner tool result; the dispatcher calls
`plugins.PreResponse(ctx, rc, ref.Exposed, nil, inner)`. A denial returns the plugin's `*RPCError` and
the tool content is never delivered; a 2xx rewrite is spliced back with `ReplaceTaskResult`. This is
the TrustGuard-bypass fix and it is asserted at the dispatcher layer.

**4 · cancel** — `tasks/cancel {taskId: handle}` takes the same gate, then
`composer.CancelTask` → upstream `tasks/cancel` → empty ack. The ack is intent, not a terminal
transition (decision 10). A later `tasks/get` on a terminal or purged task returns the same `-32602`
constant message as a forged handle, so nothing is an existence oracle.

## File Changes

| File | Action | Description |
|---|---|---|
| `pkg/app/mcp/signed_envelope.go` | Create | Shared HMAC envelope: version prefix, `c`/`p` rotation, base64url framing, `hmac.Equal`, injectable clock, purpose tag in the MAC, `enabled()` fail-closed, size bound, verify-only `legacyPurposes` |
| `pkg/app/mcp/signed_envelope_test.go` | Create | Envelope unit tests: rotation, tamper, expiry, size bound, purpose separation, legacy fallback |
| `pkg/app/mcp/mrtr_ticket.go` | Modify | Re-expressed on the envelope; exported surface, error identity, and `tg1` wire bytes unchanged; `ticketKidCurrent` aliased so existing tests compile |
| `pkg/app/mcp/task_handle.go` | Create | `TaskHandleClaims`, `Binds`, `TaskHandleSigner` (own secret, TTL clamp, size bound), `principalFingerprint` |
| `pkg/app/mcp/task_handle_test.go` | Create | Mint/unwrap, TTL clamp to `createdAt+ttlMs` and to `24h`, oversize, rotation, cross-primitive rejection (MRTR ticket vs handle) |
| `pkg/app/mcp/tasks.go` | Create | `Task`/`CreateTaskResult`/`DetailedTask` envelope-preserving types, `TaskStatus`, raw-JSON rewrite helpers, `numberField`/`setNumberField` |
| `pkg/app/mcp/tasks_test.go` | Create | Unknown-field round-trip, poll-floor clamp, terminal-result extract/replace, strip for non-declaring clients |
| `pkg/app/mcp/protocol.go` | Modify | `TaskRef`, `TaskUpstream` (`Upstream` untouched) |
| `pkg/app/mcp/composer.go` | Modify | `tasks` signer + `pollFloorMs`; `NewComposerWithMediation`; task branch in `wrapContinuation`; `resolveTask`; `UnwrapTaskHandle`/`GetTask`/`UpdateTask`/`CancelTask` |
| `pkg/app/mcp/composer_tasks_test.go` | Create | Re-authorization matrix and origin-bound routing |
| `pkg/app/mcp/mrtr_caps.go` | Modify | Allowlist `extensions` bounded to the tasks key with a forced `{}` value; `DeclaredTasksExtension` |
| `pkg/app/mcp/errors.go` | Modify | Task sentinels, `CodeTaskCapabilityRequired`, constant-message RPC errors, `MapTaskError` |
| `pkg/app/mcp/mocks/mcp_composer_mock.go` | Modify | Regenerate (`go:generate mockery`) for the four new `Composer` methods |
| `pkg/api/handler/http/mcp/mcp_handler.go` | Modify | `isSupportedModernMethod` + `tasks/*`; `TasksSupport`; `NewHandlerWithMediation`; extensions dropped when the signer is off; `mcpRequestAttrs` returns `("task","","","")`; task outcome/failure recording; `writeAppError` task branches |
| `pkg/api/handler/http/mcp/modern_validation.go` | Modify | `sourceField = "taskId"` for `tasks/*`; `MCP_TASK_HANDLE_MAX_BYTES` bound before the compare |
| `pkg/api/handler/http/mcp/rpc_dispatcher.go` | Modify | Three cases; `requireTasksCapability`; `PreRequest` on `inputResponses`; `PreResponse` on the terminal result under `ref.Exposed` |
| `pkg/api/handler/http/mcp/modern_response.go` | Modify | Compute `isTask` before `_meta`; skip both `applyMRTRFields` and the `ttlMs`/`cacheScope` scrub for task results; `tasks/get` → `resultType:"complete"` with filtered `inputRequests` |
| `pkg/api/handler/http/mcp/server_discover.go` | Modify | `capabilities.extensions` when `tasksEndToEnd(signer, rc)` and a `tools` surface exists; added after `configuredCapabilities` so both toolkit branches get it |
| `pkg/api/handler/http/mcp/protocol_metrics.go` | Modify | `TaskOperation`/`TaskOutcome`, `TasksRecorder`, `NewTasksRecorder`, `mcp.northbound.tasks.outcome_total` |
| `pkg/api/handler/http/mcp/tasks_handler_test.go` | Create | Method set, header binding, `-32025`, `-32602` uniformity, plugin wiring, discover advertisement |
| `pkg/infra/mcp/client/modern_upstream.go` | Modify | `GetTask`/`UpdateTask`/`CancelTask`; `withModernRouting` context value; `modernRoundTripper` sets `Mcp-Method` + base64-sentinel-encoded `Mcp-Name` for `tasks/*`; `metadataForTask` forwards `extensions` |
| `pkg/infra/mcp/client/modern_upstream_tasks_test.go` | Create | Southbound params, headers with the real `taskId`, `_meta` extension forwarding |
| `pkg/infra/trace/span.go` | Modify | `TaskOperation*`/`TaskOutcome*` constants, `BoundTaskOperation`/`BoundTaskOutcome`, `MCPAttrs.TaskOperation`/`TaskOutcome`, `SetMCPTask`. **No task-id field is added** |
| `pkg/config/config.go` | Modify | `MCPTasksConfig{HandleSecret, HandleSecretPrev, HandleTTL, PollIntervalFloorMs, HandleMaxBytes}` on `ServerConfig`; four env vars with defaults `1h` / `1000` / `1024` |
| `pkg/container/modules/mcp.go` | Modify | Provide `*appmcp.TaskHandleSigner`; composer via `NewComposerWithMediation`; handler via `NewHandlerWithMediation` with `TasksSupport` |
| `openspec/specs/mcp-dual-era-northbound/spec.md` | Modify | Apply the delta on archive |
| `docs/operational-metrics.md`, `docs/mcp/` | Modify | New counter, four env vars, rollback lever, orphaned-task note |

**Unchanged by design**: router, auth middleware, role scoper, registry `protocol_mode` semantics,
legacy `initialize` capabilities, MRTR wire format, `pkg/infra/mcp/client/client.go` (D3), every
existing `Upstream` test fake.

`pkg/config/config.go`:

```go
MCPTasks: MCPTasksConfig{
	HandleSecret:        getEnv("MCP_TASK_HANDLE_SECRET", ""),
	HandleSecretPrev:    getEnv("MCP_TASK_HANDLE_SECRET_PREV", ""),
	HandleTTL:           getEnvDuration("MCP_TASK_HANDLE_TTL", defaultMCPTaskHandleTTL),
	PollIntervalFloorMs: getEnvInt("MCP_TASK_POLL_INTERVAL_FLOOR_MS", defaultMCPTaskPollIntervalFloorMs),
	HandleMaxBytes:      getEnvInt("MCP_TASK_HANDLE_MAX_BYTES", defaultMCPTaskHandleMaxBytes),
},
```

The `24h` ceiling is applied inside `NewTaskHandleSigner`, not in config, so it holds for every caller.

## Telemetry

`mcp.northbound.tasks.outcome_total{operation, outcome, era}`, ops-gated (nil recorder when
`Telemetry.OpsMetricsEnabled` is false), mirroring `NewMRTRRecorder`. `operation` ∈
`create|get|update|cancel`; `outcome` ∈
`working|input_required|completed|failed|cancelled|handle_rejected|not_found|policy_denied|expired`,
both filtered through `trace.BoundTaskOperation`/`BoundTaskOutcome` so an unknown value is dropped
rather than emitted. **Emission policy**: every handle-verification and re-authorization failure
records `handle_rejected` — never a discriminated cause — so the metric cannot reconstruct the oracle
the `-32602` constant message hides. `not_found` and `expired` stay in the declared enum, reserved for
RUN-1104 and upstream-reported states, so adding them later is not a label-set change. Spans carry
`TaskOperation`/`TaskOutcome` only. No handle, `taskId`, `result`, `error.data`, `statusMessage`,
`inputRequests`, or `inputResponses` reaches any metric, span, or log.

## Testing Strategy

| Layer | File | What to Test | Approach |
|---|---|---|---|
| Unit — crypto | `signed_envelope_test.go` | Rotation `c`/`p`, tamper, expiry, unknown version/kid, size bound, purpose separation, legacy-purpose fallback | Table-driven, injected clock, no `time.Sleep` |
| Unit — MRTR regression | existing `mrtr_ticket_test.go`, `composer_mrtr_test.go`, `plugin_runner_mrtr_test.go` | MRTR unchanged | **Not edited.** Passing them verbatim is the behaviour-preservation gate |
| Unit — handle | `task_handle_test.go` | Claim binding on all six fields, `exp = min(now+TTL, createdAt+ttlMs)`, `24h` clamp, oversize → `ErrTaskHandleTooLarge`, an MRTR ticket never unwraps as a handle and vice versa | Table-driven, injected clock |
| Unit — wire types | `tasks_test.go` | Unknown-field round-trip, poll-floor clamp with and without an upstream value, terminal extract/replace, strip | Golden JSON fixtures |
| Unit — composer | `composer_tasks_test.go` | Detached registry / toolkit no longer maps `expn→upn` / principal mismatch / different consumer / credential failure / non-`TaskUpstream` → identical `-32602`; only the bound registry is dialled | Fake `Dialer` counting dials per registry |
| Unit — plugins | `plugin_runner_test.go` (extend) | `inputResponses` reach `PreRequest`; terminal result reaches `PreResponse` under the exposed name; denial withholds content | Fake `appplugins.Executor` capturing stage input |
| Handler | `tasks_handler_test.go` | `tasks/*` no longer 404; `Mcp-Name` mismatch → `-32020`; oversize `taskId` → `-32602`; non-declaring → `-32025` with `data.requiredCapabilities`; discover advertises only when enabled + non-legacy registry; legacy `initialize` byte-identical | Fiber test app with a mocked `Composer` |
| Handler — response shape | `modern_response` tests | `resultType:"task"` survives with `ttlMs`; `tasks/get` reports `complete`; `inputRequests` filtered | Golden normalized maps |
| Southbound | `modern_upstream_tasks_test.go` | Params carry the real `taskId`; `Mcp-Method`/`Mcp-Name` set; `_meta.extensions` present only when declared | `httptest` server asserting headers and body |
| Integration | existing MCP handler suite | Create → poll → terminal → cancel with a scripted upstream; secret unset restores pre-change behaviour | Table-driven, `-race` |
| Telemetry | `protocol_metrics` tests | Bounded labels, unknown dropped, no ids/payloads | In-memory meter reader |

Run with `-race`; `go vet ./...` and `golangci-lint run` clean.

## Migration / Rollout

No data migration and no schema change — TrustGate stores nothing (decision 8). The feature is inert
until `MCP_TASK_HANDLE_SECRET` is set: discover omits `extensions`, the handler strips the client's
declaration, no upstream sees it, nothing is minted, `tasks/*` answers `-32025`. Unsetting the secret
is the instant rollback lever with no deploy. `MCP_TASK_HANDLE_SECRET_PREV` covers secret rotation
without invalidating live handles. Delivery is one PR with `size:exception` (400-line risk: **High**),
sequenced as four atomic commits: (1) envelope + signer + wire types + config/DI, (2) northbound
plumbing + composer + southbound, (3) negotiation, (4) plugins + telemetry + specs + docs. Commit 2
must not ship without commit 1 — the `resultType` fix and the dispatch have to land together or a
`CreateTaskResult` is corrupted in flight.

## Open Questions

- [ ] **D2 revert asymmetry**: after a `git revert`, MRTR tickets minted by the new binary carry the
  tagged MAC and the reverted binary rejects them, bounded by the 5-minute MRTR TTL (client sees the
  existing `-32023` and restarts the call). Accept, or make the *tagged* MAC the fallback too so both
  directions verify?
- [ ] Southbound `Mcp-Method`/`Mcp-Name` are scoped to `tasks/*` here. Extend to `tools/call`,
  `prompts/get`, and `resources/read` in a follow-up (spec-required, but a behaviour change on
  paths this ticket lists as unchanged)?
- [ ] `principalFingerprint` reuses `discoveryKey`'s 64-bit truncation. Adequate given `gid`/`cid`/`rid`
  binding plus the MAC, or widen the claim to the full 256-bit digest (+48 chars, still far inside
  the 1 KiB bound)?
