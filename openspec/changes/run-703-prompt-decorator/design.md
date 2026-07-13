# Design: RUN-703 Prompt Decorator

## Technical Approach

Add `prompt_decorator` as a pure `pre_request` transform implementing the existing plugin port. `Execute` treats `ExecInput.Request`, `Body`, `OriginalBody`, and all aliased data as immutable. It parses/copies the current source-format body into private RawMessage structures, applies ordered decorators, marshals newly allocated bytes, and returns only `Result.RequestBody`. The executor remains the sole `RequestContext.Body` writer; provider adaptation follows plugin execution. `prompt_template` remains unchanged.

## Architecture Decisions

| Option | Tradeoff | Decision |
|---|---|---|
| Directly assign or edit `RequestContext.Body` | Fewer allocations, but violates the plugin contract and races with parallel work | Reject; return a non-aliased `Result.RequestBody` |
| Add locks or another scheduler | Duplicates established ordering/folding | Reject; advertise `MutatesRequestBody() == true` and use `StagePlan` |
| Canonical decode/edit/encode | Simple, but loses rich/unknown fields | Reject; edit a narrow source-format RawMessage document |
| Extend `prompt_template` | Couples static decoration to RUN-702 | Reject; use a distinct plugin |
| Snapshot original client bytes | One extra allocation only when mutation is planned | Choose; clone Fiber bytes once into `Body`, then lazily capture `OriginalBody` at the executor boundary before a pre-request stage containing a body mutator |

OpenAI edits raw `messages`; Anthropic edits raw top-level `system` and `messages`. Entries see prior entries in configuration order. Anchors remain: `start=0`, `end=len`, `after_system` follows the full leading system prefix/top-level system and otherwise starts at zero, and `before_last_user` falls back to end.

Every JSON object is token-scanned recursively so exact duplicate members fail before map collapse. Case-insensitive alias rejection is envelope-local: each request, message, or text-block decoder compares only the protocol keys tracked for that envelope. Nested metadata, tool arguments, schemas, and extension objects receive duplicate validation without inheriting protocol-key aliases from their parent.

For `position=system`, `merge` uses a blank-line separator within the existing representation; `replace` overwrites its text; `append` creates a following system message/block; `skip` inserts only if absent. Whitespace-only original system text is absent.

## Data Flow and Concurrency

```mermaid
sequenceDiagram
    participant H as HTTP handler
    participant P as StagePlan
    participant E as Executor
    participant D as prompt_decorator
    participant A as Provider adapter
    H->>H: clone Fiber body once into Body
    P->>P: order; split request-body mutators into serial batches
    E->>E: if stage mutates body, move owned Body to OriginalBody and clone Body
    E->>D: read-only current folded Body + OriginalBody
    D->>D: copy/parse; validate original; decorate current
    alt observe
        D-->>E: no RequestBody, no rejection
    else enforce and original system absent
        D-->>E: PluginError 400 exact body
    else enforce
        D-->>E: newly allocated Result.RequestBody
        E->>E: assign RequestContext.Body
        E->>A: adapt folded source body to target
    end
```

`StagePlan` already sorts by priority, slug, and policy ID and permits at most one request-body mutator per parallel batch. Before any plugin in a pre-request stage executes, the executor scans that stage's batches. If any entry mutates the request body, it captures the original exactly once: an unset `OriginalBody` takes ownership of the existing `Body` slice, while a caller-provided `OriginalBody` is preserved. The executor then always clones `Body`, regardless of whether the caller-provided slices are identical, overlapping, or disjoint. Stages without a request-body mutator do not allocate or set `OriginalBody`. Policies marked parallel remain serialized against `prompt_decorator`; a safe read-only plugin may share its batch and sees the pre-plugin snapshot. The executor folds the result before the next mutator, which observes the decorated body.

## Invariants and Error Handling

- Decoration reads current folded `Body`; `require_system_message` reads only immutable `OriginalBody`.
- The proxy performs one body allocation. The executor performs the second allocation lazily only for a pre-request stage whose plan contains a request-body mutator, before read-only or mutating plugins can execute.
- The plugin never writes contexts or mutates input bytes, RawMessages, maps, or slices. Private parsed state and returned bytes do not alias input.
- Only executor result folding assigns `Body`. Observe returns no `RequestBody`.
- Roles are `system|user|assistant`; system role requires `position=system`. Content, strategy, combinations, and unknown config are validated strictly. Informational `scope` never overrides policy scope.
- Required-system enforce rejection is HTTP 400 with exactly `{"error":{"type":"system_message_required"}}`; malformed supported-source JSON returns a plugin error.

## File Changes

| File | Action | Description |
|---|---|---|
| `pkg/infra/plugins/promptdecorator/config.go` | Create | Strict configuration |
| `pkg/infra/plugins/promptdecorator/document.go` | Create | Private lossless transform |
| `pkg/infra/plugins/promptdecorator/plugin.go` | Create | Pure plugin execution/capabilities |
| `pkg/infra/plugins/promptdecorator/config_test.go` | Create | Validation matrix |
| `pkg/infra/plugins/promptdecorator/document_test.go` | Create | Semantics, fidelity, fuzz, alias safety |
| `pkg/infra/plugins/promptdecorator/plugin_test.go` | Create | Modes, original validation, exact errors |
| `pkg/infra/plugins/promptdecorator/composition_test.go` | Create | StagePlan/executor composition and non-aliasing |
| `pkg/infra/context/request_context.go` | Modify | Add immutable `OriginalBody` |
| `pkg/api/handler/http/proxy/proxy_handler.go` | Modify | Clone Fiber body once; leave original unset |
| `pkg/api/handler/http/proxy/proxy_handler_test.go` | Modify | One-copy creation and lazy-original contract |
| `pkg/app/plugins/executor.go` | Modify | Lazy pre-stage original capture and unconditional working-body clone |
| `pkg/app/plugins/executor_test.go` | Modify | Allocation, preservation, alias, sequential, and parallel coverage |
| `pkg/infra/providers/adapter/anthropic_adapter.go` | Modify | Decode text-block systems for translation |
| `pkg/infra/providers/adapter/anthropic_adapter_test.go` | Modify | Block translation |
| `pkg/infra/providers/adapter/bedrock_adapter_test.go` | Modify | Claude/OpenAI-compatible targets |
| `pkg/container/modules/plugins.go` | Modify | Register plugin |
| `pkg/app/plugins/catalog_metadata.go` | Modify | Catalog schema |
| `pkg/app/plugins/catalog_test.go` | Modify | Catalog expectations |
| `tests/functional/plugin_prompt_decorator_test.go` | Create | Scope/protocol/upstream behavior |

The planner and body-folding semantics do not change; the executor adds only lazy snapshot ownership before pre-request execution. No files are deleted.

## Testing, Compatibility, and Rollout

Unit tests prove one proxy body copy, no second allocation or `OriginalBody` without a mutator, lazy independent snapshots before all plugins in a mutating stage, preservation of caller-provided originals, and bidirectional non-aliasing. Composition tests combine preceding and following body mutators, including `parallel=true`, proving deterministic folding and immutable original validation; read-only parallel execution remains allowed. Adapter, functional, fuzz, and `go test -race ./...` coverage validates protocols, rich fields, Bedrock families, exact rejection, and no upstream call.

No migration is required. Ship dormant until policies reference the slug; rollback removes those policies. Risks remain raw-JSON fidelity, prompt growth, and an over-400-line implementation requiring reviewable task slices.

## Open Questions

None.
