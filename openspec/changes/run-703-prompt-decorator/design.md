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
| Snapshot original client bytes | One extra allocation | Choose; independently allocate `Body` and `OriginalBody` at HTTP context creation |

OpenAI edits raw `messages`; Anthropic edits raw top-level `system` and `messages`. Entries see prior entries in configuration order. Anchors remain: `start=0`, `end=len`, `after_system` follows the full leading system prefix/top-level system and otherwise starts at zero, and `before_last_user` falls back to end.

For `position=system`, `merge` uses a blank-line separator within the existing representation; `replace` overwrites its text; `append` creates a following system message/block; `skip` inserts only if absent. Whitespace-only original system text is absent.

## Data Flow and Concurrency

```mermaid
sequenceDiagram
    participant H as HTTP handler
    participant P as StagePlan
    participant E as Executor
    participant D as prompt_decorator
    participant A as Provider adapter
    H->>H: allocate Body and OriginalBody separately
    P->>P: order; split request-body mutators into serial batches
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

`StagePlan` already sorts by priority, slug, and policy ID and permits at most one request-body mutator per parallel batch. Thus policies marked parallel are still serialized against `prompt_decorator`; a safe read-only plugin may share its batch and sees that batch's input. The executor folds the result before the next mutator, which observes the decorated body. No executor or planner semantic change is planned; existing composition coverage is retained.

## Invariants and Error Handling

- Decoration reads current folded `Body`; `require_system_message` reads only immutable `OriginalBody`.
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
| `pkg/api/handler/http/proxy/proxy_handler.go` | Modify | Allocate independent bodies |
| `pkg/api/handler/http/proxy/proxy_handler_test.go` | Modify | Creation non-aliasing |
| `pkg/infra/providers/adapter/anthropic_adapter.go` | Modify | Decode text-block systems for translation |
| `pkg/infra/providers/adapter/anthropic_adapter_test.go` | Modify | Block translation |
| `pkg/infra/providers/adapter/bedrock_adapter_test.go` | Modify | Claude/OpenAI-compatible targets |
| `pkg/container/modules/plugins.go` | Modify | Register plugin |
| `pkg/app/plugins/catalog_metadata.go` | Modify | Catalog schema |
| `pkg/app/plugins/catalog_test.go` | Modify | Catalog expectations |
| `tests/functional/plugin_prompt_decorator_test.go` | Create | Scope/protocol/upstream behavior |

No executor/planner files or semantics change; no files are deleted.

## Testing, Compatibility, and Rollout

Unit tests mutate input/output after execution to prove bidirectional non-aliasing, verify input maps/bytes remain byte-identical, and cover every anchor/strategy/order. Composition tests combine preceding and following body mutators, including `parallel=true`, proving deterministic folding and immutable original validation; read-only parallel execution remains allowed. Adapter, functional, fuzz, and `go test -race ./...` coverage validates protocols, rich fields, Bedrock families, exact rejection, and no upstream call.

No migration is required. Ship dormant until policies reference the slug; rollback removes those policies. Risks remain raw-JSON fidelity, prompt growth, and an over-400-line implementation requiring reviewable task slices.

## Open Questions

None.
