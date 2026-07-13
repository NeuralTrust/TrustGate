# Proposal: RUN-703 Prompt Decorator

## Intent

Add deterministic prompt decoration for consumer-scoped and global policies while preserving client JSON fidelity and validating required system content against the original request.

## Scope

### In Scope
- Add `prompt_decorator`; leave `prompt_template` unchanged.
- Accept ordered `decorators[]` with role, nonblank content, positions `start|end|after_system|before_last_user|system`, and system strategies `merge|replace|append|skip`.
- Support enforce/observe; observe neither mutates nor rejects.
- Validate optional `settings.scope` as metadata; effective scope remains policy-owned.
- Handle OpenAI and Anthropic top-level system/messages losslessly; cover Bedrock Claude/OpenAI-compatible targets.
- Allocate immutable `OriginalBody` at HTTP creation. Enforce `require_system_message` before injection with HTTP 400 and `{"error":{"type":"system_message_required"}}` when originally absent/blank.

### Out of Scope
- Templating, variables, versioning, Mustache/Jinja, executable transforms, Bedrock source routes, and unnamed provider families.

## Capabilities

### New Capabilities
- `prompt-decoration`: Static, ordered, protocol-aware prompt placement and original-system enforcement.

### Modified Capabilities
- None.

## Approach

Implement a pure pre-request transform in `pkg/infra/plugins/promptdecorator/`. Build a separately allocated, lossless source representation from immutable `ExecInput.Request.Body` and backing bytes/maps; return it only via `Result.RequestBody`. Declare request-body mutation so StagePlan serializes it against all body/content mutators. The executor alone folds/writes bodies, giving each later mutator the prior result; read-only plugins may share planner-safe batches. Apply decorators sequentially: `start` is index 0; `end` follows the last message; `after_system` follows the leading system prefix or start; `before_last_user` precedes the final user or falls back to end. Adapt providers afterward. Merge preserves representation with a blank line; replace overwrites; append adds a distinct following segment/block; skip inserts only when absent. Roles are system/user/assistant; system is valid only at `position=system`.

## Affected Areas

| Area | Impact |
|---|---|
| `pkg/infra/plugins/promptdecorator/` | Pure transform and tests |
| `pkg/infra/context/`, HTTP creation | Immutable original body |
| `pkg/container/modules/plugins.go` | Registration |
| `pkg/app/plugins/catalog_metadata.go` | Catalog/schema |
| `tests/functional/` | Scope/protocol QA |

## Acceptance Criteria

- Tests cover every position/strategy/fallback, config ordering, consumer/global scope, invalid config, OpenAI, Anthropic string/block systems, Bedrock Claude/OpenAI-compatible targets, and unrelated-JSON retention.
- Tests prove immutable `OriginalBody` governs validation, injection cannot satisfy it, whitespace is absent, rejection/upstream behavior is exact, input storage is neither changed nor aliased, and composition with another body mutator follows executor-folded order.

## Risks

- Raw JSON surgery may corrupt rich blocks; mitigate with losslessness fixtures and fuzz tests.
- Prompt growth affects latency/tokens; retain existing request-size controls.
- Coexistence with other mutators can surprise ordering; preserve StagePlan ordering and immutable original validation.

## Migration, Rollout, and Rollback

No schema migration or existing-plugin behavior change is required. Ship disabled until policies reference the new slug; verify focused unit, race, catalog, adapter, and functional suites. Roll back by removing those policies and reverting registration/plugin code; stored unrelated policies remain compatible.
