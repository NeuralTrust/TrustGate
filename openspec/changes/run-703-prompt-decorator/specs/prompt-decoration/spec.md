# Prompt Decoration Specification

## Requirements

### Requirement: Configuration

Configuration MUST reject unknown fields, invalid enums, blank content, invalid role-position-strategy pairings, and settings lacking decorators and `require_system_message`. Roles MUST be `system|user|assistant`; positions MUST be `start|end|after_system|before_last_user|system`. System role MUST occur only at system position, whose strategy MUST be `merge|replace|append|skip`. Scope MAY be `consumer|global` metadata. V1 MUST NOT add plugin-specific caps.

#### Scenario: Valid configuration
- GIVEN valid settings
- WHEN validated
- THEN accepted

#### Scenario: Invalid configuration
- GIVEN a schema violation
- WHEN validated
- THEN rejected

### Requirement: Ordered Placement

Entries MUST apply in order and observe prior results.

#### Scenario: Start and end
- GIVEN messages
- WHEN `start` or `end` runs
- THEN insertion uses index 0 or last+1

#### Scenario: After system
- GIVEN leading OpenAI systems, Anthropic system, or none
- WHEN `after_system` runs
- THEN insertion follows the prefix, uses message index 0 for top-level system, or starts

#### Scenario: Before last user
- GIVEN messages with or without users
- WHEN `before_last_user` runs
- THEN insertion precedes the final user or ends

### Requirement: System Strategies

Strategies MUST evaluate prior entries and SHALL insert when system is absent.

#### Scenario: Existing system strategies
- GIVEN string, block, or multiple system content
- WHEN a strategy runs
- THEN merge uses a blank line preserving representation; replace overwrites; append adds a following message/segment/block; skip does nothing

#### Scenario: Absent system
- GIVEN no system
- WHEN any strategy runs
- THEN content is inserted

### Requirement: Mode, Scope, and Compatibility

Enforce MUST decorate/reject; observe MUST neither mutate nor reject. Scope MUST follow policy ownership. `prompt_template` MUST remain unchanged. Templating, variables, and versioning MUST remain excluded.

#### Scenario: Enforce and observe
- GIVEN enforce and observe
- WHEN run
- THEN only enforce changes or rejects

#### Scenario: Consumer and global ownership
- GIVEN consumer or global ownership
- WHEN run
- THEN ownership determines scope

#### Scenario: Existing template policy
- GIVEN `prompt_template`
- WHEN decorator is introduced
- THEN template behavior is unchanged

### Requirement: Original System Enforcement

`require_system_message` MUST inspect immutable `OriginalBody`. Whitespace-only text SHALL be absent; any nonblank original string/block SHALL qualify.

#### Scenario: Missing original system
- GIVEN enforce without original system
- WHEN run
- THEN HTTP 400 returns exactly `{"error":{"type":"system_message_required"}}`
- AND upstream is not called

#### Scenario: Mutation cannot satisfy requirement
- GIVEN folded body gains system absent from original
- WHEN enforced
- THEN rejected

#### Scenario: Any original system qualifies
- GIVEN nonblank OpenAI or Anthropic string/block system
- WHEN enforced
- THEN processing continues

### Requirement: Pure Body Transformation

The decorator MUST read current folded body without mutating or assigning it, `RequestContext.Body`, or aliased bytes/maps. It MUST return separately allocated output only as `Result.RequestBody`. Executor MUST be sole writer and fold outputs. Planner MUST serialize body/content mutators through existing mutation capability in deterministic order; later mutators MUST read folded output. Planner-safe read-only plugins MAY run parallel.

#### Scenario: Input non-aliasing
- GIVEN aliased input
- WHEN decorated
- THEN every alias remains unchanged

#### Scenario: Separate result allocation
- GIVEN changed output
- WHEN returned
- THEN `Result.RequestBody` has independent storage

#### Scenario: No context write
- GIVEN `RequestContext.Body`
- WHEN decorated
- THEN plugin does not assign it; output exists only in result

#### Scenario: Sequential body-mutator composition
- GIVEN decorator before another body mutator
- WHEN the plan runs
- THEN planner serializes them and executor folds the first result
- AND the second deterministically receives folded output

### Requirement: Protocol Fidelity

Decoration MUST preserve untouched OpenAI/Anthropic source JSON. Adaptation SHALL follow.

#### Scenario: Source fidelity
- GIVEN strings, blocks, multiple systems, and unknown fields
- WHEN decorated
- THEN untouched JSON is lossless

#### Scenario: Bedrock translation
- GIVEN Bedrock Claude or OpenAI-compatible target
- WHEN translated
- THEN upstream contains decoration
- AND no Bedrock source route exists
