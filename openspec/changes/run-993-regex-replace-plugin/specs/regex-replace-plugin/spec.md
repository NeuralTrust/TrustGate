# Regex Replace Plugin Specification

## Purpose

Provider-agnostic RE2 text rewriting inside the TrustGate gateway on exactly one
leg per instance: the request prompt (`pre_request`) XOR the LLM response
(`pre_response`). Redaction/normalization transform, not an access gate.

## Requirements

### Requirement: Descriptor & stage registration

The plugin MUST register ONE descriptor with `SupportedStages=[pre_request, pre_response]`,
`MandatoryStages=[]`, catalog group `Guardrails`, and MUST be covered by a dedicated
schema test. Following the existing Guardrails convention (`bedrock_guardrail`,
`azure_content_safety`, `trustguard`), the slug is validated by a standalone
`TestRegexReplaceSchema` and is deliberately NOT added to `catalog_test` `builtinSlugs`
(that curated fixture drives `TestCatalogService_EntriesHaveStagesAndSchema`, whose
`len(entries)==len(visibleSlugs)` assertion would break otherwise).

#### Scenario: Catalog exposure
- GIVEN the plugin registry is initialized
- WHEN the catalog is listed
- THEN `regex_replace` appears under group `Guardrails` with both supported stages
- AND `TestRegexReplaceSchema` asserts the catalog metadata (target enum + rules schema)

### Requirement: Config validation

`ValidateConfig` MUST reject configs where: `target` is missing or not in `{request,response}`;
`rules` is empty/absent; any rule lacks `pattern`; or any `pattern` fails `regexp.Compile`
(including RE2-unsupported backreferences/lookaround). Valid configs MUST be accepted.

#### Scenario: target required and enum-checked
- GIVEN a config with no `target` or `target: both`
- WHEN `ValidateConfig` runs
- THEN it returns an error

#### Scenario: rules must be non-empty
- GIVEN a config with `rules: []`
- WHEN `ValidateConfig` runs
- THEN it returns an error

#### Scenario: invalid regex rejected
- GIVEN a rule `pattern` that is invalid RE2 (e.g. `(?=x)` lookahead or `\1` backreference)
- WHEN `ValidateConfig` runs
- THEN it returns the `regexp.Compile` error and the config is rejected

#### Scenario: valid config accepted
- GIVEN `target: request` with one rule whose `pattern` compiles
- WHEN `ValidateConfig` runs
- THEN it returns no error

### Requirement: Request-leg rewrite (pre_request)

When `target=request` and mode is enforce on `pre_request`, the plugin MUST decode the
request via the adapter Registry, apply rules to top-level `System` and every
`Messages[].Content`, re-encode, and return `Result{RequestBody}`. Non-text fields MUST be
untouched. On `pre_response` it MUST no-op.

#### Scenario: prompt masked before upstream
- GIVEN `target=request` with a rule masking emails
- WHEN a request with an email in `System` and message content reaches `pre_request`
- THEN the returned `RequestBody` has both occurrences masked
- AND roles, model, and other fields are unchanged

#### Scenario: no-op on wrong stage
- GIVEN `target=request`
- WHEN `Execute` runs on `pre_response`
- THEN the response body is unchanged and no rewrite occurs

### Requirement: Response-leg rewrite (pre_response)

When `target=response` and mode is enforce on `pre_response`, the plugin MUST decode the
response, rewrite `CanonicalResponse.Content`, re-encode, and return
`Result{Body, StopUpstream:true}` (never `Result.ResponseBody`). On `pre_request` it MUST
no-op. Streaming responses MUST pass through unchanged.

#### Scenario: response rewritten via StopUpstream
- GIVEN `target=response` with a normalization rule
- WHEN a non-streaming response reaches `pre_response`
- THEN the plugin returns `Body` with rewritten content and `StopUpstream=true`

#### Scenario: streaming pass-through
- GIVEN `target=response` and `in.Response.Streaming` is true
- WHEN `Execute` runs
- THEN the body passes through unchanged with no rewrite

#### Scenario: no-op on wrong stage
- GIVEN `target=response`
- WHEN `Execute` runs on `pre_request`
- THEN the request body is unchanged

### Requirement: Ordered chained rules

Rules MUST apply in declaration order; the output of rule N MUST be the input to rule N+1.
Each rule compiles `case_insensitive`→`(?i)`, `multiline`→`(?m)` into the pattern and uses
Go `$1`/`${name}` replacement via `ReplaceAllString`.

#### Scenario: chaining
- GIVEN rules [replace `a`→`b`, then `b`→`c`]
- WHEN applied to text `a`
- THEN the result is `c`

#### Scenario: capture-group replacement
- GIVEN a rule with a capture group and replacement `$1`
- WHEN applied to matching text
- THEN the captured group is substituted into the output

### Requirement: Modes

Mode `enforce` (mandatory) MUST mutate the body. Mode `observe` MUST compute matches and
emit telemetry only, returning the body unmutated.

#### Scenario: observe does not mutate
- GIVEN mode `observe` with a matching rule
- WHEN `Execute` runs
- THEN telemetry reflects the match and the body is returned unchanged

### Requirement: Provider-agnostic behavior

All rewrite behavior MUST hold across providers (openai, anthropic, gemini, bedrock,
mistral) through the canonical model, since text is read/written via the adapter Registry.

#### Scenario: cross-provider parity
- GIVEN the same rule and equivalent text
- WHEN requests/responses are processed for each provider
- THEN each is decoded, rewritten, and re-encoded with the same textual result

### Requirement: Edge-case behavior

The plugin MUST handle: no match (body unchanged); empty `replacement` (matched text
deleted); multiple rules applied cumulatively.

#### Scenario: no match is a no-op
- GIVEN a rule that matches nothing in the text
- WHEN `Execute` runs
- THEN the body is byte-identical to the input

#### Scenario: empty replacement deletes
- GIVEN a rule with `replacement: ""`
- WHEN applied to matching text
- THEN the matched substring is removed

### Requirement: Non-functional

Production code MUST contain no code comments. The plugin MUST ship `-race`-clean unit tests
covering config validation, both legs, modes, chaining, and edge cases, plus one functional
test exercising request and response rewrite.

#### Scenario: coverage gate
- GIVEN the test suite
- WHEN `go test -race ./...` runs
- THEN unit and functional tests pass and no production file contains comments
