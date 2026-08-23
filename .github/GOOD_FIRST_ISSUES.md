# Good First Issues

Curated tasks for new contributors. Each has clear scope and acceptance criteria.

If you'd like to work on one, open a GitHub issue referencing this task so others know it's in progress.

---

## 1. Add TypeScript/Node.js SDK Example

**Area:** Examples  
**Difficulty:** Easy  
**Skills:** TypeScript, Node.js

### Description

Add a TypeScript example showing how to use the OpenAI Node.js SDK through TrustGate, similar to the existing Python example.

### Acceptance Criteria

- [ ] Create `examples/openai-sdk-typescript/` directory
- [ ] Add `README.md` with setup and usage instructions
- [ ] Add `chat.ts` that mirrors the Python `chat.py` functionality
- [ ] Add `package.json` with `openai` dependency
- [ ] Add `tsconfig.json` for TypeScript compilation
- [ ] Test that it works against a running TrustGate instance

### References

- [Existing Python example](../examples/openai-sdk/)
- [OpenAI Node.js SDK](https://github.com/openai/openai-node)

---

## 2. Add Anthropic SDK Example

**Area:** Examples  
**Difficulty:** Easy  
**Skills:** Python

### Description

Add a Python example showing how to use the Anthropic SDK through TrustGate's `/v1/messages` endpoint.

### Acceptance Criteria

- [ ] Create `examples/anthropic-sdk/` directory
- [ ] Add `README.md` explaining Anthropic routing through TrustGate
- [ ] Add `chat.py` using the Anthropic Python SDK
- [ ] Add `requirements.txt` with `anthropic` dependency
- [ ] Document registry setup for Anthropic provider
- [ ] Test against a running TrustGate with Anthropic registry

### References

- [Providers table in README](../README.md#providers)
- [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python)

---

## 3. Document All Plugin Configuration Options

**Area:** Documentation  
**Difficulty:** Easy-Medium  
**Skills:** Technical writing, Go (to read source)

### Description

Create a comprehensive plugin configuration reference documenting all available settings for each built-in plugin.

### Acceptance Criteria

- [ ] Create `docs/plugins/` directory
- [ ] Add individual docs for: `ratelimit`, `tokenratelimit`, `requestsize`, `semanticcache`, `cors`
- [ ] Document all configuration fields with types and defaults
- [ ] Include example JSON snippets for each plugin
- [ ] Link from main README's Plugins section

### References

- [Plugin source](../pkg/infra/plugins/)
- [Plugins table in README](../README.md#plugins)

---

## 4. Add Go Client Example

**Area:** Examples  
**Difficulty:** Medium  
**Skills:** Go

### Description

Add a Go example showing how to call TrustGate's proxy using the `sashabaranov/go-openai` library or standard `net/http`.

### Acceptance Criteria

- [ ] Create `examples/go-client/` directory
- [ ] Add `README.md` with setup instructions
- [ ] Add `main.go` demonstrating a chat completion
- [ ] Add `go.mod` with dependencies
- [ ] Show how to set custom headers (`X-AG-Gateway-Slug`, `X-AG-API-Key`)
- [ ] Test against a running TrustGate

### References

- [go-openai library](https://github.com/sashabaranov/go-openai)

---

## 5. Improve Error Messages in Admin API

**Area:** Core / Admin API  
**Difficulty:** Medium  
**Skills:** Go

### Description

Audit Admin API endpoints and improve error messages to be more actionable. Many current errors are generic; they should explain what went wrong and how to fix it.

### Acceptance Criteria

- [ ] Identify 5+ endpoints with unclear error responses
- [ ] Update error messages to include:
  - What failed
  - Why it failed (validation, not found, auth)
  - How to fix it (when possible)
- [ ] Add tests for the improved error cases
- [ ] Keep errors secure (don't leak internal details)

### References

- [API handlers](../pkg/api/handler/http/)
- [Domain errors](../pkg/domain/)

---

## How to Contribute

1. **Comment on or open an issue** indicating you want to work on a task
2. **Fork the repository** and create a branch
3. **Follow the development setup** in [CONTRIBUTING.md](../CONTRIBUTING.md)
4. **Open a PR** referencing the issue

Questions? Join our [Slack community](https://join.slack.com/t/neuraltrustcommunity/shared_invite/zt-2xl47cag6-_HFNpltIULnA3wh4R6AqBg).
