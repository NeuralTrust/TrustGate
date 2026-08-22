# Contributing to TrustGate

We love your input! Whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Adding examples
- Improving documentation

## Getting Started

**New to TrustGate?** Check out:
- [`.github/GOOD_FIRST_ISSUES.md`](.github/GOOD_FIRST_ISSUES.md) — Curated starter tasks with clear acceptance criteria
- [`examples/`](examples/) — Runnable examples you can extend

## We Develop with GitHub

We use GitHub to host code, track issues and feature requests, and accept pull requests.

## GitHub Flow

Pull requests are the best way to propose changes. We actively welcome your PRs:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation (`make docs`).
4. Ensure the test suite passes (`make test`).
5. Make sure your code lints (`make lint`) and is formatted (`make fmt`).
6. Issue that pull request!

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/TrustGate.git
cd TrustGate

# Copy the env template
cp .env.example .env

# Boot the local dev infra (Postgres, Redis, Kafka, Zookeeper)
make compose-up

# Run the admin and proxy in two separate terminals
make run-admin      # admin on :8080
make run-proxy      # proxy on :8081
make run-mcp        # mcp on :8082 (optional)
```

Before pushing, run the same checks CI runs:

```bash
make fmt            # gofmt + go vet
make lint           # golangci-lint
make test           # unit tests
make test-race      # unit tests with the race detector
```

Install the git pre-commit hook to run these automatically:

```bash
make install-pre-commit
```

## Project Architecture

The codebase follows a **hexagonal architecture**:

```
pkg/domain/     # entities, value objects, port interfaces
pkg/app/        # application services (use cases)
pkg/infra/      # adapters: providers, plugins, database, telemetry
pkg/api/        # HTTP handlers
pkg/server/     # Server wiring
pkg/container/  # dig DI modules
```

Key principles:
- Dependencies point inward (domain has no external deps)
- Dependency injection via [`dig`](https://github.com/uber-go/dig) under `pkg/container/modules/`
- Prefer self-documenting code over comments

## Adding Examples

We especially welcome new examples! Good candidates:
- Language SDKs (TypeScript, Go, Java, Ruby)
- Framework integrations (LangChain, LlamaIndex, CrewAI)
- Specific provider setups (Anthropic, Bedrock, Azure)

See [`examples/README.md`](examples/README.md) for the existing structure.

## Regenerating Mocks

If you change an interface that has a mock:

```bash
make gen-mocks
```

## License

When you submit code changes, your submissions are understood to be under the same [Apache 2.0 License](LICENSE) that covers the project.

## Report Bugs

We use GitHub issues to track bugs. Report one by [opening a new issue](https://github.com/NeuralTrust/TrustGate/issues/new/choose).

**Great bug reports** include:
- A quick summary
- Steps to reproduce (be specific!)
- Sample code or curl commands if possible
- What you expected vs. what actually happened
- TrustGate version (`curl localhost:8080/__/version`)

## Community

- [Slack](https://join.slack.com/t/neuraltrustcommunity/shared_invite/zt-2xl47cag6-_HFNpltIULnA3wh4R6AqBg) — Questions, discussions, help
- [GitHub Issues](https://github.com/NeuralTrust/TrustGate/issues) — Bugs and feature requests
- [Documentation](https://docs.neuraltrust.ai) — Guides and API reference
