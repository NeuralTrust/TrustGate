# Contributing to TrustGate

We love your input! We want to make contributing to this project as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## We Develop with GitHub

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## We Use [GitHub Flow](https://guides.github.com/introduction/flow/index.html), So All Code Changes Happen Through Pull Requests

Pull requests are the best way to propose changes to the codebase (we use [GitHub Flow](https://guides.github.com/introduction/flow/index.html)). We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation (`make docs`).
4. Ensure the test suite passes (`make test`).
5. Make sure your code lints (`make lint`) and is formatted (`make fmt`).
6. Issue that pull request!

## Development Setup

```bash
# Copy the env template
cp .env.example .env

# Boot the local dev infra (Postgres, Redis, Kafka, Zookeeper)
make compose-up

# Run the admin and proxy in two separate terminals
make run-admin      # admin on :8080
make run-proxy      # proxy on :8081
```

Before pushing, run the same checks CI runs:

```bash
make fmt            # gofmt + go vet
make lint           # golangci-lint
make test           # unit tests
make test-race      # unit tests with the race detector
```

You can install the git pre-commit hook to run these automatically:

```bash
make install-pre-commit
```

## Coding Conventions

- The codebase follows a **hexagonal architecture**: `domain` (entities, ports), `app` (use cases), `infra` (adapters), `api` (HTTP handlers) and `server` (wiring). Keep dependencies pointing inward.
- Dependency injection is wired with [`dig`](https://github.com/uber-go/dig) under `pkg/container/modules/`, one module per context.
- Prefer self-documenting code over comments; only comment non-obvious intent or trade-offs.
- Regenerate mocks with `make gen-mocks` when you change an interface that has a mock.

## Any contributions you make will be under the Apache 2.0 Software License

In short, when you submit code changes, your submissions are understood to be under the same [Apache 2.0 License](LICENSE) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issues](https://github.com/NeuralTrust/TrustGate/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/NeuralTrust/TrustGate/issues/new); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

People *love* thorough bug reports. We're not even kidding.

## License

By contributing, you agree that your contributions will be licensed under its Apache 2.0 License.
