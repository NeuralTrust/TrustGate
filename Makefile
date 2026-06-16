.PHONY: help build run run-admin run-proxy run-mcp run-all run-proxy-sandbox run-servers up down logs local-dns test test-race test-cover test-functional test-repositories lint fmt tidy generate gen-mocks tools swagger openapi docs license license-check \
        install-pre-commit \
        docker-build docker-push compose-up compose-down compose-logs

# --- Build metadata injected into the binary via -ldflags ------------------
APP_NAME      := trustgate
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")
COMMIT        ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
MODULE        := github.com/NeuralTrust/AgentGateway
LDFLAGS       := -X $(MODULE)/pkg/version.Version=$(VERSION) \
                 -X $(MODULE)/pkg/version.Commit=$(COMMIT) \
                 -X $(MODULE)/pkg/version.BuildDate=$(BUILD_DATE)

DOCKER_IMAGE  ?= ghcr.io/neuraltrust/agentgateway
DOCKER_TAG    ?= $(VERSION)

M := $(shell printf "\033[34;1m▶\033[0m")

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the agentgateway binary into ./bin/
	@$(info $(M) Building $(APP_NAME) $(VERSION) ...)
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME) ./cmd/trustgate

run: run-proxy ## Build and run the proxy server (alias for run-proxy)

run-admin: build ## Build and run the admin server
	@$(info $(M) Running $(APP_NAME) admin ...)
	./bin/$(APP_NAME) admin

run-proxy: build ## Build and run the proxy server
	@$(info $(M) Running $(APP_NAME) proxy ...)
	./bin/$(APP_NAME) proxy

run-mcp: build ## Build and run the MCP server
	@$(info $(M) Running $(APP_NAME) mcp ...)
	./bin/$(APP_NAME) mcp

run-all: build ## Build and run admin + proxy together in one process (single-node)
	@$(info $(M) Running $(APP_NAME) admin + proxy ...)
	./bin/$(APP_NAME) run

run-proxy-sandbox: build ## Run the proxy resolving gateways from {slug}.gw.neuraltrust.sandbox (see local-dns)
	@$(info $(M) Running $(APP_NAME) proxy with sandbox base domain ...)
	GATEWAY_BASE_DOMAIN=gw.neuraltrust.sandbox ./bin/$(APP_NAME) proxy

local-dns: ## Point *.gw.neuraltrust.sandbox to 127.0.0.1 via dnsmasq (macOS, requires sudo)
	@$(info $(M) Configuring local sandbox DNS ...)
	./scripts/setup-local-subdomains.sh

run-servers: up ## Alias for 'up': start the full stack + admin & proxy in docker

up: ## One command to bring up everything (infra + admin & proxy) in Docker
	@$(info $(M) Bringing up the full AgentGateway stack ...)
	docker compose -f docker-compose.yaml -f docker-compose.api.yaml up -d --build
	@echo ""
	@echo "  AgentGateway is up:"
	@echo "    Admin  -> http://localhost:8080  (healthz: /healthz)"
	@echo "    Proxy  -> http://localhost:8081  (healthz: /healthz)"
	@echo "  Tail logs with 'make logs', tear down with 'make down'."

down: ## Tear down the full stack and remove volumes
	@$(info $(M) Tearing down the full AgentGateway stack ...)
	docker compose -f docker-compose.yaml -f docker-compose.api.yaml down -v

logs: ## Tail logs from the full stack
	docker compose -f docker-compose.yaml -f docker-compose.api.yaml logs -f --tail=200

test: ## Run unit tests
	@$(info $(M) Running unit tests ...)
	go test -cover -v ./pkg/...

test-race: ## Run unit tests with the race detector
	@$(info $(M) Running unit tests with -race ...)
	go test -race ./pkg/...

test-cover: ## Run unit tests with coverage profile
	@$(info $(M) Running unit tests with coverage ...)
	go test -race -coverprofile=coverage.out -covermode=atomic ./pkg/...
	go tool cover -func=coverage.out | tail -1

test-functional: ## Run functional tests against a real admin server (requires Postgres on localhost:5432)
	@$(info $(M) Running functional tests ...)
	go test -tags functional -v -count=1 -timeout=120s ./tests/functional/...

test-repositories: ## Run repository integration tests (requires PG_TEST_URL pointing at a disposable database)
	@$(info $(M) Running repository integration tests ...)
	go test -tags functional -v -count=1 -p 1 -timeout=120s ./tests/functional/repositories/...

lint: ## Run golangci-lint
	@$(info $(M) Running golangci-lint ...)
	@PATH="$$HOME/go/bin:$$PATH" golangci-lint run ./...

fmt: ## Run gofmt + go vet
	@$(info $(M) Running gofmt + go vet ...)
	gofmt -s -w .
	go vet ./...

tidy: ## Run go mod tidy
	@$(info $(M) Tidying modules ...)
	go mod tidy

generate: ## Run go generate
	@$(info $(M) Running go generate ...)
	go generate ./...

tools: ## Install Go dev tools pinned in tools/tools.go
	@$(info $(M) Installing dev tools ...)
	go install github.com/vektra/mockery/v2
	go install github.com/swaggo/swag/cmd/swag
	go install github.com/google/addlicense

swagger: ## Generate the Swagger 2.0 spec (docs/swagger.{json,yaml} + docs.go) from handler annotations
	@$(info $(M) Generating Swagger 2.0 spec ...)
	@command -v swag >/dev/null 2>&1 || { \
	  echo "swag not found in PATH; run 'make tools' first" >&2; exit 1; \
	}
	swag init -g cmd/trustgate/main.go --parseDependency --parseInternal --output docs

openapi: swagger ## Convert the Swagger 2.0 spec into an OpenAPI 3 spec (docs/openapi.json)
	@$(info $(M) Converting Swagger 2.0 -> OpenAPI 3 ...)
	@command -v swagger2openapi >/dev/null 2>&1 || { \
	  echo "swagger2openapi not found in PATH; install it with 'npm i -g swagger2openapi'" >&2; exit 1; \
	}
	swagger2openapi docs/swagger.json -o docs/openapi.json

docs: openapi ## Regenerate all API docs (Swagger 2.0 + OpenAPI 3)

gen-mocks: ## Regenerate all mockery mocks across the codebase
	@$(info $(M) Regenerating mocks ...)
	@command -v mockery >/dev/null 2>&1 || { \
	  echo "mockery not found in PATH; run 'make tools' first" >&2; exit 1; \
	}
	go generate ./...

license: ## Add Apache 2.0 license headers to source files
	@$(info $(M) Adding Apache 2.0 license headers ...)
	@command -v addlicense >/dev/null 2>&1 || { echo "addlicense not found in PATH; run 'make tools' first" >&2; exit 1; }
	addlicense -v -c "NeuralTrust" -y 2026 -l apache -ignore '**/mocks/**' cmd pkg tools

license-check: ## Verify every source file has a license header
	@$(info $(M) Checking license headers ...)
	@command -v addlicense >/dev/null 2>&1 || { echo "addlicense not found in PATH; run 'make tools' first" >&2; exit 1; }
	addlicense -check -c "NeuralTrust" -y 2026 -l apache -ignore '**/mocks/**' cmd pkg tools

install-pre-commit: ## Install the git pre-commit hook
	@$(info $(M) Installing pre-commit hook ...)
	@mkdir -p .git/hooks
	@cp scripts/pre-commit.sh .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "Pre-commit hook installed successfully!"

docker-build: ## Build the production docker image
	@$(info $(M) Building docker image $(DOCKER_IMAGE):$(DOCKER_TAG) ...)
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		.

docker-push: docker-build ## Push the docker image
	@$(info $(M) Pushing $(DOCKER_IMAGE):$(DOCKER_TAG) ...)
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest

compose-up: ## Start the local dev stack via docker compose
	@$(info $(M) Starting docker compose stack ...)
	docker compose up -d --build

compose-down: ## Stop the local dev stack and remove volumes
	@$(info $(M) Stopping docker compose stack ...)
	docker compose down -v

compose-logs: ## Tail logs from the local dev stack
	docker compose logs -f --tail=200
