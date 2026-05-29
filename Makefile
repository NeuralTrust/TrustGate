.PHONY: help build run run-admin run-proxy test test-race test-cover test-functional lint fmt tidy generate mocks tools \
        install-pre-commit \
        docker-build docker-push compose-up compose-down compose-logs

# --- Build metadata injected into the binary via -ldflags ------------------
APP_NAME      := agentgateway
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
	go build -ldflags "$(LDFLAGS)" -o bin/$(APP_NAME) ./cmd/agentgateway

run: run-proxy ## Build and run the proxy server (alias for run-proxy)

run-admin: build ## Build and run the admin server
	@$(info $(M) Running $(APP_NAME) admin ...)
	./bin/$(APP_NAME) admin

run-proxy: build ## Build and run the proxy server
	@$(info $(M) Running $(APP_NAME) proxy ...)
	./bin/$(APP_NAME) proxy

test: ## Run unit tests
	@$(info $(M) Running unit tests ...)
	go test -v ./...

test-race: ## Run unit tests with the race detector
	@$(info $(M) Running unit tests with -race ...)
	go test -race ./...

test-cover: ## Run unit tests with coverage profile
	@$(info $(M) Running unit tests with coverage ...)
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -func=coverage.out | tail -1

test-functional: ## Run functional tests against a real admin server (requires Postgres on localhost:5432)
	@$(info $(M) Running functional tests ...)
	go test -v -count=1 -timeout=120s ./tests/functional/...

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

mocks: ## Regenerate all mockery mocks across the codebase
	@$(info $(M) Regenerating mocks ...)
	@command -v mockery >/dev/null 2>&1 || { \
	  echo "mockery not found in PATH; run 'make tools' first" >&2; exit 1; \
	}
	go generate ./...

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
