.PHONY: test
test:  ; $(info $(M) Running unit tests ...)	@ ## Run unit tests
	go test -v ./pkg/... -coverprofile coverage.out ./...

.PHONY: test-functional
test-functional: ## Run test with check race  and coverage
	go test -v ./tests/functional/... -tags=functional

.PHONY: generate-mocks
generate-mocks:  ; $(info $(M) Generating mocks ...)	@ ## Generate mocks
	go generate ./...

.PHONY: lint
lint:  ; $(info $(M) Running linter ...)	@ ## Run linter
	golangci-lint run ./...

.PHONY: swagger
swagger:  ; $(info $(M) Generate Swagger file ...)	@ ## Run linter
	swag init -g cmd/gateway/main.go