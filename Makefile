.PHONY: test
test:  ; $(info $(M) Running unit tests ...)	@ ## Run unit tests
	go test -v  -coverprofile coverage.out ./...

.PHONY: test-functional
test-functional: ## Run test with check race  and coverage
	go test -v ./tests/functional/... -tags=functional

.PHONY: generate-mocks
generate-mocks:  ; $(info $(M) Generating mocks ...)	@ ## Generate mocks
	go generate ./...