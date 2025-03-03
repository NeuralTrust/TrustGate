.PHONY: test
test:  ; $(info $(M) Running unit tests ...)	@ ## Run unit tests
	go test -v  -coverprofile coverage.out ./...

.PHONY: generate-mocks
generate-mocks:  ; $(info $(M) Generating mocks ...)	@ ## Generate mocks
	go generate ./...