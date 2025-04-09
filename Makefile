.PHONY: run run-functional
run:
	@echo "Starting the application..."
	docker-compose up -d

run-functional:
	@echo "Starting the application with all services..."
	docker-compose -f docker-compose.yaml -f docker-compose.functional.yaml up -d

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
lint:  ; $(info $(M) Running linter ...)	@
	golangci-lint run ./...

.PHONY: swagger
swagger:  ; $(info $(M) Generate Swagger file ...)	@
	swag init -g cmd/gateway/main.go

.PHONY: openapi
openapi:  ; $(info $(M) Generate OpenAPI file ...)	@
	swag init -g cmd/gateway/main.go
	swagger2openapi docs/swagger.json -o docs/openapi.json

.PHONY: create-kafka-topic
create-kafka-topic:
	docker-compose exec kafka \
		kafka-topics --create \
		--if-not-exists \
		--bootstrap-server kafka:9092 \
		--replication-factor 1 \
		--partitions 1 \
		--topic metrics


.PHONY: test-crt
test-crt:  ; $(info $(M) Testing nginx server ...)	@
	cd docker/nginx && curl -k https://localhost   --cert client.crt   --key client.key
