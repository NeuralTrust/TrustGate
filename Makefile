.PHONY: build run stop deps test view-coverage

build:
	docker-compose build

run:
	docker-compose up -d

stop:
	docker-compose stop

deps:
	go mod tidy
	go mod vendor

test:
	go test ./... -v -cover -coverprofile=coverage.out

view-coverage:
	go tool cover -html=coverage.out
