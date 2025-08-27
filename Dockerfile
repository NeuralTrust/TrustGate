# Build stage
FROM golang:1.23-bullseye AS builder

WORKDIR /build

# Add build arguments
ARG VERSION
ARG GIT_COMMIT
ARG BUILD_DATE

# Install build dependencies (added build-base and librdkafka-dev)
RUN apt-get update && apt-get install -y librdkafka-dev git curl

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Verify module dependencies
RUN go mod verify

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -tags dynamic -ldflags "-X github.com/NeuralTrust/TrustGate/pkg/version.Version=${VERSION} \
                      -X github.com/NeuralTrust/TrustGate/pkg/version.GitCommit=${GIT_COMMIT} \
                      -X github.com/NeuralTrust/TrustGate/pkg/version.BuildDate=${BUILD_DATE}" \
    -o gateway ./cmd/gateway

# Final stage
FROM debian:bullseye-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata curl librdkafka1 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/gateway /app/
COPY config/ /app/config/

ENV GIN_MODE=release

COPY scripts/docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8080 8081 9090

ENTRYPOINT ["/app/docker-entrypoint.sh"]