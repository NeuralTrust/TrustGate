# Build stage
FROM golang:1.23-bullseye AS builder

WORKDIR /build

# Add build arguments
ARG VERSION
ARG GIT_COMMIT
ARG BUILD_DATE

# Install build dependencies (added build-base and librdkafka-dev)
RUN apt-get update && apt-get install -y librdkafka-dev git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Verify module dependencies
RUN go mod verify

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags "-X github.com/NeuralTrust/TrustGate/pkg/version.Version=${VERSION} \
                      -X github.com/NeuralTrust/TrustGate/pkg/version.GitCommit=${GIT_COMMIT} \
                      -X github.com/NeuralTrust/TrustGate/pkg/version.BuildDate=${BUILD_DATE}" \
    -o gateway ./cmd/gateway

# Final stage
FROM alpine:3.18

WORKDIR /app

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy binary and config files
COPY --from=builder /build/gateway /app/
COPY config/ /app/config/

# Set environment variables
ENV GIN_MODE=release

# Add entrypoint script
COPY scripts/docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

# Expose API and metrics ports
EXPOSE 8080 8081 9090

ENTRYPOINT ["/app/docker-entrypoint.sh"] 