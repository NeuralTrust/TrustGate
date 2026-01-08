# Build stage
FROM golang:1.25-bookworm AS builder

WORKDIR /build

# Add build arguments
ARG VERSION
ARG GIT_COMMIT
ARG BUILD_DATE
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install build dependencies (use precompiled librdkafka-dev instead of building from source)
RUN apt-get update && apt-get install -y git ca-certificates librdkafka-dev && rm -rf /var/lib/apt/lists/*

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Verify module dependencies
RUN go mod verify

# Build the application with dynamic linking
RUN CGO_ENABLED=1 GOOS=linux go build -tags dynamic \
    -ldflags "-X github.com/NeuralTrust/TrustGate/pkg/version.Version=${VERSION} \
              -X github.com/NeuralTrust/TrustGate/pkg/version.GitCommit=${GIT_COMMIT} \
              -X github.com/NeuralTrust/TrustGate/pkg/version.BuildDate=${BUILD_DATE}" \
    -o gateway ./cmd/gateway

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (use precompiled librdkafka1 instead of building from source)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    curl \
    librdkafka1 \
    libssl3 \
    libsasl2-2 \
    zlib1g \
    libzstd1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/gateway /app/

ENV GIN_MODE=release

COPY scripts/docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8080 8081 9090

ENTRYPOINT ["/app/docker-entrypoint.sh"]