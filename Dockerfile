# Build stage
FROM golang:1.25-bookworm AS builder

WORKDIR /build

# Add build arguments
ARG VERSION
ARG GIT_COMMIT
ARG BUILD_DATE
ARG TARGETPLATFORM
ARG BUILDPLATFORM

# Install build dependencies and build librdkafka from source
RUN apt-get update && \
    apt-get install -y \
        git \
        curl \
        build-essential \
        zlib1g-dev \
        libssl-dev \
        libsasl2-dev \
        libzstd-dev \
        pkg-config \
        cmake && \
    git clone --depth 1 --branch v2.3.0 https://github.com/confluentinc/librdkafka.git && \
    cd librdkafka && \
    ./configure --prefix=/usr && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf librdkafka && \
    rm -rf /var/lib/apt/lists/*

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

# Install runtime dependencies and librdkafka from source
RUN apt-get update && \
    apt-get install -y \
        ca-certificates \
        tzdata \
        curl \
        libssl3 \
        libsasl2-2 \
        zlib1g \
        libzstd1 \
        build-essential \
        git \
        cmake && \
    git clone --depth 1 --branch v2.3.0 https://github.com/confluentinc/librdkafka.git && \
    cd librdkafka && \
    ./configure --prefix=/usr && \
    make -j$(nproc) && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf librdkafka && \
    apt-get remove -y build-essential git cmake && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/gateway /app/
COPY config/ /app/config/

ENV GIN_MODE=release

COPY scripts/docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

EXPOSE 8080 8081 9090

ENTRYPOINT ["/app/docker-entrypoint.sh"]