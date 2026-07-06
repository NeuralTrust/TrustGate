# syntax=docker/dockerfile:1.7
FROM golang:1.26.4-bookworm AS builder

WORKDIR /build

# CGO is required: confluent-kafka-go is a cgo binding to librdkafka. The
# bundled glibc librdkafka (statically linked into the binary) ships for both
# amd64 and arm64, so we build against glibc and run on distroless base.
ENV GOPRIVATE=github.com/NeuralTrust/* \
    GONOPROXY=github.com/NeuralTrust/* \
    GONOSUMDB=github.com/NeuralTrust/* \
    GIT_TERMINAL_PROMPT=0 \
    CGO_ENABLED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
        gcc \
        libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
COPY pkg/metrics/go.mod ./pkg/metrics/go.mod

ARG GITHUB_TOKEN
RUN if [ -n "$GITHUB_TOKEN" ]; then \
        git config --global url."https://${GITHUB_TOKEN}@github.com/".insteadOf "https://github.com/" ; \
    fi && \
    go mod download

COPY . .

RUN go mod verify

ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG MODULE=github.com/NeuralTrust/AgentGateway

RUN go build \
    -trimpath \
    -ldflags "-s -w \
        -X ${MODULE}/pkg/version.Version=${VERSION} \
        -X ${MODULE}/pkg/version.Commit=${COMMIT} \
        -X ${MODULE}/pkg/version.BuildDate=${BUILD_DATE}" \
    -o /out/trustgate \
    ./cmd/trustgate

# --- Runtime stage ---------------------------------------------------------
# distroless "base" (not "static") because the cgo binary dynamically links glibc.
FROM gcr.io/distroless/base-debian12:nonroot AS runtime

WORKDIR /app

COPY --from=builder /out/trustgate /app/trustgate

# Admin (8080) and Proxy (8081).
EXPOSE 8080 8081

USER nonroot:nonroot

# Override with `docker run <image> admin` (or set `args: ["admin"]` in
# the k8s manifest) to run the admin server in this container instead.
ENTRYPOINT ["/app/trustgate"]
CMD ["proxy"]
