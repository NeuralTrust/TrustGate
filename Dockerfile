# syntax=docker/dockerfile:1.7
FROM golang:1.27-trixie@sha256:2f84bc93ecfb2689f782b153fdcd368b5a7ab96c1386c65cdaccf35e726d6a44 AS builder

WORKDIR /build

# CGO is off: the binary is fully static and runs on distroless "static". With
# cgo disabled Go uses its pure-Go DNS resolver, which reads /etc/resolv.conf
# (search domains, ndots) and /etc/hosts but ignores nsswitch.conf.
ENV GIT_TERMINAL_PROMPT=0 \
    CGO_ENABLED=0

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
COPY pkg/metrics/go.mod ./pkg/metrics/go.mod

RUN go mod download

COPY . .

RUN go mod verify

ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG MODULE=github.com/NeuralTrust/TrustGate

RUN go build \
    -trimpath \
    -ldflags "-s -w \
        -X ${MODULE}/pkg/version.Version=${VERSION} \
        -X ${MODULE}/pkg/version.Commit=${COMMIT} \
        -X ${MODULE}/pkg/version.BuildDate=${BUILD_DATE}" \
    -o /out/trustgate \
    ./cmd/trustgate

# "static" has no libc or loader, so a dependency that pulls cgo back in must
# fail here, not when the pod starts.
RUN if readelf -d /out/trustgate | grep -q NEEDED; then \
        echo "trustgate must be statically linked (CGO_ENABLED=0), readelf found NEEDED entries:" >&2; \
        readelf -d /out/trustgate >&2; \
        exit 1; \
    fi

# --- Runtime stage ---------------------------------------------------------
# distroless "static": CA certificates, tzdata and the nonroot user, no libc.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3 AS runtime

WORKDIR /app

COPY --from=builder /out/trustgate /app/trustgate

# Admin (8080) and Proxy (8081).
EXPOSE 8080 8081

USER nonroot:nonroot

# Override with `docker run <image> admin` (or set `args: ["admin"]` in
# the k8s manifest) to run the admin server in this container instead.
ENTRYPOINT ["/app/trustgate"]
CMD ["proxy"]
