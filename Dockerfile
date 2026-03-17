# Dockerfile.scanner — multi-stage build for the scanner agent container image.
#
# Build args for version stamping (pass from CI):
#   --build-arg VERSION=$(git describe --tags --always)
#   --build-arg COMMIT=$(git rev-parse --short HEAD)
#   --build-arg BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ─── Stage 1: Go binary ───────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w \
      -X github.com/tlsentinel/tlsentinel-scanner/internal/version.Version=${VERSION} \
      -X github.com/tlsentinel/tlsentinel-scanner/internal/version.Commit=${COMMIT} \
      -X github.com/tlsentinel/tlsentinel-scanner/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/scanner ./cmd/scanner

# ─── Stage 2: minimal runtime image ──────────────────────────────────────────
FROM gcr.io/distroless/static-debian12

COPY --from=builder /out/scanner /scanner

ENTRYPOINT ["/scanner"]
