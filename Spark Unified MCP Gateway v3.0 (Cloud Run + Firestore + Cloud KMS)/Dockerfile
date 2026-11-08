# ==============================================================================
# Spark Unified MCP Gateway v3.0 (spark-mcp-gateway)
# Production Multi-Stage Distroless Containerfile
# ==============================================================================
# Multi-stage build:
# Stage 1: Build static Go binary with Go 1.23 on Debian Bookworm
# Stage 2: Distroless minimal runtime (static-debian12:nonroot, uncompressed < 30 MB)
# ==============================================================================

# Stage 1: Build statically linked binary
FROM golang:1.23-bookworm AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true

# Copy gateway source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/

# Build static binary targeting linux/amd64 (Cloud Run architecture)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=3.0.0" \
    -o /out/spark-mcp-gateway \
    ./cmd/gateway

# Stage 2: Distroless static runtime
FROM gcr.io/distroless/static-debian12:nonroot

LABEL maintainer="Spark MCP Team" \
      description="Spark Unified MCP Gateway v3.0 on Cloud Run" \
      org.opencontainers.image.title="spark-mcp-gateway" \
      org.opencontainers.image.description="Unified MCP gateway broker for Google Cloud, GDK, GitHub, and Jira" \
      org.opencontainers.image.source="https://github.com/Aetherise-cloud/Google-Cloud-Project"

# Copy binary from builder stage
COPY --from=builder /out/spark-mcp-gateway /spark-mcp-gateway

# Enforce non-root execution (UID 65532:GID 65532)
USER nonroot:nonroot

# Expose Cloud Run default ingress port
EXPOSE 8080

# Execute gateway binary
ENTRYPOINT ["/spark-mcp-gateway"]
