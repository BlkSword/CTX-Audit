# Multi-stage build for CTX-Audit Rust Backend
# Stage 1: Build core library
FROM rust:1.75-alpine AS core-builder

# Install build dependencies
RUN apk add --no-cache musl-dev sqlite-dev

WORKDIR /app

# Copy core source
COPY core /app/core

# Build core library
WORKDIR /app/core
RUN cargo build --release

# Stage 2: Build web backend
FROM rust:1.75-alpine AS backend-builder

# Install build dependencies
RUN apk add --no-cache musl-dev sqlite-dev

WORKDIR /app

# Copy Cargo configs
COPY core /app/core
COPY web-backend /app/web-backend

# Copy pre-built core from previous stage
COPY --from=core-builder /app/core/target /app/core/target

# Build web-backend
WORKDIR /app/web-backend
RUN cargo build --release

# Stage 3: Runtime image
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache sqlite ca-certificates curl

WORKDIR /app

# Copy binary from builder
COPY --from=backend-builder /app/web-backend/target/release/deepaudit-web /app/deepaudit-web

# Create data directory
RUN mkdir -p /app/data

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["/app/deepaudit-web"]
