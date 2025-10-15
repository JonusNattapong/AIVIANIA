# Use the official Rust image as the base image
FROM rust:1.70-slim as builder

# Set the working directory
WORKDIR /app

# Install build dependencies required at build-time only (kept in builder stage)
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Copy manifest first to leverage Docker cache
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY src ./src

# Build the application in release mode using Cargo.lock for reproducible builds
RUN cargo build --release --locked

# Strip the binary to reduce size
RUN strip target/release/aiviania || true

# Use a more recent, minimal runtime image
FROM debian:bookworm-slim

# Create a non-root user for running the binary
RUN useradd --system --user-group --create-home appuser

# Install only runtime dependencies and ca-certificates, keep image small
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends \
  ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/aiviania /app/aiviania

# Ensure binary is owned by non-root user
RUN chown appuser:appuser /app/aiviania && chmod 750 /app/aiviania

# Switch to non-root user
USER appuser

# Expose the port the app runs on (adjust if needed)
EXPOSE 3000

# Healthcheck to help orchestrators detect unhealthy containers
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- --timeout=2 http://127.0.0.1:3000/healthz || exit 1

# Command to run the application
CMD ["/app/aiviania"]