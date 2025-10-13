# Use the official Rust image as the base image
FROM rust:1.70-slim as builder

# Set the working directory
WORKDIR /app

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY src ./src

# Build the application in release mode
RUN cargo build --release

# Use a smaller base image for the final stage
FROM debian:bullseye-slim

# Install runtime dependencies (if any)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/target/release/aiviania /app/aiviania

# Expose the port the app runs on (adjust if needed)
EXPOSE 3000

# Command to run the application
CMD ["./aiviania"]