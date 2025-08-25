# Use the official Rust image as a builder
FROM rust:1.88 as builder

# Set the working directory
WORKDIR /usr/src/app

# Copy the manifests
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies only (this layer will be cached)
RUN cargo build --release

# Remove the dummy main.rs
RUN rm src/main.rs

# Copy the actual source code
COPY . .

# Build the application
RUN cargo build --release --bin vertix-backend

# Create a new stage with a minimal runtime image
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -r -s /bin/false app

# Copy the binary from the builder stage
COPY --from=builder /usr/src/app/target/release/vertix-backend /usr/local/bin/

# Change ownership to the app user
RUN chown app:app /usr/local/bin/vertix-backend

# Switch to the app user
USER app

# Expose the port
EXPOSE 8080

# Set the binary as the entrypoint
ENTRYPOINT ["/usr/local/bin/vertix-backend"]
