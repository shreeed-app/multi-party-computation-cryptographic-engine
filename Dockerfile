# Builder stage.
FROM rust:1-alpine AS builder

# Install necessary build dependencies.
RUN apk add --no-cache musl-dev protobuf

WORKDIR /app
COPY . .

RUN cargo build --release

# Final stage.
FROM scratch

# Copy the compiled binary from the builder stage.
COPY --from=builder /app/target/release/app /app

# Expose the gRPC port.
EXPOSE 50051

# Use a non-root user to run the application.
USER 65532:65532

ENTRYPOINT ["/app"]
