FROM rust:1.72-bookworm as builder

WORKDIR /usr/src/app
COPY . .

# Get the target triple of the current build environment
RUN echo "$(rustc -vV | sed -n 's|host: ||p')" > rust_target

RUN apt update && apt install -y openssl pkg-config libc6 build-essential cmake clang libclang-dev

# cargo under QEMU building for ARM can consumes 10s of GBs of RAM...
# Solution: https://users.rust-lang.org/t/cargo-uses-too-much-memory-being-run-in-qemu/76531/2
ENV CARGO_NET_GIT_FETCH_WITH_CLI true

# Will build and cache the binary and dependent crates in release mode
RUN --mount=type=cache,target=/usr/local/cargo,from=rust:latest,source=/usr/local/cargo \
    --mount=type=cache,target=target \
    cargo build --target $(cat rust_target) --release && mv ./target/$(cat rust_target)/release/nostr-wallet-connect-lnd ./nostr-wallet-connect-lnd

# Runtime image
FROM debian:bookworm-slim

RUN apt update && apt install -y openssl pkg-config libc6

# Run as "app" user
RUN useradd -ms /bin/bash app

USER app
WORKDIR /app

# Get compiled binaries from builder's cargo install directory
COPY --from=builder /usr/src/app/nostr-wallet-connect-lnd /app/nostr-wallet-connect-lnd

ENV VSS_PORT=8080
EXPOSE $VSS_PORT

# Run the app
CMD ./nostr-wallet-connect-lnd
