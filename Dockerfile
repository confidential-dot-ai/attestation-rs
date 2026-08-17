FROM rust:1.94-bookworm AS chef
# Compiled once; the layer is reused until the base image or the pin changes.
RUN cargo install cargo-chef --locked --version 0.1.78
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
RUN apt-get update && apt-get install -y libtss2-dev && rm -rf /var/lib/apt/lists/*
# Dependency layer: keyed on the recipe (Cargo.toml/lock graph), so it is
# reused across source-only changes instead of rebuilding every crate.
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p attestation-api --bin attestation-api

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends libtss2-esys-3.0.2-0 libtss2-tctildr0 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/attestation-api /attestation-api

EXPOSE 8400

ENTRYPOINT ["/attestation-api"]
