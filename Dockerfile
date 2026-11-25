FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

ENV CARGO_NET_RETRY=3
RUN cargo rustc --release --locked --bin raksa-hostguard -- -C target-feature=+crt-static

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /src/target/release/raksa-hostguard /raksa-hostguard

USER nonroot:nonroot
ENTRYPOINT ["/raksa-hostguard"]
CMD ["version"]
