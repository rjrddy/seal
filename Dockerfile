FROM rust:1.99.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked
FROM debian:bookworm-slim
RUN useradd --uid 10001 --create-home app && mkdir -p /app/data && chown app:app /app/data
WORKDIR /app
COPY --from=build /build/target/release/seal /usr/local/bin/seal
COPY web ./web
USER 10001
ENV SEAL_WEB=/app/web SEAL_ADDR=0.0.0.0:8093
EXPOSE 8093
CMD ["seal", "serve", "/app/data"]
