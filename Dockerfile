FROM rust:1-slim-bookworm AS builder
WORKDIR /source
COPY . .
RUN cargo build --release --workspace

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home wioos && mkdir -p /data && chown wioos:wioos /data
COPY --from=builder /source/target/release/wioos-runtime /usr/local/bin/wioos-runtime
ENV WIOOS_STATE_DIR=/data
USER wioos
EXPOSE 3000
CMD ["/usr/local/bin/wioos-runtime"]
