# ---- Build stage: bien dich Rust ----
FROM rust:1-bookworm AS builder

# aws-lc-rs (release) can cmake + perl + nasm. LUU Y: ban release KHONG cho
# dung AWS_LC_SYS_NO_ASM -> bat buoc co nasm.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl nasm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . .
RUN cargo build --release --bin website_buu

# ---- Runtime stage: image gon chi chua binary ----
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/website_buu /usr/local/bin/website_buu

# Mac dinh chay che do internet, lang nghe moi giao dien trong container,
# du lieu o /data (mount volume de khong mat khi cap nhat).
ENV APP_BIND_ADDR=0.0.0.0:18088 \
    APP_NETWORK_MODE=internet-test \
    APP_REQUIRE_HTTPS=1 \
    APP_RUNTIME_DIR=/data

EXPOSE 18088
VOLUME ["/data"]

CMD ["website_buu"]
