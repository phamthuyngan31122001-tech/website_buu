# ---- Base: toolchain + cargo-chef (để cache dependencies, build nhanh) ----
FROM rust:1-bookworm AS chef
# aws-lc-rs (release) cần cmake + perl + nasm.
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake perl nasm \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
WORKDIR /app

# ---- Lập "công thức" dependencies ----
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Build ----
FROM chef AS builder
# Bước này CHỈ build dependencies -> được cache lại (gha) khi Cargo.toml/lock
# không đổi, nên các lần build sau bỏ qua, chỉ biên dịch code ứng dụng.
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
# Giờ mới copy toàn bộ mã nguồn và build phần ứng dụng.
COPY . .
RUN cargo build --release --bin website_buu

# ---- Runtime: image gọn chỉ chứa binary ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/website_buu /usr/local/bin/website_buu

ENV APP_BIND_ADDR=0.0.0.0:18088 \
    APP_NETWORK_MODE=internet-test \
    APP_REQUIRE_HTTPS=1 \
    APP_RUNTIME_DIR=/data

EXPOSE 18088
VOLUME ["/data"]
CMD ["website_buu"]
