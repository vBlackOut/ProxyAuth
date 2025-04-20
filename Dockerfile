FROM rust:alpine AS build

COPY . /app
WORKDIR /app

RUN apk add openssl openssl-libs-static openssl-dev musl-dev build-base pkgconf alpine-sdk

RUN cargo build --release

FROM alpine:latest as runtime

RUN mkdir -p /app/config
WORKDIR /app

COPY --from=build /app/target/release/proxyauth /app/
COPY --from=build /app/config/ /app/config/

EXPOSE 8080
CMD ["./proxyauth"]

