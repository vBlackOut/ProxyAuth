FROM rust:alpine

RUN apk add openssl openssl-libs-static openssl-dev musl-dev build-base pkgconf alpine-sdk

RUN cargo install proxyauth # stable version command: cargo install proxyauth@0.4.2
RUN mkdir -p /app/config
WORKDIR /app

COPY ./config/ /app/config/

EXPOSE 8080
CMD ["proxyauth"]
