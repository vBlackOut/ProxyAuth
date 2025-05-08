FROM rust:alpine

RUN apk add openssl openssl-libs-static openssl-dev musl-dev build-base pkgconf alpine-sdk sudo

RUN cargo install --root /usr/local -j $(($(nproc) - 1)) proxyauth # stable version proxyauth@0.5.10
WORKDIR /app

RUN sudo proxyauth prepare
USER proxyauth

EXPOSE 8080
CMD ["proxyauth"]
