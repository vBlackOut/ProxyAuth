FROM rust:alpine

RUN apk add openssl openssl-libs-static openssl-dev musl-dev build-base pkgconf alpine-sdk sudo

RUN cargo install --root /usr/local proxyauth # stable version command: cargo install proxyauth@0.4.2
RUN mkdir -p /app/config
WORKDIR /app

RUN sudo proxyauth prepare
USER proxyauth

EXPOSE 8080
CMD ["proxyauth"]
