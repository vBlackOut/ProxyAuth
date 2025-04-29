FROM rust:alpine

RUN apk add openssl openssl-libs-static openssl-dev musl-dev build-base pkgconf alpine-sdk
RUN set -ex && apk --no-cache add sudo

RUN cargo install --root /usr/local proxyauth # stable version command: cargo install proxyauth@0.5.5

RUN mkdir -p /app/config
WORKDIR /app

EXPOSE 8080
RUN proxyauth prepare

CMD ["proxyauth"]
