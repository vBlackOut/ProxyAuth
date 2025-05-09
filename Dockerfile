FROM rust:alpine

# Install required system dependencies
RUN apk add --no-cache openssl openssl-libs-static openssl-dev musl-dev build-base pkgconf alpine-sdk sudo

# Create non-root user
RUN addgroup -g 1000 proxyauth && \
    adduser -D -u 1000 -G proxyauth -h /home/proxyauth proxyauth

# Install proxyauth from crates.io (adapt version if needed)
RUN cargo install proxyauth --root /usr/local  -j $(($(nproc) - 1)) --locked

RUN mkdir -p /etc/proxyauth/config && \
    chown -R proxyauth:proxyauth /etc/proxyauth

RUN proxyauth prepare

USER proxyauth

# Expose the service port
EXPOSE 8080

# Launch the binary
CMD ["/usr/local/bin/proxyauth"]

