{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    cargo-audit
    rustfmt
    clippy
    rust-analyzer
    pkg-config
    openssl
    nettle
  ];

  shellHook = ''
    rustfmt --edition 2024 src/*.rs tests/*.rs
    cargo audit
  '';

  RUST_BACKTRACE = 1;
}
