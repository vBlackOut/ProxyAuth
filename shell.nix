{
  pkgs ? import (
    let
      tryNixpkgs = builtins.tryEval <nixpkgs>;
    in
    if tryNixpkgs.success then
      tryNixpkgs.value
    else
      fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz"
  ) { },
}:

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
    echo "Rust version: $(rustc --version)"
    rustfmt --edition 2024 src/*.rs tests/*.rs
    cargo audit
  '';

  RUST_BACKTRACE = 1;
}
