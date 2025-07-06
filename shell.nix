let
  rustOverlay = import (fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");
  pkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-23.11.tar.gz") {
    overlays = [ rustOverlay ];
  };
in
pkgs.mkShell {
  buildInputs = [
    pkgs.rust-bin.nightly.latest.default
    pkgs.rust-analyzer
    pkgs.cargo-audit
    pkgs.rustfmt
    pkgs.clippy
    pkgs.pkg-config
    pkgs.openssl
    pkgs.nettle
  ];

  shellHook = ''
    echo "Rust version: $(rustc --version)"
    cargo audit || true
  '';

  RUST_BACKTRACE = 1;
}
