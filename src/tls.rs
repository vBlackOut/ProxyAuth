use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;

pub fn check_port(addr: &str) -> bool {
    TcpListener::bind(addr).is_ok()
}

pub fn load_rustls_config() -> rustls::ServerConfig {
    let cert_file = &mut BufReader::new(
        File::open("/etc/proxyauth/certs/cert.pem").expect("Cannot open certificate file"),
    );
    let key_file = &mut BufReader::new(
        File::open("/etc/proxyauth/certs/key.pem").expect("Cannot open key file"),
    );

    let cert_chain = certs(cert_file)
        .expect("Cannot read certificates")
        .into_iter()
        .map(Certificate)
        .collect();

    let mut keys = pkcs8_private_keys(key_file)
        .expect("Cannot read private key")
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();

    if keys.is_empty() {
        panic!("No private key found");
    }

    ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))
        .expect("Failed to build TLS config")
}
