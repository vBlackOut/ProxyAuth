use crate::AppConfig;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{App, Error, HttpServer};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::net::TcpListener;
use std::time::Duration;

pub fn check_port(addr: &str) -> bool {
    TcpListener::bind(addr).is_ok()
}

pub fn bind_server<T, F>(
    app_factory: F,
    listener: TcpListener,
    config: &AppConfig,
) -> std::io::Result<actix_web::dev::Server>
where
    T: ServiceFactory<
            ServiceRequest,
            Config = (),
            Response = ServiceResponse<BoxBody>,
            Error = Error,
            InitError = (),
        > + 'static,
    F: Fn() -> App<T> + Clone + Send + 'static,
{
    let builder = HttpServer::new(app_factory)
        .workers(config.worker as usize)
        .keep_alive(Duration::from_millis(config.keep_alive))
        .backlog(config.pending_connections_limit)
        .max_connections(config.max_connections)
        .client_request_timeout(Duration::from_millis(config.client_timeout));

    let server = if config.tls {
        let tls_config = load_rustls_config();
        builder.listen_rustls_0_21(listener, tls_config)?
    } else {
        builder.listen(listener)?
    };

    Ok(server.run())
}

pub fn load_rustls_config() -> ServerConfig {
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
