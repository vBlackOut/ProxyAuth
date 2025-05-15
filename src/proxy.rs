use actix_web::{web, HttpRequest, HttpResponse, Error, error};
use hyper::{Client, Body, Request, Uri};
use hyper::client::connect::HttpConnector;
use hyper::header::{HeaderMap, HeaderValue, USER_AGENT};
use hyper_rustls::HttpsConnector;
use rustls::client::ClientConfig;
use rustls::{Certificate, PrivateKey, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use webpki_roots::TLS_SERVER_ROOTS;
use hyper_proxy::{Proxy, ProxyConnector, Intercept};
use crate::AppState;
use crate::security::validate_token;

pub struct ClientOptions<'a> {
    pub use_proxy: bool,
    pub proxy_addr: Option<&'a str>,
    pub use_cert: bool,
    pub cert_path: Option<&'a str>,
    pub key_path: Option<&'a str>,
}

fn build_hyper_client_cert(opts: ClientOptions) -> Client<HttpsConnector<HttpConnector>> {
    let timeout_duration = Duration::from_millis(500);

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = if opts.use_cert {
        let cert_path = opts.cert_path.expect("cert_path required");
        let key_path = opts.key_path.expect("key_path required");

        let cert_file = &mut BufReader::new(File::open(cert_path).expect("Failed to open cert file"));
        let key_file = &mut BufReader::new(File::open(key_path).expect("Failed to open key file"));

        let cert_chain: Vec<Certificate> = certs(cert_file)
            .expect("Error reading cert file")
            .into_iter()
            .map(Certificate)
            .collect();

        let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
            .expect("Error reading key file")
            .into_iter()
            .map(PrivateKey)
            .collect();

        if keys.is_empty() {
            panic!("No key found in file: {:?}", key_path);
        }

        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, keys.remove(0))
            .expect("Invalid cert/key pair")
    } else {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(timeout_duration));
    http_connector.enforce_http(false);

    let tls_config = Arc::new(config);
    let https_connector = HttpsConnector::from((http_connector, tls_config));

    Client::builder()
        .pool_idle_timeout(Some(timeout_duration))
        .pool_max_idle_per_host(50)
        .http2_adaptive_window(true)
        .build::<_, Body>(https_connector)
}

fn build_hyper_client_proxy(opts: ClientOptions) -> Client<ProxyConnector<HttpsConnector<HttpConnector>>> {
    let timeout_duration = Duration::from_millis(500);

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = if opts.use_cert {
        let cert_path = opts.cert_path.expect("cert_path required");
        let key_path = opts.key_path.expect("key_path required");

        let cert_file = &mut BufReader::new(File::open(cert_path).expect("Failed to open cert file"));
        let key_file = &mut BufReader::new(File::open(key_path).expect("Failed to open key file"));

        let cert_chain: Vec<Certificate> = certs(cert_file)
            .expect("Error reading cert file")
            .into_iter()
            .map(Certificate)
            .collect();

        let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
            .expect("Error reading key file")
            .into_iter()
            .map(PrivateKey)
            .collect();

        if keys.is_empty() {
            panic!("No key found in file: {:?}", key_path);
        }

        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_client_auth_cert(cert_chain, keys.remove(0))
            .expect("Invalid cert/key pair")
    } else {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(timeout_duration));
    http_connector.enforce_http(false);

    let tls_config = Arc::new(config);
    let https_connector = HttpsConnector::from((http_connector, tls_config));

    let proxy_connector = if opts.use_proxy {
        let proxy_addr = opts.proxy_addr.unwrap_or("http://127.0.0.1:8888");
        let proxy_uri = hyper::Uri::from_str(proxy_addr).expect("Invalid proxy address");
        ProxyConnector::from_proxy(https_connector, Proxy::new(Intercept::All, proxy_uri))
            .expect("Failed to create proxy connector")
    } else {
        ProxyConnector::from_proxy(https_connector, Proxy::new(Intercept::None, hyper::Uri::from_static("http://127.0.0.1:8888")))
            .expect("Failed to create dummy proxy connector")
    };

    Client::builder()
        .pool_idle_timeout(Some(timeout_duration))
        .pool_max_idle_per_host(50)
        .http2_adaptive_window(true)
        .build::<_, Body>(proxy_connector)
}

fn build_hyper_client() -> Client<HttpsConnector<HttpConnector>> {
    let timeout_duration = Duration::from_millis(500);

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(timeout_duration));
    http_connector.enforce_http(false);

    let tls_config = Arc::new(config);
    let https_connector = HttpsConnector::from((http_connector, tls_config));

    Client::builder()
        .pool_idle_timeout(Some(timeout_duration))
        .pool_max_idle_per_host(50)
        .http2_adaptive_window(true)
        .build::<_, Body>(https_connector)
}

pub fn client_ip(req: &HttpRequest) -> Option<IpAddr> {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|forwarded| forwarded.to_str().ok())
        .and_then(|forwarded_str| forwarded_str.split(',').next())
        .and_then(|ip_str| ip_str.trim().parse::<IpAddr>().ok())
        .or_else(|| {
            req.headers()
                .get("x-real-ip")
                .and_then(|real_ip| real_ip.to_str().ok())
                .and_then(|ip_str| ip_str.trim().parse::<IpAddr>().ok())
        })
        .or_else(|| req.peer_addr().map(|addr| addr.ip()))
}

pub async fn global_proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let path = req.path();
    if let Some(rule) = data.routes.routes.iter().find(|r| path.starts_with(&r.prefix)) {
        if rule.proxy {
            proxy_with_proxy(req, body, data).await
        } else {
            proxy_without_proxy(req, body, data).await
        }
    } else {
        Ok(HttpResponse::NotFound().body("404 Not Found"))
    }
}

pub async fn proxy_with_proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let path = req.path();
    let ip = client_ip(&req).unwrap_or(IpAddr::from([127, 0, 0, 1])).to_string();
    let method = req.method();

    if let Some(rule) = data.routes.routes.iter().find(|r| path.starts_with(&r.prefix)) {
        // Construire l'URL cible
        let forward_path = path.strip_prefix(&rule.prefix).unwrap_or("");
        let target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);
        let full_url = if target_url.starts_with("http") {
            target_url
        } else {
            format!("http://{}", target_url)
        };

        let client = build_hyper_client_proxy(ClientOptions {
            use_proxy: true,
            proxy_addr: Some(&rule.proxy_config),
            use_cert: !rule.cert.is_empty(),
            cert_path: rule.cert.get("file").map(|s| s.as_str()),
            key_path: rule.cert.get("key").map(|s| s.as_str()),
        });

        let uri = Uri::from_str(&full_url)
            .map_err(|e| error::ErrorBadRequest(format!("Invalid proxy URI: {}", e)))?;

        // Validation du token si sécurisé
        let username = if rule.secure {
            let token_header = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .ok_or_else(|| error::ErrorUnauthorized("Missing token"))?;

            let username = validate_token(token_header, &data, &data.config, &ip)
                .await
                .map_err(|err| error::ErrorUnauthorized(err))?;

            if !rule.username.contains(&username) {
                return Ok(HttpResponse::Unauthorized().body("403 Forbidden"));
            }
            username
        } else {
            String::new()
        };

        // Construction des en-têtes
        let mut request_builder = Request::builder()
            .method(method)
            .uri(&uri);
        for (key, value) in req.headers() {
            if key != "authorization" && key != "user-agent" {
                request_builder = request_builder.header(key, value);
            }
        }
        request_builder = request_builder
            .header(USER_AGENT, "ProxyAuth")
            .header("Host", uri.host().ok_or_else(|| error::ErrorInternalServerError("Missing host"))?);

        let hyper_req = request_builder
            .body(Body::from(body))
            .map_err(|e| error::ErrorInternalServerError(format!("Failed to build request: {}", e)))?;

        // Envoi de la requête avec timeout
        let response_result = timeout(Duration::from_secs(10), client.request(hyper_req)).await;

        match response_result {
            Ok(Ok(res)) => {
                let mut client_resp = HttpResponse::build(res.status());
                for (key, value) in res.headers() {
                    if key != USER_AGENT && key.as_str() != "authorization" {
                        client_resp.append_header((key, value));
                    }
                }
                let body_bytes = hyper::body::to_bytes(res.into_body())
                    .await
                    .map_err(|e| error::ErrorInternalServerError(format!("Failed to read response: {}", e)))?;
                Ok(client_resp.body(body_bytes))
            }
            Ok(Err(e)) => Ok(HttpResponse::BadGateway().body(format!("Request failed: {}", e))),
            Err(_) => Ok(HttpResponse::GatewayTimeout().body("Target unreachable (timeout)")),
        }
    } else {
        Ok(HttpResponse::NotFound().body("404 Not Found"))
    }
}

pub async fn proxy_without_proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let path = req.path();
    let ip = client_ip(&req).unwrap_or(IpAddr::from([127, 0, 0, 1])).to_string();
    let method = req.method();

    if let Some(rule) = data.routes.routes.iter().find(|r| path.starts_with(&r.prefix)) {
        // Construire l'URL cible
        let forward_path = path.strip_prefix(&rule.prefix).unwrap_or("");
        let target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);
        let full_url = if target_url.starts_with("http") {
            target_url
        } else {
            format!("http://{}", target_url)
        };

        let client = if !rule.cert.is_empty() {
            build_hyper_client_cert(ClientOptions {
                use_proxy: false,
                proxy_addr: None,
                use_cert: true,
                cert_path: rule.cert.get("file").map(|s| s.as_str()),
                key_path: rule.cert.get("key").map(|s| s.as_str()),
            })
        } else {
            build_hyper_client()
        };

        let uri = Uri::from_str(&full_url)
            .map_err(|e| error::ErrorBadRequest(format!("Invalid URI: {}", e)))?;

        // Validation du token si sécurisé
        let username = if rule.secure {
            let token_header = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .ok_or_else(|| error::ErrorUnauthorized("Missing token"))?;

            let username = validate_token(token_header, &data, &data.config, &ip)
                .await
                .map_err(|err| error::ErrorUnauthorized(err))?;

            if !rule.username.contains(&username) {
                return Ok(HttpResponse::Unauthorized().body("403 Forbidden"));
            }
            username
        } else {
            String::new()
        };

        // Construction des en-têtes
        let mut request_builder = Request::builder()
            .method(method)
            .uri(&uri);
        for (key, value) in req.headers() {
            if key != "authorization" && key != "user-agent" {
                request_builder = request_builder.header(key, value);
            }
        }
        request_builder = request_builder
            .header(USER_AGENT, "ProxyAuth")
            .header("Host", uri.host().ok_or_else(|| error::ErrorInternalServerError("Missing host"))?);

        let hyper_req = request_builder
            .body(Body::from(body))
            .map_err(|e| error::ErrorInternalServerError(format!("Failed to build request: {}", e)))?;

        // Envoi de la requête avec timeout
        let response_result = timeout(Duration::from_secs(10), client.request(hyper_req)).await;

        match response_result {
            Ok(Ok(res)) => {
                let mut client_resp = HttpResponse::build(res.status());
                for (key, value) in res.headers() {
                    if key != USER_AGENT && key.as_str() != "authorization" {
                        client_resp.append_header((key, value));
                    }
                }
                let body_bytes = hyper::body::to_bytes(res.into_body())
                    .await
                    .map_err(|e| error::ErrorInternalServerError(format!("Failed to read response: {}", e)))?;
                Ok(client_resp.body(body_bytes))
            }
            Ok(Err(e)) => Ok(HttpResponse::BadGateway().body(format!("Request failed: {}", e))),
            Err(_) => Ok(HttpResponse::GatewayTimeout().body("Target unreachable (timeout)")),
        }
    } else {
        Ok(HttpResponse::NotFound().body("404 Not Found"))
    }
}
