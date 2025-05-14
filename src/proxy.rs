use actix_web::{web, HttpRequest, HttpResponse, Error, error};
use hyper::{Client, Body, Request, Uri};
use hyper::client::connect::HttpConnector;
use hyper::header::{HeaderMap, HeaderValue, USER_AGENT};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use rustls::client::ClientConfig;
use rustls::{Certificate, PrivateKey, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::net::IpAddr;
use std::sync::Arc;
use std::str::FromStr;
use tokio::time::{timeout, Duration};
use tracing::{info, warn};
use webpki_roots::TLS_SERVER_ROOTS;

// Les autres `use` spécifiques à ton projet
use crate::AppState;
use crate::security::validate_token;

pub struct ClientOptions<'a> {
    pub use_proxy: bool,
    pub proxy_addr: Option<&'a str>,
    pub use_cert: bool,
    pub cert_path: Option<&'a str>,
    pub key_path: Option<&'a str>,
}

fn build_hyper_client(opts: ClientOptions) -> Client<HttpsConnector<HttpConnector>> {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = if opts.use_cert {
        let cert_path = opts.cert_path.expect("cert_path required");
        let key_path = opts.key_path.expect("key_path required");

        let cert_file = &mut BufReader::new(File::open(cert_path).expect("Cannot open cert file"));
        let key_file = &mut BufReader::new(File::open(key_path).expect("Cannot open key file"));

        let cert_chain: Vec<Certificate> = certs(cert_file)
            .unwrap()
            .into_iter()
            .map(Certificate)
            .collect();

        let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
            .unwrap()
            .into_iter()
            .map(PrivateKey)
            .collect();

        if keys.is_empty() {
            panic!("No private keys found in {:?}", key_path);
        }

        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_single_cert(cert_chain, keys.remove(0))
            .expect("Invalid cert/key pair")
    } else {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    let https_connector = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_or_http()
        .enable_http1()
        .build();

    Client::builder().build::<_, Body>(https_connector)
}

pub fn client_ip(req: &HttpRequest) -> Option<IpAddr> {
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip_str) = forwarded_str.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    req.peer_addr().map(|addr| addr.ip())
}

pub async fn proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let path = req.path();
    let ip = client_ip(&req).unwrap_or("127.0.0.1".parse().unwrap()).to_string();
    let method = req.method().clone();
    let mut username_check = String::new();

    if let Some(rule) = data.routes.routes.iter().find(|r| path.starts_with(&r.prefix)) {
        let forward_path = path.strip_prefix(&rule.prefix).unwrap_or("");
        let target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);

        let (client, uri) = if rule.proxy {
            let full_url = if target_url.starts_with("http") {
                target_url.clone()
            } else {
                format!("http://{}", target_url)
            };
            let client = build_hyper_client(ClientOptions {
                use_proxy: true,
                proxy_addr: Some(&rule.proxy_config),
                use_cert: false,
                cert_path: None,
                key_path: None,
            });
            let uri = Uri::from_str(&full_url).map_err(|e| error::ErrorBadRequest(format!("Invalid proxy URI: {}", e)))?;
            (client, uri)
        } else if !rule.cert.is_empty() {
            let client = build_hyper_client(ClientOptions {
                use_proxy: false,
                proxy_addr: None,
                use_cert: true,
                cert_path: rule.cert.get("file").map(|s| s.as_str()),
                key_path: rule.cert.get("key").map(|s| s.as_str()),
            });
            let uri = Uri::from_str(&target_url).map_err(|e| error::ErrorBadRequest(format!("Invalid URI: {}", e)))?;
            (client, uri)
        } else {
            let client = build_hyper_client(ClientOptions {
                use_proxy: false,
                proxy_addr: None,
                use_cert: false,
                cert_path: None,
                key_path: None,
            });
            let uri = Uri::from_str(&target_url).map_err(|e| error::ErrorBadRequest(format!("Invalid URI: {}", e)))?;
            (client, uri)
        };

        if rule.secure {
            let token_header = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .ok_or_else(|| error::ErrorUnauthorized("Missing token"))?;

            let username = validate_token(&token_header.to_string(), &data, &data.config, &ip).await
                .map_err(|err| error::ErrorUnauthorized(err))?;

            if !rule.username.contains(&username) {
                return Ok(HttpResponse::Unauthorized().body("403 Forbidden"));
            }

            username_check = username;
        }

        let mut headers = HeaderMap::new();
        for (key, value) in req.headers().iter() {
            if key != "authorization" && key != "user-agent" {
                headers.insert(key.clone(), value.clone());
            }
        }
        headers.insert(USER_AGENT, HeaderValue::from_static("ProxyAuth"));
        if let Some(host) = uri.host() {
            headers.insert("Host", HeaderValue::from_str(host).unwrap());
        }

        let mut request_builder = Request::builder().method(method.clone()).uri(uri.clone());
        *request_builder.headers_mut().unwrap() = headers;

        let hyper_req = request_builder
            .body(Body::from(body.to_vec()))
            .map_err(|e| error::ErrorInternalServerError(format!("Failed to build request: {}", e)))?;

        let response_result = timeout(Duration::from_millis(100), client.request(hyper_req)).await;

        match response_result {
            Ok(Ok(res)) => {
                let mut client_resp = HttpResponse::build(res.status());
                for (key, value) in res.headers() {
                    if key != &USER_AGENT && key.as_str() != "authorization" {
                        client_resp.append_header((key.clone(), value.clone()));
                    }
                }

                let body_bytes = hyper::body::to_bytes(res.into_body()).await.unwrap_or_default();
                Ok(client_resp.body(body_bytes))
            }
            Ok(Err(e)) => Ok(HttpResponse::BadGateway().body(format!("Request failed: {}", e))),
            Err(_) => Ok(HttpResponse::GatewayTimeout().body("Target unreachable (timeout)")),
        }
    } else {
        Ok(HttpResponse::NotFound().body("404 Not Found"))
    }
}
