use actix_web::{web, HttpRequest, HttpResponse, Error, error};
use hyper::{Client, Body, Request, Uri};
use hyper::header::USER_AGENT;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::time::{timeout, Duration};
use crate::AppState;
use crate::AppConfig;
use std::sync::Arc;
use crate::security::validate_token;
use once_cell::sync::Lazy;
use dashmap::DashMap;
use crate::shared_client::{build_hyper_client_normal, build_hyper_client_cert};

static CLIENT_CACHE: Lazy<DashMap<ClientKey, Client<HttpsConnector<HttpConnector>>>> =
Lazy::new(|| DashMap::new());

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct ClientKey {
    pub use_proxy: bool,
    pub proxy_addr: Option<String>,
    pub use_cert: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

impl ClientKey {
    pub fn from_options(opts: &ClientOptions) -> Self {
        ClientKey {
            use_proxy: opts.use_proxy,
            proxy_addr: opts.proxy_addr.clone().map(|s| s.to_string()),
            use_cert: opts.use_cert,
            cert_path: opts.cert_path.clone().map(|s| s.to_string()),
            key_path: opts.key_path.clone().map(|s| s.to_string()),
        }
    }
}

pub fn get_or_build_client(
    opts: ClientOptions,
    state: &Arc<AppConfig>
) -> Client<hyper_rustls::HttpsConnector<HttpConnector>> {
    let key = ClientKey::from_options(&opts);

    if let Some(client) = CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let https_connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();

    let client = Client::builder().build::<_, hyper::Body>(https_connector);

    CLIENT_CACHE.insert(key, client.clone());
    client
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ClientOptions {
    pub use_proxy: bool,
    pub proxy_addr: Option<String>,
    pub use_cert: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
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

        let forward_path = path.strip_prefix(&rule.prefix).unwrap_or("");
        let target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);
        let full_url = if target_url.starts_with("http") {
            target_url
        } else {
            format!("http://{}", target_url)
        };

        let client = get_or_build_client(ClientOptions {
            use_proxy: true,
            proxy_addr: Some(rule.proxy_config.clone()),
            use_cert: false,
            cert_path: Some("".to_string()),
            key_path: Some("".to_string()),
        }, &data.config.clone());

        let uri = Uri::from_str(&full_url)
            .map_err(|e| error::ErrorBadRequest(format!("Invalid proxy URI: {}", e)))?;

        let _username = if rule.secure {
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

        let response_result = timeout(Duration::from_secs(5), client.request(hyper_req)).await;

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

        let forward_path = path.strip_prefix(&rule.prefix).unwrap_or("");
        let target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);
        let full_url = if target_url.starts_with("http") {
            target_url
        } else {
            format!("http://{}", target_url)
        };

        let client = if !rule.cert.is_empty() {
            get_or_build_client(ClientOptions {
                use_proxy: false,
                proxy_addr: None,
                use_cert: true,
                cert_path: rule.cert.get("file").cloned(),
                key_path: rule.cert.get("key").cloned(),
            }, &data.config.clone())
        } else {
            build_hyper_client_normal(&data.config.clone())
        };

        let uri = Uri::from_str(&full_url)
            .map_err(|e| error::ErrorBadRequest(format!("Invalid URI: {}", e)))?;

        let _username = if rule.secure {
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
