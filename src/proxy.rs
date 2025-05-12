use crate::security::validate_token;
use crate::AppState;
use actix_web::{error, web, Error, HttpRequest, HttpResponse, Result};
use reqwest::Proxy;
//use std::time::Duration;
use reqwest::{header, Client, Identity};
use std::fs;
use std::net::IpAddr;
use tracing::{info, warn};

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
    let ip = client_ip(&req).expect("?").to_string();
    let method = req.method().clone();
    let mut username_check = "".to_string();

    if let Some(rule) = data
        .routes
        .routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
    {
        let forward_path = path.strip_prefix(&rule.prefix).unwrap_or("");
        let target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);

        let client = if rule.proxy {
            let proxy = Proxy::all(&rule.proxy_config)
                .map_err(|e| error::ErrorBadRequest(format!("Error configuration proxy: {}", e)))?;

            Client::builder()
                .proxy(proxy)
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| {
                    error::ErrorInternalServerError(format!("Error build client: {}", e))
                })?
        } else if !rule.cert.is_empty() {
            let file_path = rule.cert.get("file").ok_or_else(|| {
                error::ErrorInternalServerError(format!(
                    "No found file certificat for target_url {}.",
                    target_url
                ))
            })?;

            let password = rule.cert.get("password").map(|s| s.as_str()).unwrap_or("");

            let cert_bytes = fs::read(file_path).map_err(|e| {
                error::ErrorInternalServerError(format!("Error read certificat: {}", e))
            })?;

            let identity = Identity::from_pkcs12_der(&cert_bytes, password)
                .map_err(|e| error::ErrorInternalServerError(format!("Error identity: {}", e)))?;

            Client::builder()
                //.timeout(Duration::from_millis(100))
                .identity(identity)
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| {
                    error::ErrorInternalServerError(format!(
                        "Error build request for client: {}",
                        e
                    ))
                })?
        } else {
            reqwest::Client::builder()
            //.timeout(Duration::from_millis(100))
            .build()
            .expect("Failed to build reqwest client")
        };

        if rule.secure {
            let token_header = match req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
            {
                Some(t) => t.to_string(),
                None => return Ok(HttpResponse::Unauthorized().body("Missing token")),
            };

            let token_hash = &token_header;

            let username = match validate_token(&token_hash, &data, &data.config, &ip) {
                Ok(username) => username,
                Err(err) => return Ok(HttpResponse::Unauthorized().body(err)),
            };

            username_check = username.clone();

            if !rule.username.contains(&username) {
                warn!(
                    "[{}] user {} not authorized to access route {} response 403 forbidden.",
                    ip, username, rule.prefix
                );
                return Ok(HttpResponse::Unauthorized().body("403 Forbidden"));
            }
        }

        let mut forwarded_req = client
            .request(method, &target_url)
            .header(header::USER_AGENT, "ProxyAuth");
        for (key, value) in req.headers() {
            if "Authorization" != key && "user-agent" != key {
                forwarded_req = forwarded_req.header(key, value);
            }
        }

        let res = forwarded_req.body(body.clone()).send().await;

        match res {
            Ok(resp) => {
                let mut client_resp = HttpResponse::build(resp.status());
                for (key, value) in resp.headers() {
                    client_resp.append_header((key.clone(), value.clone()));
                }

                let bytes = resp.bytes().await.unwrap_or_default();
                if username_check != "" {
                    info!(
                        "[{}] user {} forward request {} to url {} proxy response code 200",
                        ip, username_check, rule.prefix, target_url
                    );
                } else {
                    info!(
                        "[{}] forward request {} to url {} proxy response code 200",
                        ip, rule.prefix, target_url
                    );
                }
                return Ok(client_resp.body(bytes));
            }
            Err(_) => {
                warn!(
                    "[{}] user {} forward request {} proxy response url unreachable for {}",
                    ip, username_check, rule.prefix, target_url
                );
                return Ok(HttpResponse::BadGateway().body("Target unreachable"));
            }
        }
    } else {
        info!(
            "[{}] try to access route {} proxy response no route",
            ip, path
        );
        return Ok(HttpResponse::NotFound().body("404 Not Found"));
    }
}
