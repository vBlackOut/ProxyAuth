
use crate::AppState;
use crate::security::validate_token;
use actix_web::{Error, HttpRequest, HttpResponse, Result, error, web};
use reqwest::{Client, Identity, Proxy, header};
use std::fs;
use std::net::IpAddr;
use std::time::Duration;
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
    let ip = client_ip(&req).unwrap_or_else(|| "0.0.0.0".parse().unwrap()).to_string();
    let method = req.method().clone();
    let mut username_check = String::new();

    if let Some(rule) = data.routes.routes.iter().find(|r| path.starts_with(&r.prefix)) {
        let forward_path = path.strip_prefix(&rule.prefix).unwrap_or("");
        let target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);

        let client = &data.client;

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

            let username = match validate_token(&token_header, &data, &data.config, &ip) {
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
            if key != header::AUTHORIZATION && key != header::USER_AGENT {
                forwarded_req = forwarded_req.header(key, value);
            }
        }

        match forwarded_req.body(body.clone()).send().await {
            Ok(resp) => {
                let mut client_resp = HttpResponse::build(resp.status());

                for (key, value) in resp.headers() {
                    client_resp.append_header((key.clone(), value.clone()));
                }

                match resp.bytes().await {
                    Ok(bytes) => {
                        if !username_check.is_empty() {
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

                        Ok(client_resp.body(bytes))
                    }
                    Err(e) => {
                        warn!(
                            "[{}] user {} forward request {} failed to read body from {}: {}",
                            ip, username_check, rule.prefix, target_url, e
                        );
                        Ok(HttpResponse::BadGateway().body("Failed to read response body"))
                    }
                }
            }
            Err(e) => {
                warn!(
                    "[{}] Failed to forward request for user '{}' on route '{}' → target '{}': connection error: {}",
                    ip, username_check, rule.prefix, target_url, e
                );
                Ok(HttpResponse::BadGateway().body("Target unreachable"))
            }
        }
    } else {
        warn!(
            "[{}] Rejected request: no matching route for path '{}'. Responded with 404 Not Found.",
            ip, path
        );
        Ok(HttpResponse::NotFound().body("404 Not Found"))
    }
}
