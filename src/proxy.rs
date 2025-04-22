use crate::security::validate_token;
use crate::AppState;
use actix_web::{web, Error, HttpRequest, HttpResponse};
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

            let username = match validate_token(&token_hash, &data.config, &ip) {
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

        let mut forwarded_req = data.client.request(method, &target_url);
        for (key, value) in req.headers() {
            forwarded_req = forwarded_req.header(key, value);
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
                return Ok(client_resp.body(bytes))
            }
            Err(_) => {
                warn!(
                    "[{}] user {} forward request {} proxy response url unreachable for {}",
                    ip, username_check, rule.prefix, target_url
                );
                return Ok(HttpResponse::BadGateway().body("Target unreachable"))
            }
        }
    } else {
        info!(
            "[{}] try to access route {} proxy response no route",
            ip, path
        );
        return Ok(HttpResponse::NotFound().body("404 Not Found"))
    }
}
