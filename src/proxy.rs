use actix_web::{web, HttpRequest, HttpResponse, Error, error};
use hyper::{Body, Request, Uri};
use hyper::header::USER_AGENT;
use std::net::IpAddr;
use std::str::FromStr;
use tokio::time::{timeout, Duration};
use crate::AppState;
use crate::security::validate_token;
use crate::loadbalancing::forward_failover;
use crate::shared_client::{get_or_build_client, get_or_build_client_proxy, ClientOptions};
use tracing::warn;

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


        let client = get_or_build_client_proxy(ClientOptions {
            use_proxy: true,
            proxy_addr: Some(rule.proxy_config.clone()),
            use_cert: false,
            cert_path: Some("".to_string()),
            key_path: Some("".to_string()),
        }, data.config.clone());

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
                warn!(
                    client_ip = %ip,
                    username = %username,
                    path = %forward_path,
                    target = %full_url,
                    "This username is not authorized to access"
                );
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
            .map_err(|e| {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Failed to read response body from backend"
                );
                error::ErrorInternalServerError(format!("{}", e))
            })?;

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
                    .map_err(|e| {
                        warn!(
                            client_ip = %ip,
                            target = %full_url,
                            "Failed to read response body from backend"
                        );
                        error::ErrorInternalServerError(format!("{}", e))
                    })?;
                Ok(client_resp.body(body_bytes))
            }
            Ok(Err(e)) => {
                warn!("Route fallback: 404 Not Found – reason: {}", e);
                Ok(HttpResponse::NotFound().body("404 Not Found"))
            },
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
            }, data.config.clone())
        } else {
            get_or_build_client(ClientOptions {
                use_proxy: false,
                proxy_addr: None,
                use_cert: false,
                cert_path: rule.cert.get("file").cloned(),
                key_path: rule.cert.get("key").cloned(),
            }, data.config.clone())
            // build_hyper_client_normal(&data.config.clone())
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
                .map_err(|err| {
                    warn!(
                        client_ip = %ip,
                        "Unauthorized token attempt"
                    );
                    error::ErrorUnauthorized(err)
                })?;

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
            .map_err(|e| {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Route fallback: 500 Internal error reason: {} ", e);
                    error::ErrorInternalServerError(format!("{}", e))
            })?;

        let response_result = if !rule.backends.is_empty() {
            forward_failover(hyper_req, &rule.backends).await.map_err(|e| {
                warn!(client_ip = %ip, target = %full_url, "Failover failed: {}", e);
                error::ErrorServiceUnavailable("503 Service Unavailable")
            })?
        } else {
            match timeout(Duration::from_secs(10), client.request(hyper_req)).await {
                Ok(Ok(res)) => res,
                Ok(Err(e)) => {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Route fallback reason (client error): {}", e
                    );
                    return Ok(HttpResponse::ServiceUnavailable().body("503 Service Unavailable"));
                }
                Err(e) => {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Route fallback reason (timeout): {}", e
                    );
                    return Ok(HttpResponse::ServiceUnavailable().body("503 Service Unavailable"));
                }
            }
        };

        let mut client_resp = HttpResponse::build(response_result.status());
        for (key, value) in response_result.headers() {
            if key != USER_AGENT && key.as_str() != "authorization" {
                client_resp.append_header((key.clone(), value.clone()));
            }
        }

        let body_bytes = hyper::body::to_bytes(response_result.into_body())
        .await
        .map_err(|e| {
            warn!(
                client_ip = %ip,
                target = %full_url,
                "Route fallback: 500 Internal error reason: {}", e
            );
            error::ErrorInternalServerError(format!("{}", e))
        })?;

        Ok(client_resp.body(body_bytes))

    } else {
        Ok(HttpResponse::NotFound().body("404 Not Found"))
    }
}
