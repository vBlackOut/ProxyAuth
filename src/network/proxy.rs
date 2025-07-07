use crate::AppState;
use crate::config::config::BackendConfig;
use crate::config::config::BackendInput;
use crate::network::loadbalancing::forward_failover;
use crate::network::shared_client::{
    ClientOptions, get_or_build_client_proxy, get_or_build_thread_client,
};
use crate::token::security::validate_token;
use actix_web::{Error, HttpRequest, HttpResponse, error, web};
use hyper::header::USER_AGENT;
use hyper::{Body, Method, Request, Uri};
use std::net::IpAddr;
use std::str::FromStr;
use tokio::time::{Duration, timeout};
use tracing::{info, warn};

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
    if let Some(rule) = data
        .routes
        .routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
    {
        if rule.proxy {
            proxy_with_proxy(req, body, data).await
        } else {
            proxy_without_proxy(req, body, data).await
        }
    } else {
        Ok(HttpResponse::NotFound()
            .append_header(("server", "ProxyAuth"))
            .body("404 Not Found"))
    }
}

pub async fn proxy_with_proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let path = req.path();
    let ip = client_ip(&req)
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
        .to_string();
    let method = req.method();

    if let Some(rule) = data
        .routes
        .routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
    {
        // fix allow redirect pârams inside the GET method.
        let original_uri = req.uri();
        let raw_forward = req.path().strip_prefix(&rule.prefix).unwrap_or("");
        let forward_path = if raw_forward.starts_with('/') {
            raw_forward.to_string()
        } else {
            format!("/{}", raw_forward)
        };

        let mut user_agent = "";

        let mut target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);

        if let Some(query) = original_uri.query() {
            target_url.push('?');
            target_url.push_str(query);
        }

        let full_url = if target_url.starts_with("http") {
            target_url.clone()
        } else {
            format!("http://{}", target_url)
        };

        let client = get_or_build_client_proxy(
            ClientOptions {
                use_proxy: true,
                proxy_addr: Some(rule.proxy_config.clone()),
                use_cert: false,
                cert_path: Some("".to_string()),
                key_path: Some("".to_string()),
            },
            data.config.clone(),
        );

        let uri = Uri::from_str(&full_url)
            .map_err(|e| error::ErrorBadRequest(format!("Invalid proxy URI: {}", e)))?;

        let (username, token_id) = if rule.secure {
            let token_header = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .ok_or_else(|| error::ErrorUnauthorized("Missing token"))?;

            let (username, token_id) = validate_token(token_header, &data, &data.config, &ip)
                .await
                .map_err(|err| {
                    warn!(
                        client_ip = %ip,
                        "Unauthorized token attempt"
                    );
                    error::ErrorUnauthorized(err)
                })?;

            if !rule.username.contains(&username) {
                warn!(
                    client_ip = %ip,
                    username = %username,
                    path = %forward_path,
                    target = %full_url,
                    "This username is not authorized to access"
                );
                return Ok(HttpResponse::Unauthorized()
                    .append_header(("server", "ProxyAuth"))
                    .body("403 Forbidden"));
            }
            (username, token_id)
        } else {
            (String::new(), String::new())
        };

        let mut request_builder = Request::builder().method(method).uri(&uri);

        for (key, value) in req.headers() {
            if key == "user-agent" {
                user_agent = value.to_str().unwrap_or("");
            }
            if key != "authorization" && key != "user-agent" {
                request_builder = request_builder.header(key, value);
            }
        }

        request_builder = request_builder
            .header("Connection", "close")
            .header(USER_AGENT, "ProxyAuth")
            .header(
                "Host",
                uri.authority().map(|a| a.as_str()).unwrap_or("127.0.0.1"),
            );

        let hyper_req = if method == Method::GET || method == Method::HEAD {
            request_builder.body(Body::empty()).map_err(|e| {
                warn!(client_ip = %ip, target = %full_url, "Request build failed (GET): {}", e);
                error::ErrorInternalServerError(format!("{}", e))
            })?
        } else {
            request_builder.body(Body::from(body)).map_err(|e| {
                warn!(client_ip = %ip, target = %full_url, "Request build failed: {}", e);
                error::ErrorInternalServerError(format!("{}", e))
            })?
        };

        let response_result = if !rule.backends.is_empty() {
            let backends: Vec<BackendConfig> = rule
                .backends
                .iter()
                .map(|b| match b {
                    BackendInput::Simple(url) => BackendConfig {
                        url: url.clone(),
                        weight: 1,
                    },
                    BackendInput::Detailed(cfg) => cfg.clone(),
                })
                .collect();

            forward_failover(hyper_req, &backends, Some(&rule.proxy_config))
                .await
                .map_err(|e| {
                    warn!(client_ip = %ip, target = %full_url, "Failover failed: {}", e);
                    error::ErrorServiceUnavailable("503 Service Unavailable")
                })?
        } else {
            match timeout(Duration::from_millis(500), client.request(hyper_req)).await {
                Ok(Ok(res)) => res,
                Ok(Err(e)) => {
                    warn!(client_ip = %ip, target = %full_url, "Upstream error: {}", e);
                    return Ok(HttpResponse::ServiceUnavailable()
                        .append_header(("server", "ProxyAuth"))
                        .finish());
                }
                Err(e) => {
                    warn!(client_ip = %ip, target = %full_url, "Timeout error: {}", e);
                    return Ok(HttpResponse::ServiceUnavailable()
                        .append_header(("server", "ProxyAuth"))
                        .finish());
                }
            }
        };

        let status = response_result.status();

        if status.is_server_error() {
            warn!(client_ip = %ip, target = %full_url, "Upstream returned server error: {}", status);
            return Ok(HttpResponse::InternalServerError()
                .append_header(("server", "ProxyAuth"))
                .finish());
        }

        let mut client_resp = HttpResponse::build(status);
        for (key, value) in response_result.headers() {
            if key != USER_AGENT && key.as_str() != "authorization" && key.as_str() != "server" {
                client_resp.append_header((key.clone(), value.clone()));
            }
        }

        let body_bytes = hyper::body::to_bytes(response_result.into_body())
            .await
            .map_err(|e| {
                warn!(client_ip = %ip, target = %full_url, "Body read error: {}", e);
                error::ErrorInternalServerError("500 Internal Server Error")
            })?;

        info!(
            "{} - {} {} {} {} {} [tid:{}] {}",
            ip,
            path,
            method,
            status.as_u16(),
            body_bytes.len(),
            username,
            token_id,
            user_agent
        );
        Ok(client_resp
            .append_header(("server", "ProxyAuth"))
            .body(body_bytes))
    } else {
        Ok(HttpResponse::NotFound()
            .append_header(("server", "ProxyAuth"))
            .body("404 Not Found"))
    }
}

pub async fn proxy_without_proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let path = req.path();
    let ip = client_ip(&req)
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
        .to_string();
    let method = req.method();

    if let Some(rule) = data
        .routes
        .routes
        .iter()
        .find(|r| path.starts_with(&r.prefix))
    {
        // fix allow redirect pârams inside the GET method.
        let original_uri = req.uri();
        let forward_path = req.path().strip_prefix(&rule.prefix).unwrap_or("");

        let forward_path = if forward_path.starts_with('/') {
            forward_path.to_string()
        } else {
            format!("/{}", forward_path)
        };

        let mut user_agent = "";

        let mut target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);

        if let Some(query) = original_uri.query() {
            target_url.push('?');
            target_url.push_str(query);
        }

        let full_url = if target_url.starts_with("http") {
            target_url.clone()
        } else {
            format!("http://{}", target_url)
        };

        let client = if !rule.cert.is_empty() {
            get_or_build_thread_client(
                &ClientOptions {
                    use_proxy: false,
                    proxy_addr: None,
                    use_cert: true,
                    cert_path: rule.cert.get("file").cloned(),
                    key_path: rule.cert.get("key").cloned(),
                },
                &data.config.clone(),
            )
        } else {
            get_or_build_thread_client(
                &ClientOptions {
                    use_proxy: false,
                    proxy_addr: None,
                    use_cert: false,
                    cert_path: rule.cert.get("file").cloned(),
                    key_path: rule.cert.get("key").cloned(),
                },
                &data.config.clone(),
            )
            // build_hyper_client_normal(&data.config.clone())
        };

        let uri = Uri::from_str(&full_url)
            .map_err(|e| error::ErrorBadRequest(format!("Invalid URI: {}", e)))?;

        let (username, token_id) = if rule.secure {
            let token_header = req
                .headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .ok_or_else(|| error::ErrorUnauthorized("Missing token"))?;

            let (username, token_id) = validate_token(token_header, &data, &data.config, &ip)
                .await
                .map_err(|err| {
                    warn!(
                        client_ip = %ip,
                        "Unauthorized token attempt"
                    );
                    error::ErrorUnauthorized(err)
                })?;

            if !rule.username.contains(&username) {
                return Ok(HttpResponse::Unauthorized()
                    .append_header(("server", "ProxyAuth"))
                    .body("403 Forbidden"));
            }
            (username, token_id)
        } else {
            (String::new(), String::new())
        };

        let mut request_builder = Request::builder().method(method).uri(&uri);

        for (key, value) in req.headers() {
            if key.as_str() == "user-agent" {
                user_agent = value.to_str().unwrap_or("");
            }
            if key != "authorization" && key != "user-agent" {
                request_builder = request_builder.header(key, value);
            }
        }

        request_builder = request_builder.header(USER_AGENT, "ProxyAuth").header(
            "Host",
            uri.host()
                .ok_or_else(|| error::ErrorInternalServerError("Missing host"))?,
        );

        let hyper_req = if method == Method::GET || method == Method::HEAD {
            request_builder.body(Body::empty()).map_err(|e| {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Route fallback: 500 Internal error (GET/HEAD): {}", e
                );
                error::ErrorInternalServerError(format!("{}", e))
            })?
        } else {
            request_builder.body(Body::from(body)).map_err(|e| {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Route fallback: 500 Internal error reason: {}", e
                );
                error::ErrorInternalServerError(format!("{}", e))
            })?
        };

        let response_result = if !rule.backends.is_empty() {
            // Mode failover

            let backends: Vec<BackendConfig> = rule
                .backends
                .iter()
                .map(|b| match b {
                    BackendInput::Simple(url) => BackendConfig {
                        url: url.clone(),
                        weight: 1,
                    },
                    BackendInput::Detailed(cfg) => cfg.clone(),
                })
                .collect();

            forward_failover(hyper_req, &backends, None)
                .await
                .map_err(|e| {
                    warn!(client_ip = %ip, target = %full_url, "Failover failed: {}", e);
                    error::ErrorServiceUnavailable("503 Service Unavailable")
                })?
        } else {
            // Mode direct
            match timeout(Duration::from_millis(500), client.request(hyper_req)).await {
                Ok(Ok(res)) => res,
                Ok(Err(e)) => {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Route fallback reason (client error): {}", e
                    );
                    return Ok(HttpResponse::ServiceUnavailable()
                        .append_header(("server", "ProxyAuth"))
                        .finish());
                }
                Err(e) => {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Route fallback reason (timeout): {}", e
                    );
                    return Ok(HttpResponse::ServiceUnavailable()
                        .append_header(("server", "ProxyAuth"))
                        .finish());
                }
            }
        };

        let status = response_result.status();

        if status.is_server_error() {
            warn!(
                client_ip = %ip,
                target = %full_url,
                "Upstream returned server error: {}",
                status
            );
            return Ok(HttpResponse::InternalServerError()
                .append_header(("server", "ProxyAuth"))
                .finish());
        }

        let (parts, body) = response_result.into_parts();
        let status = parts.status;
        let headers = parts.headers;

        let mut client_resp = HttpResponse::build(status);

        for (key, value) in &headers {
            if key != USER_AGENT && key.as_str() != "authorization" && key.as_str() != "server" {
                client_resp.append_header((key.clone(), value.clone()));
            }
        }

        let body_bytes = hyper::body::to_bytes(body).await.map_err(|e| {
            warn!(
                client_ip = %ip,
                target = %full_url,
                "Body read error: {}", e
            );
            error::ErrorInternalServerError("500 Internal Server Error")
        })?;

        info!(
            "{} - {} {} {} {} {} [tid:{}] {}",
            ip,
            path,
            method,
            status.as_u16(),
            body_bytes.len(),
            username,
            token_id,
            user_agent
        );
        Ok(client_resp
            .append_header(("server", "ProxyAuth"))
            .body(body_bytes))
    } else {
        Ok(HttpResponse::NotFound()
            .append_header(("server", "ProxyAuth"))
            .body("404 Not Found"))
    }
}
