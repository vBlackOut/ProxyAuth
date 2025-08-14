use crate::config::config::BackendConfig;
use crate::config::config::BackendInput;
use crate::config::config::RouteRule;
use crate::network::loadbalancing::forward_failover;
use crate::network::canonical_url::canonicalize_path_for_match;
use crate::network::shared_client::{
    ClientOptions, get_or_build_client_proxy, get_or_build_thread_client,
};
use crate::token::security::apply_filters_regex_allow_only;
use crate::token::csrf::{inject_csrf_token, validate_csrf_token, fix_mime_actix};
use crate::token::security::validate_token;
use crate::{AppConfig, AppState};
use actix_web::{Error, HttpRequest, HttpResponse, HttpResponseBuilder, error, http::header, http::StatusCode, web};
use hyper::header::USER_AGENT;
use hyper::http::request::Builder;
use hyper::{Body, Method, Request, Uri};
use std::net::IpAddr;
use std::str::FromStr;
use tokio::time::{Duration, timeout};
use tracing::{info, warn};
use once_cell::sync::Lazy;
use std::sync::RwLock;

static ORDERED_ROUTE_IDX: Lazy<RwLock<Option<Vec<usize>>>> = Lazy::new(|| RwLock::new(None));

#[cfg(test)]
pub(crate) fn _reset_route_order_for_tests() {
    *ORDERED_ROUTE_IDX.write().unwrap() = None;
}

fn norm_len(prefix: &str) -> usize {
    if prefix == "/" { 0 } else { prefix.trim_end_matches('/').len() }
}


fn is_method_allowed(allowed: Option<&[String]>, method: &Method) -> bool {
    match allowed {
        None => true,
        Some(list) => {
            let m = method.as_str();
            list.iter().any(|s| {
                let t = s.trim();
                t == "*" || t.eq_ignore_ascii_case(m)
            })
        }
    }
}

fn build_allow_header(allowed: Option<&[String]>) -> String {
    const ALL: &str = "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS";
    match allowed {
        None => ALL.to_string(),
        Some(list) => {
            if list.iter().any(|s| s.trim() == "*") {
                return ALL.to_string();
            }

            let mut v: Vec<String> = list
            .iter()
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| !s.is_empty())
            .collect();
            v.sort();
            v.dedup();

            if !v.iter().any(|s| s == "OPTIONS") {
                v.push("OPTIONS".into());
                v.sort();
                v.dedup();
            }
            v.join(", ")
        }
    }
}

fn canonicalize_prefix(prefix: &str) -> String {
    let p = if prefix.is_empty() { "/" } else { prefix };
    let p = p.trim_end_matches('/');
    if p.is_empty() { "/".to_string() } else { canonicalize_path_for_match(p) }
}


pub fn compile_filters_on_routes(routes: &mut [RouteRule]) {
    for r in routes.iter_mut() {
        r.filters_compiled = match &r.filters {
            Some(cfg) => cfg.compile().ok(),
            None => None,
        };
    }
}

pub fn init_routes_order(routes: &[RouteRule]) {
    let mut idx: Vec<usize> = (0..routes.len()).collect();
    idx.sort_by(|&i, &j| {
        let pi = routes[i].prefix.as_str();
        let pj = routes[j].prefix.as_str();
        let ri = pi == "/";
        let rj = pj == "/";
        match (ri, rj) {
            (true,  false) => std::cmp::Ordering::Greater,
                (false, true ) => std::cmp::Ordering::Less,
                _ => {
                    let li = norm_len(pi);
                    let lj = norm_len(pj);
                    if li != lj { lj.cmp(&li) } else { pi.cmp(pj) }
                }
        }
    });

    *ORDERED_ROUTE_IDX.write().unwrap() = Some(idx);
}


pub fn init_routes(routes: &mut [RouteRule]) {
    compile_filters_on_routes(routes);
    init_routes_order(routes);
}

fn matches_prefix(path: &str, prefix: &str) -> bool {
    let path_norm = canonicalize_path_for_match(path);
    let pref_norm = canonicalize_prefix(prefix);
    if pref_norm == "/" { return true; }
    path_norm == pref_norm || path_norm.starts_with(&(pref_norm.clone() + "/"))
}

pub fn match_route<'a>(raw_path: &str, routes: &'a [RouteRule]) -> Option<&'a RouteRule> {
    {
        let guard = ORDERED_ROUTE_IDX.read().unwrap();
        if let Some(order) = guard.as_ref() {
            if order.iter().all(|&i| i < routes.len()) {
                for &i in order {
                    let r = &routes[i];
                    if matches_prefix(raw_path, &r.prefix) {
                        return Some(r);
                    }
                }
                return None;
            }
        }
    }

    let mut idx: Vec<usize> = (0..routes.len()).collect();
    idx.sort_by(|&i, &j| {
        let pi = routes[i].prefix.as_str();
        let pj = routes[j].prefix.as_str();
        let ri = pi == "/";
        let rj = pj == "/";
        match (ri, rj) {
            (true,  false) => std::cmp::Ordering::Greater,
                (false, true ) => std::cmp::Ordering::Less,
                _ => {
                    let li = norm_len(pi);
                    let lj = norm_len(pj);
                    if li != lj { lj.cmp(&li) } else { pi.cmp(pj) }
                }
        }
    });

    for &i in &idx {
        let r = &routes[i];
        if matches_prefix(raw_path, &r.prefix) {
            return Some(r);
        }
    }
    None
}

pub fn inject_header(mut builder: Builder, username: &str, config: &AppConfig) -> Builder {
    if username.is_empty() {
        return builder;
    }

    if let Ok(val) = hyper::header::HeaderValue::from_str(username) {
        builder = builder.header("x-user", val);
    }

    if let Some(user) = config.users.iter().find(|u| u.username == username) {
        if let Some(roles) = &user.roles {
            let roles_str = roles.join(",");
            if let Ok(val) = hyper::header::HeaderValue::from_str(&roles_str) {
                builder = builder.header("x-user-roles", val);
            }
        }
    }

    builder
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
    if req.method() == actix_web::http::Method::OPTIONS {
        let origin_header = req.headers().get(header::ORIGIN);
        let origin = origin_header.and_then(|v| v.to_str().ok());

        let allowed = data.config.cors_origins.as_ref();

        let is_allowed = match (origin, allowed) {
            (Some(o), Some(list)) => {
                let origin_normalized = o.trim_end_matches('/');
                list.iter()
                    .any(|allowed| allowed.trim_end_matches('/') == origin_normalized)
            }
            _ => false,
        };

        if let (Some(origin_str), true) = (origin, is_allowed) {
            return Ok(HttpResponse::Ok()
                .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str))
                .insert_header((
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    "GET, POST, PUT, DELETE, OPTIONS",
                ))
                .insert_header((
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "Authorization, Content-Type, Accept",
                ))
                .insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"))
                .finish());
        } else {
            return Ok(HttpResponse::Forbidden().body("CORS origin not allowed"));
        }
    }

    let path = req.path();
    let method = req.method().as_str();
    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "-".to_string());
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-");

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
        info!("{} 404 {} {} {}", ip, method, path, user_agent);
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
    let user_agent = req
    .headers()
    .get("User-Agent")
    .and_then(|h| h.to_str().ok())
    .unwrap_or("-");

    let add_cors_headers = |resp: &mut HttpResponseBuilder, req: &HttpRequest| {
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            let origin_trimmed = origin.trim_end_matches('/');

            let is_allowed = data
                .config
                .cors_origins
                .as_ref()
                .map(|list| {
                    list.iter()
                        .any(|allowed| allowed.trim_end_matches('/') == origin_trimmed)
                })
                .unwrap_or(false);

            if is_allowed {
                let method_str = req.method().as_str();

                resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
                resp.insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, method_str));
                resp.insert_header((
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "Authorization, Content-Type, Accept",
                ));
                resp.insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
            }
        }
    };

   if let Some(rule) = match_route(path, &data.routes.routes) {

       if let Some(status) = apply_filters_regex_allow_only(rule, &req, &body) {
           let mut resp = HttpResponse::build(status);
           resp.insert_header(("server", "ProxyAuth"));
           add_cors_headers(&mut resp, &req);
           warn!(
               "[{}] - {} {} {} {}",
               ip,
               path,
               method,
               "403 acl no match".to_string(),
                 user_agent
           );
           return Ok(resp.body("403 Forbidden"));
       }

       if !is_method_allowed(rule.allow_methods.as_deref(), req.method()) {
           let allow = build_allow_header(rule.allow_methods.as_deref());
           let mut resp = HttpResponse::build(StatusCode::METHOD_NOT_ALLOWED);
           resp.insert_header(("Allow", allow));
           resp.insert_header(("server", "ProxyAuth"));
           add_cors_headers(&mut resp, &req);
           warn!(
               "[{}] - {} {} {} {}",
               ip,
               path,
               method,
               "405 method not allowed".to_string(),
               user_agent
           );
           return Ok(resp.body("405 Method Not Allowed"));
       }

        // verify csrf token
        if data.config.session_cookie && data.config.csrf_token && rule.need_csrf {
            if !validate_csrf_token(method, &req, &body, &data.config.secret) {
                use actix_web::{HttpResponse, http::StatusCode};

                let html = r#"<!doctype html>
                <html lang="en">
                <head><meta charset="utf-8"><title>401 Unauthorized</title></head>
                <body><h1>invalid csrf request</h1></body>
                </html>"#;

                let mut resp = HttpResponse::build(StatusCode::UNAUTHORIZED);
                resp.insert_header(("server", "ProxyAuth"));
                resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));
                resp.insert_header((header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0"));
                resp.insert_header(("Pragma", "no-cache"));
                resp.insert_header(("Expires", "0"));
                add_cors_headers(&mut resp, &req);
                warn!(
                    "[{}] - {} {} {} {}",
                    ip,
                    path,
                    method,
                    "401 invalid csrf".to_string(),
                      user_agent
                );
                return Ok(resp.body(html));
            }
        }

        let mut user_agent = "";

        // fix allow redirect pârams inside the GET method.
        let original_uri = req.uri();
        let path_no_query = original_uri.path();

        let prefix_norm = rule.prefix.trim_end_matches('/');

        let raw_forward = path_no_query
        .strip_prefix(prefix_norm)
        .unwrap_or(path_no_query);

        let cleaned_remainder = raw_forward
        .trim_start_matches('/')
        .trim_end_matches('/');

        let forward_path = if !rule.secure_path {
            if rule.preserve_prefix {
                let p = path_no_query.trim_start_matches('/');
                if p.is_empty() { String::new() } else { format!("/{}", p) }
            } else {
                if cleaned_remainder.is_empty() { String::new() } else { format!("/{}", cleaned_remainder) }
            }
        } else {
            String::new()
        };

        let mut target_url = rule.target.trim_end_matches('/').to_string();

        target_url.push_str(&forward_path);

        if let Some(q) = original_uri.query() {
            if target_url.contains('?') { target_url.push('&'); } else { target_url.push('?'); }
            target_url.push_str(q);
        }

        let full_url = if target_url.starts_with("http://") || target_url.starts_with("https://") {
            target_url
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
                .or_else(|| {
                    let is_https = req.connection_info().scheme() == "https";
                    if !is_https {
                        return None;
                    }

                    req.headers()
                        .get(header::COOKIE)
                        .and_then(|val| val.to_str().ok())
                        .and_then(|cookie_str| {
                            cookie_str.split(';').find_map(|cookie| {
                                let cookie = cookie.trim();
                                if let Some((key, value)) = cookie.split_once('=') {
                                    if key.trim() == "session_token" {
                                        return Some(value.trim());
                                    }
                                }
                                None
                            })
                        })
                })
                .ok_or_else(|| {
                    let mut resp = HttpResponse::Unauthorized();
                    resp.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut resp, &req);
                    error::InternalError::from_response("Missing token", resp.finish())
                })?;

            let (username, token_id, _expiry) =
                match validate_token(token_header, &data, &data.config, &ip).await {
                    Ok(result) => result,
                    Err(err) => {
                        warn!(
                            client_ip = %ip,
                            "Unauthorized token attempt: {}", err
                        );
                        let mut resp = HttpResponse::Unauthorized();
                        resp.append_header(("server", "ProxyAuth"));
                        add_cors_headers(&mut resp, &req);
                        return Ok(resp.body("403 Forbidden"));
                    }
                };

            if !rule.username.contains(&username) {
                warn!(
                    client_ip = %ip,
                    username = %username,
                    path = %forward_path,
                    target = %full_url,
                    "This username is not authorized to access"
                );
                let mut resp = HttpResponse::Unauthorized();
                resp.append_header(("server", "ProxyAuth"));
                add_cors_headers(&mut resp, &req);
                return Ok(resp.body("403 Forbidden"));
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

        request_builder = inject_header(request_builder, &username, &data.config);

        let hyper_req = if method == Method::GET || method == Method::HEAD {
            match request_builder.body(Body::empty()) {
                Ok(req) => req,
                Err(e) => {
                    warn!(client_ip = %ip, target = %full_url, "Request build failed (GET): {}", e);
                    let mut resp = HttpResponse::InternalServerError();
                    resp.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut resp, &req);
                    return Ok(resp.finish());
                }
            }
        } else {
            match request_builder.body(Body::from(body)) {
                Ok(req) => req,
                Err(e) => {
                    warn!(client_ip = %ip, target = %full_url, "Request build failed: {}", e);
                    let mut resp = HttpResponse::InternalServerError();
                    resp.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut resp, &req);
                    return Ok(resp.finish());
                }
            }
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
            match timeout(Duration::from_millis(2000), client.request(hyper_req)).await {
                Ok(Ok(res)) => res,
                Ok(Err(e)) => {
                    warn!(client_ip = %ip, target = %full_url, "Upstream error: {}", e);
                    let mut resp = HttpResponse::ServiceUnavailable();
                    resp.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut resp, &req);
                    return Ok(resp.finish());
                }
                Err(e) => {
                    warn!(client_ip = %ip, target = %full_url, "Timeout error: {}", e);
                    let mut resp = HttpResponse::ServiceUnavailable();
                    resp.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut resp, &req);
                    return Ok(resp.finish());
                }
            }
        };

        let status = response_result.status();

        if status.is_server_error() {
            warn!(
                client_ip = %ip,
                target = %full_url,
                "Upstream returned server error: {}", status
            );

            let mut resp = HttpResponse::InternalServerError();
            resp.append_header(("server", "ProxyAuth"));
            add_cors_headers(&mut resp, &req);
            return Ok(resp.finish());
        }

        let mut client_resp = HttpResponse::build(status);

        for (key, value) in response_result.headers() {
            if key != USER_AGENT && key.as_str() != "authorization" && key.as_str() != "server" {
                client_resp.append_header((key.clone(), value.clone()));
            }
        }

        let headers = response_result.headers().clone();

        let mut body_bytes = hyper::body::to_bytes(response_result.into_body())
            .await
            .map_err(|e| {
                warn!(client_ip = %ip, target = %full_url, "Body read error: {}", e);

                let mut resp = HttpResponse::InternalServerError();
                resp.append_header(("server", "ProxyAuth"));
                add_cors_headers(&mut resp, &req);
                error::InternalError::from_response("500 Internal Server Error", resp.finish())
            })?;

        if !rule.cache {
            client_resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));
            client_resp.insert_header((header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0"));
            client_resp.insert_header(("Pragma", "no-cache"));
            client_resp.insert_header(("Expires", "0"));
        }

        if data.config.session_cookie && data.config.csrf_token {
            if let Some((new_body, new_len)) =
                inject_csrf_token(&headers, &body_bytes, &data.config.secret)
            {
                body_bytes = new_body;
                client_resp.insert_header((header::CONTENT_LENGTH, new_len.to_string()));
            }
        }

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

        add_cors_headers(&mut client_resp, &req);
        fix_mime_actix(req.uri().path(), &mut client_resp, status);
        Ok(client_resp
            .append_header(("server", "ProxyAuth"))
            .body(body_bytes))
    } else {
        let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-");
        let method = req.method().as_str();
        let path = req.path();
        info!("[{}] {} {} 404 {}", ip, path, method, user_agent);
        let mut resp = HttpResponse::NotFound();
        add_cors_headers(&mut resp, &req);
        Ok(resp
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
    let user_agent = req
    .headers()
    .get("User-Agent")
    .and_then(|h| h.to_str().ok())
    .unwrap_or("-");

    let add_cors_headers = |resp: &mut HttpResponseBuilder, req: &HttpRequest| {
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            let origin_trimmed = origin.trim_end_matches('/');

            let is_allowed = data
                .config
                .cors_origins
                .as_ref()
                .map(|list| {
                    list.iter()
                        .any(|allowed| allowed.trim_end_matches('/') == origin_trimmed)
                })
                .unwrap_or(false);

            if is_allowed {
                let method_str = req.method().as_str();

                resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
                resp.insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, method_str));
                resp.insert_header((
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "Authorization, Content-Type, Accept",
                ));
                resp.insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
            }
        }
    };

    if let Some(rule) = match_route(path, &data.routes.routes) {

        if let Some(status) = apply_filters_regex_allow_only(rule, &req, &body) {
            let mut resp = HttpResponse::build(status);
            resp.insert_header(("server", "ProxyAuth"));
            add_cors_headers(&mut resp, &req);
            warn!(
                "[{}] - {} {} {} {}",
                ip,
                path,
                method,
                "403 acl no match".to_string(),
                user_agent
            );
            return Ok(resp.body("403 Forbidden"));
        }

        if !is_method_allowed(rule.allow_methods.as_deref(), req.method()) {
            let allow = build_allow_header(rule.allow_methods.as_deref());
            let mut resp = HttpResponse::build(StatusCode::METHOD_NOT_ALLOWED);
            resp.insert_header(("Allow", allow));
            resp.insert_header(("server", "ProxyAuth"));
            add_cors_headers(&mut resp, &req);
            warn!(
                "[{}] - {} {} {} {}",
                ip,
                path,
                method,
                "405 method not allowed".to_string(),
                user_agent
            );
            return Ok(resp.body("405 Method Not Allowed"));
        }

        // verify csrf token
        if data.config.session_cookie && data.config.csrf_token && rule.need_csrf {
            if !validate_csrf_token(method, &req, &body, &data.config.secret) {
                let html = r#"<!doctype html>
                <html lang="en">
                <head><meta charset="utf-8"><title>401 Unauthorized</title></head>
                <body><h1>invalid csrf request</h1></body>
                </html>"#;

                let mut resp = HttpResponse::build(StatusCode::UNAUTHORIZED);
                resp.insert_header(("server", "ProxyAuth"));
                resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));
                resp.insert_header((header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0"));
                resp.insert_header(("Pragma", "no-cache"));
                resp.insert_header(("Expires", "0"));
                add_cors_headers(&mut resp, &req);
                warn!(
                    "[{}] - {} {} {} {}",
                    ip,
                    path,
                    method,
                    "401 invalid csrf".to_string(),
                    user_agent
                );
                return Ok(resp.body(html));
            }
        }

        let mut user_agent = "";

        let original_uri = req.uri();
        let path_no_query = original_uri.path();

        let prefix_norm = rule.prefix.trim_end_matches('/');

        let raw_forward = path_no_query
        .strip_prefix(prefix_norm)
        .unwrap_or(path_no_query);

        let cleaned_remainder = raw_forward
        .trim_start_matches('/')
        .trim_end_matches('/');

        let forward_path = if !rule.secure_path {
            if rule.preserve_prefix {
                let p = path_no_query.trim_start_matches('/');
                if p.is_empty() { String::new() } else { format!("/{}", p) }
            } else {
                if cleaned_remainder.is_empty() { String::new() } else { format!("/{}", cleaned_remainder) }
            }
        } else {
            String::new()
        };

        let mut target_url = rule.target.trim_end_matches('/').to_string();

        target_url.push_str(&forward_path);

        if let Some(q) = original_uri.query() {
            if target_url.contains('?') { target_url.push('&'); } else { target_url.push('?'); }
            target_url.push_str(q);
        }

        let full_url = if target_url.starts_with("http://") || target_url.starts_with("https://") {
            target_url
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
                .or_else(|| {
                    let is_https = req.connection_info().scheme() == "https";
                    if !is_https {
                        return None;
                    }

                    req.headers()
                        .get(header::COOKIE)
                        .and_then(|val| val.to_str().ok())
                        .and_then(|cookie_str| {
                            cookie_str.split(';').find_map(|cookie| {
                                let cookie = cookie.trim();
                                if let Some((key, value)) = cookie.split_once('=') {
                                    if key.trim() == "session_token" {
                                        return Some(value.trim());
                                    }
                                }
                                None
                            })
                        })
                })
                .ok_or_else(|| {
                    info!(
                        "[{}] {} {} 401 Unauthorized token attempt {}",
                        ip, path, method, user_agent
                    );
                    let mut resp = HttpResponse::Unauthorized();
                    resp.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut resp, &req);
                    error::InternalError::from_response("Missing token", resp.finish())
                })?;

            let (username, token_id, _expiry) =
                match validate_token(token_header, &data, &data.config, &ip).await {
                    Ok(result) => result,
                    Err(_err) => {
                        info!(
                            "[{}] {} {} 401 Unauthorized token attempt {}",
                            ip, path, method, user_agent
                        );
                        let mut resp = HttpResponse::Unauthorized();
                        resp.append_header(("server", "ProxyAuth"));
                        add_cors_headers(&mut resp, &req);
                        return Ok(resp.body("401 Unauthorized"));
                    }
                };

            if !rule.username.contains(&username) {
                info!(
                    "[{}] {} {} 401 Unauthorized token attempt {}",
                    ip, path, method, user_agent
                );
                let mut resp = HttpResponse::Unauthorized();
                resp.append_header(("server", "ProxyAuth"));
                add_cors_headers(&mut resp, &req);
                return Ok(resp.body("401 Unauthorized"));
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

        request_builder = inject_header(request_builder, &username, &data.config);

        let hyper_req = if method == Method::GET || method == Method::HEAD {
            match request_builder.body(Body::empty()) {
                Ok(req) => req,
                Err(e) => {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Route fallback: 500 Internal error (GET/HEAD): {}", e
                    );

                    let mut builder = HttpResponse::InternalServerError();
                    builder.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut builder, &req);
                    return Ok(builder.finish());
                }
            }
        } else {
            match request_builder.body(Body::from(body)) {
                Ok(req) => req,
                Err(e) => {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Route fallback: 500 Internal error reason: {}", e
                    );

                    let mut builder = HttpResponse::InternalServerError();
                    builder.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut builder, &req);
                    return Ok(builder.finish());
                }
            }
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

            let response = match forward_failover(hyper_req, &backends, None).await {
                Ok(res) => res,
                Err(e) => {
                    warn!(client_ip = %ip, target = %full_url, "Failover failed: {}", e);

                    let mut builder = HttpResponse::ServiceUnavailable();
                    builder.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut builder, &req);
                    return Ok(builder.finish());
                }
            };

            response
        } else {
            // Mode direct
            match timeout(Duration::from_millis(2000), client.request(hyper_req)).await {
                Ok(Ok(res)) => res,
                Ok(Err(e)) => {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Route fallback reason (client error): {}", e
                    );

                    let mut resp = HttpResponse::ServiceUnavailable();
                    resp.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut resp, &req);
                    return Ok(resp.finish());
                }
                Err(e) => {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Route fallback reason (timeout): {}", e
                    );

                    let mut resp = HttpResponse::ServiceUnavailable();
                    resp.append_header(("server", "ProxyAuth"));
                    add_cors_headers(&mut resp, &req);
                    return Ok(resp.finish());
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

            let mut resp = HttpResponse::InternalServerError();
            resp.append_header(("server", "ProxyAuth"));

            add_cors_headers(&mut resp, &req);

            return Ok(resp.finish());
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

        let mut body_bytes = hyper::body::to_bytes(body).await.map_err(|e| {
            warn!(client_ip = %ip, target = %full_url, "Body read error: {}", e);
            error::ErrorInternalServerError("500 Internal Server Error")
        })?;

        if !rule.cache {
            client_resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));
            client_resp.insert_header((header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0"));
            client_resp.insert_header(("Pragma", "no-cache"));
            client_resp.insert_header(("Expires", "0"));
        }

        if data.config.session_cookie && data.config.csrf_token {
            if let Some((new_body, new_len)) =
                inject_csrf_token(&headers, &body_bytes, &data.config.secret)
            {
                body_bytes = new_body;
                client_resp.insert_header((header::CONTENT_LENGTH, new_len.to_string()));
            }
        }

        info!(
            "[{}] - {} {} {} {} {} [tid:{}] {}",
            ip,
            path,
            method,
            status.as_u16(),
            body_bytes.len(),
            username,
            token_id,
            user_agent
        );

        add_cors_headers(&mut client_resp, &req);
        fix_mime_actix(req.uri().path(), &mut client_resp, status);
        Ok(client_resp
            .append_header(("server", "ProxyAuth"))
            .body(body_bytes))
    } else {
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("-");
        let method = req.method().as_str();
        let path = req.path();
        info!("[{}] {} {} 404 {}", ip, path, method, user_agent);
        let mut resp = HttpResponse::NotFound();
        add_cors_headers(&mut resp, &req);
        Ok(resp
            .append_header(("server", "ProxyAuth"))
            .body("404 Not Found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use std::collections::HashMap;
    use serial_test::serial;

    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://upstream".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: false,

            preserve_prefix: false,
            secure_path: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    // -----------------------------
    // is_method_allowed
    // -----------------------------
    #[test]
    async fn test_is_method_allowed_none_allows_any() {
        assert!(is_method_allowed(None, &Method::GET));
        assert!(is_method_allowed(None, &Method::POST));
        assert!(is_method_allowed(None, &Method::DELETE));
    }

    #[test]
    async fn test_is_method_allowed_wildcard() {
        let allow = vec!["*".to_string()];
        assert!(is_method_allowed(Some(&allow), &Method::GET));
        assert!(is_method_allowed(Some(&allow), &Method::PATCH));
        assert!(is_method_allowed(Some(&allow), &Method::OPTIONS));
    }

    #[test]
    async fn test_is_method_allowed_exact_and_case_insensitive() {
        let allow = vec!["get".into(), "PoSt".into()];
        assert!(is_method_allowed(Some(&allow), &Method::GET));
        assert!(is_method_allowed(Some(&allow), &Method::POST));
        assert!(!is_method_allowed(Some(&allow), &Method::DELETE));
    }

    // -----------------------------
    // build_allow_header
    // -----------------------------
    #[test]
    async fn test_build_allow_header_none_returns_all() {
        let h = build_allow_header(None);
        for m in ["GET","HEAD","POST","PUT","DELETE","PATCH","OPTIONS"] {
            assert!(h.contains(m), "header no content {m}: {h}");
        }
    }

    #[test]
    async fn test_build_allow_header_wildcard_is_all() {
        let allow = vec!["*".into()];
        let h = build_allow_header(Some(&allow));
        for m in ["GET","HEAD","POST","PUT","DELETE","PATCH","OPTIONS"] {
            assert!(h.contains(m), "header not content {m}: {h}");
        }
    }

    #[test]
    async fn test_build_allow_header_sorted_dedup_and_includes_options() {
        let allow = vec!["post".into(), "GET".into(), "get".into()];
        let h = build_allow_header(Some(&allow));
        assert!(h.contains("GET"));
        assert!(h.contains("POST"));
        assert!(h.contains("OPTIONS"));
        assert_eq!(h.matches("GET").count(), 1, "GET double: {h}");
    }

    // -----------------------------
    // canonicalize_prefix / matches_prefix
    // -----------------------------
    #[test]
    async fn test_canonicalize_prefix_basic() {
        assert_eq!(canonicalize_prefix(""), "/");
        assert_eq!(canonicalize_prefix("/"), "/");
        assert_eq!(canonicalize_prefix("/api/"), "/api");
        assert_eq!(canonicalize_prefix("/api"), "/api");
    }

    #[test]
    async fn test_matches_prefix_root_matches_all() {
        assert!(matches_prefix("/nimporte/quoi", "/"));
        assert!(matches_prefix("/", "/"));
    }

    #[test]
    async fn test_matches_prefix_basic_and_subpaths() {
        assert!(matches_prefix("/api", "/api"));
        assert!(matches_prefix("/api/", "/api"));
        assert!(matches_prefix("/api/v1/users", "/api"));
        assert!(!matches_prefix("/ap", "/api"));
    }

    #[test]
    async fn test_matches_prefix_percent_decoding() {
        assert!(matches_prefix("/api%2Fadmin", "/api/admin"));
        assert!(matches_prefix("/api/admin", "/api%2Fadmin"));
    }

    // -----------------------------
    // match_route + init_routes
    // -----------------------------
    #[test]
    #[serial]
    async fn test_match_route_prefers_longest_prefix() {
        let mut routes = vec![ rr("/"), rr("/api"), rr("/api/admin") ];
        init_routes(&mut routes);

        let r = match_route("/api/admin/users", &routes).expect("attempt route");
        assert_eq!(r.prefix, "/api/admin");

        let r = match_route("/api/metrics", &routes).expect("attempt route");
        assert_eq!(r.prefix, "/api");

        let r = match_route("/static/app.js", &routes).expect("attempt route");
        assert_eq!(r.prefix, "/");
    }

    // -----------------------------
    // client_ip
    // -----------------------------
    #[test]
    async fn test_client_ip_from_x_forwarded_for() {
        let req = test::TestRequest::default()
        .insert_header(("x-forwarded-for", "203.0.113.7, 1.1.1.1"))
        .to_http_request();
        let ip = client_ip(&req).expect("ip attendue");
        assert_eq!(ip.to_string(), "203.0.113.7");
    }

    #[test]
    async fn test_client_ip_from_x_real_ip() {
        let req = test::TestRequest::default()
        .insert_header(("x-real-ip", "198.51.100.42"))
        .to_http_request();
        let ip = client_ip(&req).expect("ip attendue");
        assert_eq!(ip.to_string(), "198.51.100.42");
    }

    #[test]
    async fn test_client_ip_from_peer_addr() {
        let req = test::TestRequest::default()
        .peer_addr("192.0.2.10:51234".parse().unwrap())
        .to_http_request();
        let ip = client_ip(&req).expect("ip attendue");
        assert_eq!(ip.to_string(), "192.0.2.10");
    }

    #[test]
    async fn test_client_ip_none_when_missing() {
        let req = test::TestRequest::default().to_http_request();
        assert!(client_ip(&req).is_none());
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;
    use crate::RouteConfig;
    use actix_web::{http, test};
    use dashmap::DashMap;
    use hyper::client::HttpConnector;
    use hyper_proxy::{Intercept, Proxy, ProxyConnector};
    use hyper_rustls::HttpsConnectorBuilder;
    use std::sync::Arc;

    // ---------- helpers ----------

    fn make_https_client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
        hyper::Client::builder().build::<_, Body>(https)
    }

    fn make_proxy_client() -> hyper::Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_nodelay(true);
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);

        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:9".parse().unwrap());
        let proxy_connector = ProxyConnector::from_proxy(https, proxy).expect("proxy connector");
        hyper::Client::builder().build(proxy_connector)
    }

    fn base_config() -> AppConfig {
        AppConfig {
            secret: "secret-for-tests".into(),
            session_cookie: true,
            csrf_token: true,
            cors_origins: Some(vec!["https://example.com".to_string()]),
            ..Default::default()
        }
    }

    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "upstream.invalid".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: true,
            preserve_prefix: false,
            secure_path: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    fn make_state_with_routes(mut routes: Vec<RouteRule>, cfg: AppConfig) -> web::Data<AppState> {
        init_routes(&mut routes);

        let cfg = Arc::new(cfg);
        web::Data::new(AppState {
            config: cfg,
            routes: Arc::new(RouteConfig { routes }),
            counter: Arc::new(crate::CounterToken::new()),
            client_normal: make_https_client(),
            client_with_cert: make_https_client(),
            client_with_proxy: make_proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        })
    }

    // ---------- inject_header ----------

    #[test]
    async fn inject_header_no_username_adds_nothing() {
        let cfg = base_config();
        let b = Request::builder();
        let b = inject_header(b, "", &cfg);
        let req = b.body(Body::empty()).unwrap();
        assert!(req.headers().get("x-user").is_none());
        assert!(req.headers().get("x-user-roles").is_none());
    }

    #[test]
    async fn inject_header_with_username_and_roles() {
        let mut cfg = base_config();
        cfg.users = vec![crate::config::config::User {
            username: "alice".into(),
            password: "$argon2id$dummy".into(),
            otpkey: None,
            allow: None,
            roles: Some(vec!["admin".into(), "dev".into()]),
        }];

        let b = Request::builder();
        let b = inject_header(b, "alice", &cfg);
        let req = b.body(Body::empty()).unwrap();

        assert_eq!(req.headers().get("x-user").unwrap(), "alice");
        let roles = req.headers().get("x-user-roles").unwrap().to_str().unwrap();
        assert!(
            roles == "admin,dev" || roles == "dev,admin",
        );
    }

    // ---------- global_proxy: CORS/OPTIONS + 404 ----------

    #[tokio::test]
    async fn options_cors_allowed() {
        let data = make_state_with_routes(vec![rr("/"), rr("/api"), rr("/adm")], base_config());

        let req = test::TestRequest::default()
        .method(http::Method::OPTIONS)
        .insert_header((http::header::ORIGIN, "https://example.com"))
        .uri("/anything")
        .to_http_request();

        let resp = super::global_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let h = resp.headers();
        assert_eq!(h.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "https://example.com");
        assert!(h.get(http::header::ACCESS_CONTROL_ALLOW_METHODS).is_some());
        assert!(h.get(http::header::ACCESS_CONTROL_ALLOW_HEADERS).is_some());
    }

    #[tokio::test]
    async fn options_cors_forbidden() {
        let mut cfg = base_config();
        cfg.cors_origins = Some(vec!["https://allowed.example".into()]);
        let data = make_state_with_routes(vec![rr("/"), rr("/api"), rr("/adm")], cfg);

        let req = test::TestRequest::default()
        .method(http::Method::OPTIONS)
        .insert_header((http::header::ORIGIN, "https://not-allowed.example"))
        .uri("/x")
        .to_http_request();

        let resp = super::global_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn global_proxy_404_when_no_route_matches() {
        let data = make_state_with_routes(vec![rr("/api"), rr("/adm"), rr("/only")], base_config());
        let req = test::TestRequest::default()
        .method(http::Method::GET)
        .uri("/not/matching")
        .to_http_request();

        let resp = super::global_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
    }

    #[test]
    async fn client_ip_priority_header_order() {
        let req = test::TestRequest::default()
        .insert_header(("x-real-ip", "192.0.2.9"))
        .insert_header(("x-forwarded-for", "203.0.113.77, 10.0.0.1"))
        .peer_addr("198.51.100.1:4000".parse().unwrap())
        .to_http_request();

        let ip = super::client_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.77");
    }
}


#[cfg(test)]
mod tests_csrf {
    use super::*;
    use actix_web::{test, http::{header, Method, StatusCode}};
    use hyper::{Body, Client};
    use hyper::client::HttpConnector;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};
    use std::sync::Arc;
    use crate::config::config::{AppConfig, AppState, RouteConfig, RouteRule};
    use crate::stats::tokencount::CounterToken;
    use dashmap::DashMap;
    use serial_test::serial;

    // --- helpers -------------------------------------------------------------

    fn https_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        Client::builder().build::<_, Body>(https)
    }

    fn proxy_client() -> Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        Client::builder().build(pc)
    }

    fn make_state_with_routes(routes: Vec<RouteRule>, mut cfg: AppConfig) -> actix_web::web::Data<AppState> {
        cfg.session_cookie = true;
        cfg.csrf_token = true;

        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes }),
            counter: Arc::new(CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        };
        actix_web::web::Data::new(state)
    }

    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://upstream.example".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: true,
            cache: false,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    fn base_config() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "test-secret-123".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 10,
            timezone: "UTC".into(),
            login_via_otp: false,
            max_connections: 1024,
            pending_connections_limit: 1024,
            socket_listen: 128,
            client_timeout: 1000,
            keep_alive: 1,
            num_instances: 1,
            redis: None,
            cors_origins: None,
            session_cookie: true,
            max_age_session_cookie: 3600,
            login_redirect_url: None,
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
        }
    }

    // --- TEST ---------------------------------------------------------------

    // ---------- proxy_without_proxy: 405 + 401 (CSRF) ----------

    #[tokio::test]
    #[serial]
    async fn proxy_without_proxy_method_not_allowed_returns_405_with_allow() {
        let mut r = rr("/svc");
        r.allow_methods = Some(vec!["GET".into()]);

        let mut routes_vec = vec![ rr("/"), r, rr("/adm") ];
        init_routes(&mut routes_vec);

        let data = make_state_with_routes(routes_vec, base_config());

        let req = actix_web::test::TestRequest::default()
        .method(actix_web::http::Method::POST)
        .uri("/svc/resource")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::from_static(b"{}"), data)
        .await
        .unwrap();

        assert_eq!(resp.status(), actix_web::http::StatusCode::METHOD_NOT_ALLOWED);
        let allow = resp.headers().get(actix_web::http::header::ALLOW).unwrap().to_str().unwrap();
        assert!(allow.contains("GET"));
        assert!(allow.contains("OPTIONS"));
    }

    #[actix_web::test]
    #[serial]
    async fn proxy_without_proxy_csrf_invalid_returns_401_html() {

        super::_reset_route_order_for_tests();

        let mut routes = vec![ rr("/svc") ];
        super::init_routes(&mut routes);

        let data = make_state_with_routes(routes, base_config());

        let req = test::TestRequest::default()
        .method(Method::POST)
        .uri("/svc/resource")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();

        let body = actix_web::web::Bytes::from_static(br#"{}"#);

        let resp = super::proxy_without_proxy(req, body, data).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
        assert!(ctype.starts_with("text/html"));
    }
}


#[cfg(test)]
mod tests_proxy {
    use actix_web::{test, web};
    use actix_web::http::{header, Method, StatusCode};
    use hyper::{Body, Client};
    use hyper::client::HttpConnector;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};
    use std::sync::Arc;
    use crate::config::config::{AppConfig, AppState, RouteConfig, RouteRule};
    use crate::stats::tokencount::CounterToken;
    use dashmap::DashMap;
    use serial_test::serial;

    // --- helpers -------------------------------------------------------------

    fn https_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        Client::builder().build::<_, Body>(https)
    }

    fn proxy_client() -> Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        Client::builder().build(pc)
    }

    fn make_state_with_routes(routes: Vec<RouteRule>, mut cfg: AppConfig) -> web::Data<AppState> {
        let mut seed = routes.clone();
        super::init_routes(&mut seed);

        cfg.session_cookie = true;
        cfg.csrf_token = true;

        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes }),
            counter: Arc::new(CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        };
        web::Data::new(state)
    }

    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://upstream.example".into(),
            username: vec![],
            secure: false,
            proxy: true,
            proxy_config: "http://0.0.0.0:5000".into(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: true,
            cache: false,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    fn base_config() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "test-secret-123".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 10,
            timezone: "UTC".into(),
            login_via_otp: false,
            max_connections: 1024,
            pending_connections_limit: 1024,
            socket_listen: 128,
            client_timeout: 1000,
            keep_alive: 1,
            num_instances: 1,
            redis: None,
            cors_origins: None,
            session_cookie: true,
            max_age_session_cookie: 3600,
            login_redirect_url: None,
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
        }
    }

    // --- TESTS ---------------------------------------------------------------

    // ---------- proxy_with_proxy: (405) ----------
    #[tokio::test]
    #[serial]
    async fn proxy_with_proxy_method_not_allowed_returns_405() {
        let mut r = rr("/p");
        r.proxy = true;
        r.need_csrf = false;
        r.allow_methods = Some(vec!["GET".into()]);

        let data = make_state_with_routes(vec![rr("/"), r.clone(), rr("/adm")], base_config());

        let req = test::TestRequest::default()
        .method(Method::POST)
        .uri("/p/thing")
        .to_http_request();

        let resp = super::proxy_with_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // ---------- proxy_with_proxy: (401 CSRF) ----------
    #[tokio::test]
    #[serial]
    async fn proxy_with_proxy_csrf_invalid_returns_401() {
        let mut r = rr("/pcsrf");
        r.proxy = true;
        r.need_csrf = true;

        let mut cfg = base_config();
        cfg.session_cookie = true;
        cfg.csrf_token = true;

        let data = make_state_with_routes(vec![rr("/"), r.clone(), rr("/adm")], cfg);

        let req = test::TestRequest::default()
        .method(Method::POST)
        .uri("/pcsrf/submit")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(r#"{"hello":"world"}"#)
        .to_http_request();

        let resp = super::proxy_with_proxy(
            req,
            web::Bytes::from_static(br#"{"hello":"world"}"#),
                                           data
        ).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod extra_unit_tests {
    use super::*;
    use actix_web::http::Method;
    use serial_test::serial;

    // ---------- norm_len ----------
    #[test]
    fn norm_len_root_is_zero() {
        assert_eq!(super::norm_len("/"), 0);
    }

    #[test]
    fn norm_len_trims_trailing_slash() {
        assert_eq!(super::norm_len("/api/"), 4);
        assert_eq!(super::norm_len("/api"), 4);
    }

    // ---------- is_method_allowed ----------
    #[test]
    fn is_method_allowed_empty_list_denies_all() {
        let allow: Vec<String> = vec![];
        assert!(!super::is_method_allowed(Some(&allow), &Method::GET));
        assert!(!super::is_method_allowed(Some(&allow), &Method::POST));
    }

    // ---------- build_allow_header ----------
    #[test]
    fn build_allow_header_uppercases_dedups_and_adds_options() {
        let allow = vec!["get".into(), "GET".into(), "post".into()];
        let h = super::build_allow_header(Some(&allow));
        // uppercased + dedup
        assert!(h.contains("GET"));
        assert!(h.contains("POST"));
        assert_eq!(h.matches("GET").count(), 1, "GET en double: {h}");
        assert!(h.contains("OPTIONS"));
        assert_eq!(h.matches("get").count(), 0);
    }

    // ---------- canonicalize_prefix ----------
    #[test]
    fn canonicalize_prefix_normalizes_and_decodes() {
        assert_eq!(super::canonicalize_prefix(""), "/");
        assert_eq!(super::canonicalize_prefix("/"), "/");
        assert_eq!(super::canonicalize_prefix("/api/"), "/api");
        // %2F -> '/'
        assert_eq!(super::canonicalize_prefix("/a%2Fb"), "/a/b");
    }

    // ---------- init_routes_order / match_route ----------
    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://upstream".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: false,
            preserve_prefix: false,
            secure_path: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    #[test]
    #[serial]
    fn init_routes_order_prefers_longest_then_lexicographic() {
        // /assets/design/test
        // /assets/design
        // /assets
        // /
        let routes = vec![
            rr("/"),
            rr("/assets"),
            rr("/assets/design"),
            rr("/assets/design/test"),
        ];
        super::init_routes_order(&routes);
        let order_opt = super::ORDERED_ROUTE_IDX.read().unwrap().clone();
        let order = order_opt.expect("order should be set");
        let ordered_prefixes: Vec<&str> = order.iter().map(|&i| routes[i].prefix.as_str()).collect();

        assert_eq!(ordered_prefixes, vec![
            "/assets/design/test",
            "/assets/design",
            "/assets",
            "/",
        ]);
    }

    #[test]
    #[serial]
    fn match_route_falls_back_when_cached_order_is_invalid() {
        let mut seed = vec![ rr("/"), rr("/a"), rr("/a/b") ];
        super::init_routes(&mut seed);

        {
            let mut guard = super::ORDERED_ROUTE_IDX.write().unwrap();
            *guard = Some(vec![9999, 42]); // invalide pour la suite
        }

        let routes = vec![ rr("/"), rr("/api"), rr("/api/admin") ];
        let r = super::match_route("/api/admin/x", &routes).expect("route attendue");
        assert_eq!(r.prefix, "/api/admin");
    }

    // ---------- inject_header ----------
    #[test]
    fn inject_header_adds_only_x_user_when_no_roles() {
        let mut cfg = AppConfig::default();
        cfg.users = vec![crate::config::config::User {
            username: "bob".into(),
            password: "$argon2id$dummy".into(),
            otpkey: None,
            allow: None,
            roles: None,
        }];
        let b = Request::builder();
        let b = super::inject_header(b, "bob", &cfg);
        let req = b.body(Body::empty()).unwrap();
        assert_eq!(req.headers().get("x-user").unwrap(), "bob");
        assert!(req.headers().get("x-user-roles").is_none());
    }

    // ---------- client_ip ----------
    #[test]
    fn client_ip_malformed_headers_return_none_if_no_peer() {
        use actix_web::test;
        let req = test::TestRequest::default()
        .insert_header(("x-real-ip", "not-an-ip")) // invalid
        .to_http_request();
        assert!(super::client_ip(&req).is_none());
    }
}

#[cfg(test)]
mod extra_integrationish_tests {
    use super::*;
    use actix_web::{test, http::{self, Method, StatusCode}};
    use std::sync::Arc;
    use dashmap::DashMap;
    use serial_test::serial;

    fn base_config() -> AppConfig {
        AppConfig {
            secret: "secret-for-tests".into(),
            session_cookie: true,
            csrf_token: true,
            cors_origins: Some(vec!["https://allowed.example".into()]),
            ..Default::default()
        }
    }

    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "upstream.invalid".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: true,
            preserve_prefix: false,
            secure_path: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    fn make_state(routes: Vec<RouteRule>, cfg: AppConfig) -> web::Data<AppState> {
        let mut routes = routes;
        super::init_routes(&mut routes);
        web::Data::new(AppState {
            config: Arc::new(cfg),
                       routes: Arc::new(crate::RouteConfig { routes }),
                       counter: Arc::new(crate::CounterToken::new()),
                       client_normal: {
                           use hyper::client::HttpConnector;
                           use hyper_rustls::HttpsConnectorBuilder;
                           let mut http = HttpConnector::new();
                           http.enforce_http(false);
                           http.set_nodelay(true);
                           let https = HttpsConnectorBuilder::new()
                           .with_native_roots()
                           .https_or_http()
                           .enable_http1()
                           .wrap_connector(http);
                           hyper::Client::builder().build::<_, Body>(https)
                       },
                       client_with_cert: {
                           use hyper::client::HttpConnector;
                           use hyper_rustls::HttpsConnectorBuilder;
                           let mut http = HttpConnector::new();
                           http.enforce_http(false);
                           http.set_nodelay(true);
                           let https = HttpsConnectorBuilder::new()
                           .with_native_roots()
                           .https_or_http()
                           .enable_http1()
                           .wrap_connector(http);
                           hyper::Client::builder().build::<_, Body>(https)
                       },
                       client_with_proxy: {
                           use hyper::client::HttpConnector;
                           use hyper_rustls::HttpsConnectorBuilder;
                           use hyper_proxy::{Proxy, ProxyConnector, Intercept};
                           let mut http = HttpConnector::new();
                           http.enforce_http(false);
                           http.set_nodelay(true);
                           let https = HttpsConnectorBuilder::new()
                           .with_native_roots()
                           .https_or_http()
                           .enable_http1()
                           .wrap_connector(http);
                           let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:9".parse().unwrap());
                           let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
                           hyper::Client::builder().build(pc)
                       },
                       revoked_tokens: Arc::new(DashMap::new()),
        })
    }

    #[actix_web::test]
    async fn proxy_without_proxy_404_adds_cors_when_origin_allowed() {
        let data = make_state(vec![rr("/a"), rr("/b")], base_config());

        let req = test::TestRequest::default()
        .insert_header((http::header::ORIGIN, "https://allowed.example"))
        .method(Method::GET)
        .uri("/not-matching")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let h = resp.headers();
        assert_eq!(
            h.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://allowed.example"
        );
    }

    #[actix_web::test]
    #[serial]
    async fn proxy_without_proxy_secure_without_token_returns_401() {
        let mut secure_route = rr("/secure");
        secure_route.secure = true;
        secure_route.need_csrf = false;

        let data = make_state(vec![secure_route], base_config());

        let req = actix_web::test::TestRequest::default()
        .method(actix_web::http::Method::GET)
        .uri("/secure/resource")
        .to_http_request();

        let res = super::proxy_without_proxy(req, web::Bytes::new(), data).await;
        assert!(res.is_err(), "expected Err(actix_web::Error) when token is missing");

        let err = res.err().unwrap();
        let resp = err.error_response();
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

}

#[cfg(test)]
mod more_edge_cases {
    use super::*;
    use actix_web::{test, http::{self, Method, StatusCode}};
    use std::sync::Arc;
    use dashmap::DashMap;

    // --- petits helpers --------------------------
    fn base_config() -> AppConfig {
        AppConfig { secret: "s".into(), session_cookie: true, csrf_token: true, ..Default::default() }
    }
    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://up.example".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: true,
            preserve_prefix: false,
            secure_path: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }
    fn make_state(mut routes: Vec<RouteRule>, cfg: AppConfig) -> web::Data<AppState> {
        super::init_routes(&mut routes);
        let cfg = Arc::new(cfg);
        web::Data::new(AppState {
            config: cfg,
            routes: Arc::new(crate::RouteConfig { routes }),
                       counter: Arc::new(crate::CounterToken::new()),
                       client_normal: {
                           use hyper::client::HttpConnector;
                           use hyper_rustls::HttpsConnectorBuilder;
                           let mut http = HttpConnector::new();
                           http.enforce_http(false);
                           http.set_nodelay(true);
                           let https = HttpsConnectorBuilder::new().with_native_roots().https_or_http().enable_http1().wrap_connector(http);
                           hyper::Client::builder().build::<_, Body>(https)
                       },
                       client_with_cert: {
                           use hyper::client::HttpConnector;
                           use hyper_rustls::HttpsConnectorBuilder;
                           let mut http = HttpConnector::new();
                           http.enforce_http(false);
                           http.set_nodelay(true);
                           let https = HttpsConnectorBuilder::new().with_native_roots().https_or_http().enable_http1().wrap_connector(http);
                           hyper::Client::builder().build::<_, Body>(https)
                       },
                       client_with_proxy: {
                           use hyper::client::HttpConnector;
                           use hyper_rustls::HttpsConnectorBuilder;
                           use hyper_proxy::{Proxy, ProxyConnector, Intercept};
                           let mut http = HttpConnector::new();
                           http.enforce_http(false);
                           http.set_nodelay(true);
                           let https = HttpsConnectorBuilder::new().with_native_roots().https_or_http().enable_http1().wrap_connector(http);
                           let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:9".parse().unwrap());
                           let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
                           hyper::Client::builder().build(pc)
                       },
                       revoked_tokens: Arc::new(DashMap::new()),
        })
    }

    #[test]
    async fn build_allow_header_empty_list_gives_only_options() {
        let allow: Vec<String> = vec![];
        let h = super::build_allow_header(Some(&allow));
        assert_eq!(h, "OPTIONS", "expected only OPTIONS for empty allow list");
    }

    #[test]
    async fn match_route_with_cached_order_but_no_match_returns_none() {
        let mut seed = vec![ rr("/api"), rr("/admin") ];
        super::init_routes(&mut seed);

        let routes = vec![ rr("/api"), rr("/admin") ];
        let m = super::match_route("/nope/here", &routes);
        assert!(m.is_none(), "no route should match");
    }

    #[actix_web::test]
    async fn global_proxy_hits_proxy_branch_and_returns_405() {
        let mut p = rr("/p");
        p.proxy = true;
        p.need_csrf = false;
        p.allow_methods = Some(vec!["GET".into()]); // POST => 405
        let data = make_state(vec![p, rr("/")], base_config());

        let req = test::TestRequest::default()
        .method(Method::POST)
        .uri("/p/resource")
        .to_http_request();

        let resp = super::global_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert!(resp.headers().get(http::header::ALLOW).is_some());
    }


    #[actix_web::test]
    async fn proxy_without_proxy_invalid_uri_returns_400() {
        let mut r = rr("/bad");
        r.target = "http:// host avec espace".into();
        let data = make_state(vec![r], base_config());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/bad/x")
        .to_http_request();

        let res = super::proxy_without_proxy(req, web::Bytes::new(), data).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err.as_response_error().status_code(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn proxy_without_proxy_timeout_returns_503_without_cache_headers() {
        let mut r = rr("/nocache");
        r.cache = false;
        r.need_csrf = false;

        let mut cfg = base_config();
        cfg.client_timeout = 1; // force le timeout

        let data = make_state(vec![r], cfg);

        let req = test::TestRequest::default()
        .method(Method::POST)
        .uri("/nocache/any")
        .set_payload("{}")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::from_static(b"{}"), data)
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    async fn match_route_no_cache_no_match_returns_none() {
        super::_reset_route_order_for_tests(); // vide le cache d’ordre
        let routes = vec![ rr("/a"), rr("/b") ];
        let m = super::match_route("/z/zz", &routes);
        assert!(m.is_none());
    }
}

#[cfg(test)]
mod success_paths_and_urls {
    use super::*;
    use actix_web::{test, http::{self, Method, StatusCode}};
    use dashmap::DashMap;
    use hyper::{Body, Response, Request as HyperReq, Server, Client};
    use hyper::service::{make_service_fn, service_fn};
    use hyper::header::{CONTENT_TYPE, SERVER, CONTENT_LENGTH};
    use hyper::client::HttpConnector;
    use hyper_rustls::HttpsConnectorBuilder;
    use std::{convert::Infallible, net::SocketAddr, net::TcpListener, sync::Arc};
    use tokio::task::JoinHandle;
    use serial_test::serial;

    // ---- tiny upstream ----------------------------------------------------
    async fn spawn_upstream(handler: fn(HyperReq<Body>) -> Response<Body>) -> (JoinHandle<()>, SocketAddr) {
        let make_svc = make_service_fn(move |_| async move {
            Ok::<_, Infallible>(service_fn(move |req| async move {
                Ok::<_, Infallible>(handler(req))
            }))
        });
        let srv = Server::try_bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = srv.local_addr();
        let jh = tokio::spawn(async move { srv.serve(make_svc).await.unwrap() });
        (jh, addr)
    }
    fn https_client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let mut http = HttpConnector::new(); http.enforce_http(false); http.set_nodelay(true);
        let https = HttpsConnectorBuilder::new().with_native_roots().https_or_http().enable_http1().wrap_connector(http);
        hyper::Client::builder().build::<_, Body>(https)
    }
    fn proxy_client() -> hyper::Client<hyper_proxy::ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        use hyper_proxy::{Proxy, ProxyConnector, Intercept};
        let mut http = HttpConnector::new(); http.enforce_http(false); http.set_nodelay(true);
        let https = HttpsConnectorBuilder::new().with_native_roots().https_or_http().enable_http1().wrap_connector(http);
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        hyper::Client::builder().build(pc)
    }

    fn make_state_with(mut routes: Vec<RouteRule>, cfg: AppConfig) -> web::Data<AppState> {
        super::init_routes(&mut routes);
        web::Data::new(AppState{
            config: Arc::new(cfg),
                       routes: Arc::new(crate::RouteConfig{ routes }),
                       counter: Arc::new(crate::CounterToken::new()),
                       client_normal: https_client(),
                       client_with_cert: https_client(),
                       client_with_proxy: proxy_client(),
                       revoked_tokens: Arc::new(DashMap::new()),
        })
    }

    async fn spawn_forward_proxy() -> (JoinHandle<()>, SocketAddr) {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let client = Client::builder().build::<_, Body>(https);

        let make_svc = make_service_fn(move |_conn| {
            let client = client.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                    let client = client.clone();
                    async move {
                        let (parts, body) = req.into_parts();
                        let mut out = Request::builder()
                        .method(parts.method)
                        .uri(parts.uri);

                        for (k, v) in parts.headers.iter() {
                            let name = k.as_str().to_ascii_lowercase();
                            if name != "connection"
                                && name != "proxy-connection"
                                && name != "keep-alive"
                                && name != "transfer-encoding"
                                && name != "upgrade"
                                {
                                    out = out.header(k, v);
                                }
                        }

                        let body_bytes = hyper::body::to_bytes(body).await?;
                        let out = out.body(Body::from(body_bytes)).unwrap();

                        let resp = client.request(out).await?;
                        Ok::<_, hyper::Error>(resp)
                    }
                }))
            }
        });

        let std_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind proxy");
        std_listener.set_nonblocking(true).expect("nonblocking");
        let addr = std_listener.local_addr().expect("local_addr");

        let server = Server::from_tcp(std_listener).unwrap().serve(make_svc);

        let jh = tokio::spawn(async move {
            let _ = server.await;
        });

        (jh, addr)
    }


    fn base_cfg() -> AppConfig {
        AppConfig{ secret: "s".into(), session_cookie: true, csrf_token: true, ..Default::default() }
    }

    fn rr(prefix: &str) -> RouteRule {
        RouteRule{
            prefix: prefix.into(), target: "".into(),
            username: vec![], secure:false, proxy:false, proxy_config:String::new(),
            cert: std::collections::HashMap::new(), backends: vec![],
            need_csrf:false, cache:true, preserve_prefix:false, secure_path:false,
            allow_methods: None, filters: None, filters_compiled: None,
        }
    }

    #[actix_web::test]
    async fn proxy_without_proxy_success_no_cache_sets_headers_and_body() {
        let (jh, addr) = spawn_upstream(|_req| {
            Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .header(SERVER, "UpstreamServer/1.0")
            .body(Body::from("<h1>ok</h1>"))
            .unwrap()
        }).await;

        let mut r = rr("/svc");
        r.target = format!("http://{}", addr);
        r.cache = false;
        r.need_csrf = false;

        let data = make_state_with(vec![r], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/svc/index.html?q=1")
        .insert_header((http::header::USER_AGENT, "ClientUA/0"))
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert!(h.get(http::header::CONTENT_TYPE).unwrap().to_str().unwrap().starts_with("text/html"));
        assert_eq!(h.get(http::header::CACHE_CONTROL).unwrap(), "no-store, no-cache, must-revalidate, max-age=0");
        assert_eq!(h.get("Pragma").unwrap(), "no-cache");
        assert_eq!(h.get("Expires").unwrap(), "0");
        assert_eq!(h.get(http::header::SERVER).unwrap(), "ProxyAuth");

        jh.abort();
    }

    #[actix_web::test]
    #[serial]
    async fn proxy_with_proxy_success_basic_headers_mapping() {
        let (jh_up, addr_up) = spawn_upstream(|req| {
            let ua = req.headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
            assert_eq!(ua, "ProxyAuth");
            assert!(req.headers().get(http::header::HOST).is_some());

            Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "application/json")
            .header("X-Up", "y")
            .body(Body::from(r#"{"ok":true}"#))
            .unwrap()
        }).await;

        let (jh_proxy, addr_proxy) = spawn_forward_proxy().await;
        let proxy_url = format!("http://{}", addr_proxy);

        // 3) Route via proxy
        let mut r = rr("/p");
        r.proxy = true;
        r.need_csrf = false;
        r.target = format!("http://{}", addr_up);
        r.proxy_config = proxy_url;

        let data = make_state_with(vec![r], base_cfg());

        // 4) Requête de test
        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/p/path")
        .insert_header((http::header::AUTHORIZATION, "Bearer will_be_stripped"))
        .to_http_request();

        // 5) Appel & vérifs
        let resp = super::proxy_with_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("X-Up").unwrap(), "y");
        assert!(resp.headers().get(http::header::SERVER).is_some());

        // 6) Nettoyage
        jh_up.abort();
        jh_proxy.abort();
    }


    #[actix_web::test]
    #[serial]
    async fn url_build_variants_preserve_and_securepath_and_query_merge() {
        let (jh, addr) = spawn_upstream(|req| {
            let u = req.uri().to_string();
            let b = format!("URI={}", u);
            Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, b.len().to_string())
            .body(Body::from(b))
            .unwrap()
        }).await;

        let mut r1 = rr("/a");
        r1.target = format!("http://{}/base?fixed=1", addr);
        r1.preserve_prefix = true;
        r1.need_csrf = false;

        let mut r2 = rr("/s");
        r2.target = format!("http://{}/base?zz=9", addr);
        r2.secure_path = true;
        r2.need_csrf = false;

        let data = make_state_with(vec![r1.clone(), r2.clone()], base_cfg());

        let req_a = test::TestRequest::default()
        .method(Method::GET)
        .uri("/a/x/y?k=2")
        .to_http_request();
        let resp_a = super::proxy_without_proxy(req_a, web::Bytes::new(), data.clone()).await.unwrap();
        let body_a = actix_web::body::to_bytes(resp_a.into_body()).await.unwrap();
        let s_a = std::str::from_utf8(&body_a).unwrap();
        assert!(s_a.contains("/base"));
        assert!(s_a.contains("/x/y"), "secure_path should be preserved");
        assert!(s_a.contains("fixed=1"));
        assert!(s_a.contains("k=2"));

        let req_b = test::TestRequest::default()
        .method(Method::GET)
        .uri("/s/secret?q=ok")
        .to_http_request();
        let resp_b = super::proxy_without_proxy(req_b, web::Bytes::new(), data).await.unwrap();
        let body_b = actix_web::body::to_bytes(resp_b.into_body()).await.unwrap();
        let s_b = std::str::from_utf8(&body_b).unwrap();
        assert!(s_b.contains("/base"));
        assert!(!s_b.contains("/secret"));
        assert!(s_b.contains("zz=9"));
        assert!(s_b.contains("q=ok"));

        jh.abort();
    }

    #[actix_web::test]
    async fn csrf_injection_sets_content_length() {
        let (jh, addr) = spawn_upstream(|_req| {
            let html = "<html><body><form method='post'></form></body></html>";
            Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(html))
            .unwrap()
        }).await;

        let mut r = rr("/form");
        r.target = format!("http://{}", addr);
        r.need_csrf = true;
        r.cache = true;

        let mut cfg = base_cfg();
        cfg.session_cookie = true;
        cfg.csrf_token = true;

        let data = make_state_with(vec![r], cfg);

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/form")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cl = resp.headers().get(http::header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).unwrap();
        assert!(!cl.is_empty());
        jh.abort();
    }
}

#[cfg(test)]
mod extra_coverage_selfcontained {
    use super::*;
    use actix_web::{test, web};
    use actix_web::http::{self, header::CONTENT_TYPE, Method, StatusCode};
    use dashmap::DashMap;
    use hyper::{Body, Client, Request as HRequest, Response};
    use hyper::service::{make_service_fn, service_fn};
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};
    use hyper_rustls::HttpsConnectorBuilder;
    use std::convert::Infallible;
    use std::net::{SocketAddr, TcpListener as StdTcpListener};
    use std::sync::Arc;

    // ---------- Helpers: clients ----------

    fn https_client() -> hyper::Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>, hyper::Body> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();

        hyper::Client::builder()
        .build::<_, hyper::Body>(https)
    }

    // ---------- Helpers: spawn a tiny upstream server (echo) ----------

    async fn spawn_upstream<F>(handler: F) -> (tokio::task::JoinHandle<()>, SocketAddr)
    where
    F: Fn(hyper::Request<Body>) -> Response<Body> + Send + Sync + 'static,
    {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();

        let handler = Arc::new(handler);
        let make_svc = make_service_fn(move |_| {
            let h = handler.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |req| {
                    let h2 = h.clone();
                    async move {
                        let resp = (h2)(req);
                        Ok::<_, Infallible>(resp)
                    }
                }))
            }
        });

        let server = hyper::Server::from_tcp(listener).unwrap().serve(make_svc);
        let jh = tokio::spawn(async move { let _ = server.await; });
        (jh, addr)
    }

    // ---------- Helpers: spawn a minimal forward HTTP proxy ----------
    async fn spawn_forward_proxy() -> (tokio::task::JoinHandle<()>, SocketAddr) {
        let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();

        let make_svc = make_service_fn(move |_| async move {
            Ok::<_, Infallible>(service_fn(move |req: hyper::Request<Body>| async move {
                let abs_uri = req.uri().to_string();

                let uri: hyper::Uri = abs_uri.parse().map_err(|_| {
                    let mut resp = Response::new(Body::from("Bad Gateway"));
                    *resp.status_mut() = StatusCode::BAD_GATEWAY;
                    resp
                }).unwrap();

                let mut out = HRequest::builder()
                .method(req.method())
                .uri(uri);

                for (k, v) in req.headers().iter() {
                    let name = k.as_str().to_ascii_lowercase();
                    // remove hop-by-hop headers
                    if name != "connection" && name != "proxy-connection" && name != "keep-alive"
                        && name != "te" && name != "trailers" && name != "transfer-encoding" && name != "upgrade" {
                            out = out.header(k, v);
                        }
                }
                // body
                let body = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                let out = out.body(Body::from(body)).unwrap();

                let client = https_client();
                match client.request(out).await {
                    Ok(upstream_resp) => {
                        let (parts, body) = upstream_resp.into_parts();
                        let mut resp = Response::from_parts(parts, body);
                        resp.headers_mut().remove("connection");
                        resp.headers_mut().remove("proxy-connection");
                        resp.headers_mut().remove("keep-alive");
                        resp.headers_mut().remove("te");
                        resp.headers_mut().remove("trailers");
                        resp.headers_mut().remove("transfer-encoding");
                        resp.headers_mut().remove("upgrade");
                        Ok::<_, Infallible>(resp)
                    }
                    Err(_) => {
                        let mut resp = Response::new(Body::from("Bad Gateway"));
                        *resp.status_mut() = StatusCode::BAD_GATEWAY;
                        Ok::<_, Infallible>(resp)
                    }
                }
            }))
        });

        let server = hyper::Server::from_tcp(listener).unwrap().serve(make_svc);
        let jh = tokio::spawn(async move { let _ = server.await; });
        (jh, addr)
    }

    // ---------- Helpers: config / routes / state ----------

    fn base_cfg() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "test-secret-123".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 10,
            timezone: "UTC".into(),
            login_via_otp: false,
            max_connections: 1024,
            pending_connections_limit: 1024,
            socket_listen: 128,
            client_timeout: 1000,
            keep_alive: 1,
            num_instances: 1,
            redis: None,
            cors_origins: None,
            session_cookie: true,
            max_age_session_cookie: 3600,
            login_redirect_url: None,
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
        }
    }

    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://upstream.invalid".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: true,
            preserve_prefix: false,
            secure_path: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    fn make_state_with(mut routes: Vec<RouteRule>, cfg: AppConfig) -> web::Data<AppState> {
        super::init_routes(&mut routes);

        let cfg = Arc::new(cfg);
        web::Data::new(AppState {
            config: cfg,
            routes: Arc::new(crate::RouteConfig { routes }),
                       counter: Arc::new(crate::stats::tokencount::CounterToken::new()),
                       client_normal: https_client(),
                       client_with_cert: https_client(),
                       client_with_proxy: {
                           let https = HttpsConnectorBuilder::new()
                           .with_native_roots()
                           .https_or_http()
                           .enable_http1()
                           .build();
                           let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:9".parse().unwrap());
                           let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
                           Client::builder().build(pc)
                       },
                       revoked_tokens: Arc::new(DashMap::new()),
        })
    }

    // -----------------------------------------------------------------------
    // TESTS
    // -----------------------------------------------------------------------

    #[actix_web::test]
    async fn url_build_variants_preserve_and_securepath_and_query_merge() {
        use super::*;
        use actix_web::http::{header, Method, StatusCode};
        use hyper::{Body, Response};

        let (jh, addr) = spawn_upstream(|req| {
            let seen_uri = req.uri().to_string(); // ex: "/a/x/y?foo=1"
            Response::builder()
            .status(200)
            .header(header::CONTENT_TYPE, "text/plain")
            .header("X-URI", seen_uri)
            .body(Body::from("ok"))
            .unwrap()
        }).await;

        // base route
        let mut r = rr("/base");
        r.proxy = false;
        r.need_csrf = false;
        r.target = format!("http://{}", addr);
        r.preserve_prefix = false;
        r.secure_path = false;

        let data = make_state_with(vec![r.clone()], base_cfg());

        let req_a = actix_web::test::TestRequest::default()
        .method(Method::GET)
        .uri("/base/a/x/y?foo=1")
        .to_http_request();

        let resp_a = super::proxy_without_proxy(req_a, web::Bytes::new(), data.clone())
        .await
        .unwrap();

        assert_eq!(resp_a.status(), StatusCode::OK);
        let s_a = resp_a.headers().get("X-URI").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(s_a.starts_with("/a/x/y"), "X-URI devrait commencer par /a/x/y, got: {s_a}");
        assert!(s_a.contains("foo=1"), "X-URI devrait conserver la query foo=1, got: {s_a}");

        let mut r2 = r.clone();
        r2.preserve_prefix = true;
        let data2 = make_state_with(vec![r2], base_cfg());

        let req_b = actix_web::test::TestRequest::default()
        .method(Method::GET)
        .uri("/base/z?q=9")
        .to_http_request();

        let resp_b = super::proxy_without_proxy(req_b, web::Bytes::new(), data2)
        .await
        .unwrap();

        assert_eq!(resp_b.status(), StatusCode::OK);
        let s_b = resp_b.headers().get("X-URI").and_then(|v| v.to_str().ok()).unwrap_or("");
        assert!(
            s_b.starts_with("/base/z"),
                "avec preserve_prefix=true, X-URI doit contenir /base/z, got: {s_b}"
        );
        assert!(s_b.contains("q=9"), "X-URI doit conserver q=9, got: {s_b}");

        jh.abort();
    }



    #[actix_web::test]
    async fn proxy_without_proxy_sets_no_cache_headers_when_cache_false() {
        let (jh, addr) = spawn_upstream(|_| {
            Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "text/html")
            .body(Body::from("<ok/>"))
            .unwrap()
        }).await;

        let mut r = rr("/n");
        r.cache = false;
        r.target = format!("http://{}", addr);
        let data = make_state_with(vec![r], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/n/path")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        let h = resp.headers();
        assert_eq!(h.get(http::header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8");
        assert!(h.get(http::header::CACHE_CONTROL).is_some());
        assert!(h.get(http::header::PRAGMA).is_some());
        assert!(h.get(http::header::EXPIRES).is_some());

        jh.abort();
    }

    #[actix_web::test]
    async fn method_not_allowed_includes_allow_with_options() {
        let mut r = rr("/m");
        r.allow_methods = Some(vec!["GET".into(), "post".into()]);
        let data = make_state_with(vec![r], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::DELETE)
        .uri("/m/anything")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        let allow = resp.headers().get(http::header::ALLOW).unwrap().to_str().unwrap();
        assert!(allow.contains("GET") && allow.contains("POST") && allow.contains("OPTIONS"));
    }

    #[actix_web::test]
    async fn proxy_without_proxy_404_adds_cors_when_origin_allowed() {
        let mut cfg = base_cfg();
        cfg.cors_origins = Some(vec!["https://allowed.example".into()]);
        let data = make_state_with(vec![rr("/only")], cfg);

        let req = test::TestRequest::default()
        .method(Method::GET)
        .insert_header((http::header::ORIGIN, "https://allowed.example"))
        .uri("/not-here")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let h = resp.headers();
        assert_eq!(h.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), "https://allowed.example");
        assert!(h.get(http::header::ACCESS_CONTROL_ALLOW_METHODS).is_some());
    }

    #[actix_web::test]
    async fn proxy_without_proxy_upstream_500_maps_to_500() {
        let (jh, addr) = spawn_upstream(|_| {
            Response::builder()
            .status(500)
            .header(CONTENT_TYPE, "text/plain")
            .body(Body::from("boom"))
            .unwrap()
        }).await;

        let mut r = rr("/u");
        r.target = format!("http://{}", addr);
        let data = make_state_with(vec![r], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/u/x")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        jh.abort();
    }

    #[actix_web::test]
    async fn proxy_without_proxy_timeout_returns_503() {
        let mut r = rr("/t");
        r.target = "http://10.255.255.1:9".into();
        let data = make_state_with(vec![r], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/t/x")
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[actix_web::test]
    async fn proxy_with_proxy_success_basic_headers_mapping() {
        let (jh_up, addr_up) = spawn_upstream(|req| {
            let ua = req.headers()
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
            assert_eq!(ua, "ProxyAuth");
            assert!(req.headers().get(http::header::HOST).is_some());
            assert!(req.headers().get("authorization").is_none());

            Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "application/json")
            .header("X-Up", "y")
            .body(Body::from(r#"{"ok":true}"#))
            .unwrap()
        }).await;

        // Proxy HTTP local minimal
        let (jh_proxy, addr_proxy) = spawn_forward_proxy().await;

        let mut r = rr("/p");
        r.proxy = true;
        r.need_csrf = false;
        r.target = format!("http://{}", addr_up);
        r.proxy_config = format!("http://{}", addr_proxy);

        let data = make_state_with(vec![r], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/p/path?z=1")
        .insert_header((http::header::AUTHORIZATION, "Bearer will_be_stripped"))
        .to_http_request();

        let resp = super::proxy_with_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("X-Up").unwrap(), "y");
        assert!(resp.headers().get(http::header::SERVER).is_some());

        jh_up.abort();
        jh_proxy.abort();
    }

    #[actix_web::test]
    async fn global_proxy_404_with_cors_when_allowed() {
        use super::*;
        use actix_web::http;

        let mut cfg = base_cfg();
        cfg.cors_origins = Some(vec!["https://allowed.example".into()]);

        let data = make_state_with(vec![rr("/only")], cfg);

        let req = actix_web::test::TestRequest::default()
        .method(http::Method::GET)
        .insert_header((http::header::ORIGIN, "https://allowed.example"))
        .uri("/nope")
        .to_http_request();

        let resp = super::global_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);

        let h = resp.headers();
        assert!(
            h.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
        );
    }

    #[actix_web::test]
    async fn options_cors_allowed_and_forbidden() {
        // allowed
        let mut allowed = base_cfg();
        allowed.cors_origins = Some(vec!["https://ok.example".into()]);
        let data_ok = make_state_with(vec![rr("/")], allowed);

        let req_ok = test::TestRequest::default()
        .method(Method::OPTIONS)
        .insert_header((http::header::ORIGIN, "https://ok.example"))
        .uri("/whatever")
        .to_http_request();
        let resp_ok = super::global_proxy(req_ok, web::Bytes::new(), data_ok).await.unwrap();
        assert_eq!(resp_ok.status(), StatusCode::OK);

        // forbidden
        let mut denied = base_cfg();
        denied.cors_origins = Some(vec!["https://ok.example".into()]);
        let data_ko = make_state_with(vec![rr("/")], denied);

        let req_ko = test::TestRequest::default()
        .method(Method::OPTIONS)
        .insert_header((http::header::ORIGIN, "https://nope.example"))
        .uri("/whatever")
        .to_http_request();
        let resp_ko = super::global_proxy(req_ko, web::Bytes::new(), data_ko).await.unwrap();
        assert_eq!(resp_ko.status(), StatusCode::FORBIDDEN);
    }
}

#[cfg(test)]
mod proxy_with_proxy_auth {
    use super::*;
    use actix_web::{http, test, web};
    use dashmap::DashMap;
    use hyper::client::HttpConnector;
    use hyper_proxy::{Intercept, Proxy, ProxyConnector};
    use hyper_rustls::HttpsConnectorBuilder;
    use std::sync::Arc;

    // --------------- helpers ---------------

    fn https_client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        hyper::Client::builder().build::<_, Body>(https)
    }

    fn proxy_client() -> hyper::Client<
    ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>,
    Body,
    > {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        hyper::Client::builder().build(pc)
    }

    fn base_cfg() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "test-secret-123".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 8,
            timezone: "UTC".into(),
            login_via_otp: false,
            max_connections: 1024,
            pending_connections_limit: 1024,
            socket_listen: 128,
            client_timeout: 1000,
            keep_alive: 1,
            num_instances: 1,
            redis: None,
            cors_origins: Some(vec!["https://allowed.example".into()]),
            session_cookie: true,
            max_age_session_cookie: 3600,
            login_redirect_url: None,
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
        }
    }

    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://upstream.invalid".into(),
            username: vec!["alice".into()],
            secure: true,
            proxy: true,
            proxy_config: "http://127.0.0.1:1".into(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: false,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    fn make_state_with(routes: Vec<RouteRule>, cfg: AppConfig) -> web::Data<AppState> {
        let mut r = routes.clone();
        super::init_routes(&mut r);
        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(crate::RouteConfig { routes }),
            counter: Arc::new(crate::CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        };
        web::Data::new(state)
    }

    // --------------- tests ---------------

    #[actix_web::test]
    async fn proxy_with_proxy_secure_missing_token_returns_err_401_with_cors() {
        let data = make_state_with(vec![rr("/p")], base_cfg());

        let req = test::TestRequest::default()
        .method(http::Method::GET)
        .uri("/p/thing")
        .insert_header((http::header::ORIGIN, "https://allowed.example"))
        .to_http_request();

        let res = super::proxy_with_proxy(req, web::Bytes::new(), data).await;
        assert!(res.is_err(), "on attend Err(actix_web::Error) quand le token manque");
        let err = res.err().unwrap();
        let resp = err.error_response();
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let h = resp.headers();
        assert_eq!(
            h.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN).and_then(|v| v.to_str().ok()),
                   Some("https://allowed.example")
        );
        assert_eq!(h.get(http::header::SERVER).unwrap(), "ProxyAuth");
    }

    #[actix_web::test]
    async fn proxy_with_proxy_cookie_fallback_on_https_invalid_token_returns_401_with_cors() {
        let data = make_state_with(vec![rr("/p")], base_cfg());

        let req = test::TestRequest::default()
        .method(http::Method::GET)
        .uri("/p/secure-area")
        .insert_header((http::header::HeaderName::from_static("x-forwarded-proto"), "https"))
        .insert_header((http::header::ORIGIN, "https://allowed.example"))
        .insert_header((
            http::header::COOKIE,
            "other=a; session_token=deadbeef; foo=bar",
        ))
        .to_http_request();

        let resp = super::proxy_with_proxy(req, web::Bytes::new(), data)
        .await
        .expect("Ok(HttpResponse) 401");

        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);

        let h = resp.headers();
        assert_eq!(
            h.get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN).and_then(|v| v.to_str().ok()),
            Some("https://allowed.example"),
        );
        assert_eq!(h.get(http::header::SERVER).unwrap(), "ProxyAuth");
    }

}


#[cfg(test)]
mod proxy_with_proxy_auth_branches {
    use super::*;
    use actix_web::{http, test, web};
    use dashmap::DashMap;
    use hyper::client::HttpConnector;
    use hyper_proxy::{Intercept, Proxy, ProxyConnector};
    use hyper_rustls::HttpsConnectorBuilder;
    use std::sync::Arc;

    // ------------------- Helpers -------------------

    fn https_client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        hyper::Client::builder().build::<_, Body>(https)
    }

    fn proxy_client() -> hyper::Client<
    ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>,
    Body,
    > {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        hyper::Client::builder().build(pc)
    }

    fn base_cfg() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "test-secret-123".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 8,
            timezone: "UTC".into(),
            login_via_otp: false,
            max_connections: 1024,
            pending_connections_limit: 1024,
            socket_listen: 128,
            client_timeout: 1000,
            keep_alive: 1,
            num_instances: 1,
            redis: None,
            cors_origins: Some(vec!["https://allowed.example".into()]),
            session_cookie: true,
            max_age_session_cookie: 3600,
            login_redirect_url: None,
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
        }
    }

    fn rr(prefix: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://upstream.invalid".into(),
            username: vec!["alice".into()],
            secure: true,
            proxy: true,
            proxy_config: "http://127.0.0.1:1".into(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: false,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    fn make_state_with(routes: Vec<RouteRule>, cfg: AppConfig) -> web::Data<AppState> {
        let mut r = routes.clone();
        super::init_routes(&mut r);
        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(crate::RouteConfig { routes }),
            counter: Arc::new(crate::CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        };
        web::Data::new(state)
    }


    // ------------------- Tests -------------------

    #[actix_web::test]
    async fn missing_token_triggers_401_with_cors() {
        let data = make_state_with(vec![rr("/p")], base_cfg());

        let req = test::TestRequest::default()
        .method(http::Method::GET)
        .uri("/p/thing")
        .insert_header((http::header::ORIGIN, "https://allowed.example"))
        .to_http_request();

        let res = super::proxy_with_proxy(req, web::Bytes::new(), data).await;
        assert!(res.is_err());
        let resp = res.err().unwrap().error_response();
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
            .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
                   Some("https://allowed.example")
        );
    }

    #[actix_web::test]
    async fn cookie_fallback_invalid_token_returns_401() {
        let data = make_state_with(vec![rr("/p")], base_cfg());

        let req = test::TestRequest::default()
        .method(http::Method::GET)
        .uri("/p/secure-area")
        .insert_header((http::header::HeaderName::from_static("x-forwarded-proto"), "https"))
        .insert_header((http::header::ORIGIN, "https://allowed.example"))
        .insert_header((http::header::COOKIE, "session_token=deadbeef"))
        .to_http_request();

        let resp = super::proxy_with_proxy(req, web::Bytes::new(), data)
        .await
        .expect("Should return Ok(HttpResponse)");
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn valid_token_but_username_not_allowed_triggers_403() {
        let mut route = rr("/p");
        route.username = vec!["alice".into()];
        let data = make_state_with(vec![route], base_cfg());

        let req = test::TestRequest::default()
        .method(http::Method::GET)
        .uri("/p/private")
        .insert_header((http::header::ORIGIN, "https://allowed.example"))
        .insert_header((http::header::AUTHORIZATION, "Bearer faketoken"))
        .to_http_request();

        let resp = super::proxy_with_proxy(req, web::Bytes::new(), data)
        .await
        .expect("Should return Ok(HttpResponse)");
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED);
    }
}


#[cfg(test)]
mod token_paths_tests {
    use super::*;
    use actix_web::{test, http::{header, Method, StatusCode}};
    use hyper::{Body, Client};
    use hyper::client::HttpConnector;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};
    use std::sync::Arc;
    use crate::config::config::{AppConfig, AppState, RouteConfig, RouteRule};
    use crate::stats::tokencount::CounterToken;
    use dashmap::DashMap;
    use serial_test::serial;

    // ---------- helpers ----------
    fn https_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        Client::builder().build::<_, Body>(https)
    }

    fn proxy_client() -> Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        Client::builder().build(pc)
    }

    fn base_cfg() -> AppConfig {
        AppConfig {
            secret: "test-secret-token".into(),
            session_cookie: true,
            csrf_token: true,
            cors_origins: Some(vec!["https://allowed.example".into()]),
            ..Default::default()
        }
    }

    fn rr_secure(prefix: &str, use_proxy: bool) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: "http://upstream.invalid".into(),
            username: vec!["alice".into()],
            secure: true,
            proxy: use_proxy,
            proxy_config: "http://127.0.0.1:9".into(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: false,
            cache: true,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    fn make_state_with(routes: Vec<RouteRule>, cfg: AppConfig) -> actix_web::web::Data<AppState> {
        let mut init = routes.clone();
        super::init_routes(&mut init);

        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes }),
            counter: Arc::new(CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        };
        actix_web::web::Data::new(state)
    }

    // ============================
    // proxy_with_proxy
    // ============================

    /// (1) SECURE + no token (no Authorization, no cookie, no https) -> actix Error 401
    #[actix_web::test]
    #[serial]
    async fn pwp_secure_missing_token_returns_401_error() {
        let data = make_state_with(vec![rr_secure("/p", true)], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/p/x")
        .to_http_request();

        let res = super::proxy_with_proxy(req, web::Bytes::new(), data).await;
        assert!(res.is_err(), "doit remonter un Error quand token manquant");

        // On vérifie le StatusCode du error_response
        let resp = res.err().unwrap().error_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// (2) SECURE + Authorization: Bearer <bad> -> 401 (validate_token Err)
    #[actix_web::test]
    #[serial]
    async fn pwp_secure_bad_bearer_token_401() {
        let data = make_state_with(vec![rr_secure("/p", true)], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/p/a")
        .insert_header((header::AUTHORIZATION, "Bearer invalid-token"))
        .to_http_request();

        let resp = super::proxy_with_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// (3) SECURE + cookie session_token (proto https via X-Forwarded-Proto) -> 401 if not valid token
    #[actix_web::test]
    #[serial]
    async fn pwp_secure_cookie_path_bad_token_401() {
        let data = make_state_with(vec![rr_secure("/p", true)], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/p/a")
        .insert_header(("X-Forwarded-Proto", "https"))
        .insert_header((header::COOKIE, "other=1; session_token=bad123; theme=dark"))
        .to_http_request();

        let resp = super::proxy_with_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ============================
    // proxy_without_proxy
    // ============================

    /// (4) SECURE + no token -> actix Error 401
    #[actix_web::test]
    #[serial]
    async fn pnp_secure_missing_token_returns_401_error() {
        let data = make_state_with(vec![rr_secure("/s", false)], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/s/thing")
        .to_http_request();

        let res = super::proxy_without_proxy(req, web::Bytes::new(), data).await;
        assert!(res.is_err(), "doit remonter un Error quand token manquant");
        let resp = res.err().unwrap().error_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// (5) SECURE + Authorization: Bearer <bad> -> 401
    #[actix_web::test]
    #[serial]
    async fn pnp_secure_bad_bearer_token_401() {
        let data = make_state_with(vec![rr_secure("/s", false)], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/s/x")
        .insert_header((header::AUTHORIZATION, "Bearer no-good"))
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// (6) SECURE + cookie session_token (proto https via X-Forwarded-Proto) -> 401 si token invalide
    #[actix_web::test]
    #[serial]
    async fn pnp_secure_cookie_path_bad_token_401() {
        let data = make_state_with(vec![rr_secure("/s", false)], base_cfg());

        let req = test::TestRequest::default()
        .method(Method::GET)
        .uri("/s/a")
        .insert_header(("X-Forwarded-Proto", "https"))
        .insert_header((header::COOKIE, "foo=bar; session_token=xyz; x=y"))
        .to_http_request();

        let resp = super::proxy_without_proxy(req, web::Bytes::new(), data).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

