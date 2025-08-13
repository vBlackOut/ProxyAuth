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
use once_cell::sync::OnceCell;

static ORDERED_ROUTE_IDX: OnceCell<Vec<usize>> = OnceCell::new();

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
    ORDERED_ROUTE_IDX.set(idx).ok();
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
    let order = ORDERED_ROUTE_IDX.get().expect("route order not initialized");
    for &i in order {
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
        let mut not_found_resp = HttpResponse::NotFound();
        add_cors_headers(&mut not_found_resp, &req);
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
        let mut not_found_resp = HttpResponse::NotFound();
        add_cors_headers(&mut not_found_resp, &req);
        Ok(HttpResponse::NotFound()
            .append_header(("server", "ProxyAuth"))
            .body("404 Not Found"))
    }
}
