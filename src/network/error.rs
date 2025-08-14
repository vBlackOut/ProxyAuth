use crate::AppState;
use crate::network::shared_client::get_or_build_thread_client;
use crate::network::shared_client::ClientOptions;
use crate::token::csrf::inject_csrf_token;
use crate::config::config::BackendConfig;
use crate::config::config::BackendInput;
use crate::network::loadbalancing::forward_failover;
use actix_web::rt::time::timeout;
use actix_web::{HttpRequest, HttpResponse, web, http::header};
use hyper::{Body, Request};
use hyper::body::to_bytes;
use std::time::Duration;
use std::io::{Read, Write};
use flate2::{read::{GzDecoder, DeflateDecoder}, write::{GzEncoder, DeflateEncoder}, Compression};
use brotli::{Decompressor, CompressorWriter};
use bytes::Bytes;

fn toggle_error_block(html: String, error_text: &str) -> String {
    let start_marker = "<!-- BEGIN_BLOCK_ERROR -->";
    let end_marker   = "<!-- END_BLOCK_ERROR -->";

    if error_text.is_empty() {
        return html;
    }

    let (Some(s), Some(e)) = (html.find(start_marker), html.find(end_marker)) else {
        return html;
    };

    let block_start = s + start_marker.len();
    let block_end   = e;

    let mut block = html[block_start..block_end].to_string();

    block = block.replace("<!--", "").replace("-->", "");
    block = block.replace("{{ error }}", error_text);

    let mut out = html;
    out.replace_range(block_start..block_end, &block);
    out
}

pub async fn render_error_page(
    req: &HttpRequest,
    data: web::Data<AppState>,
    error_text: &str,
) -> HttpResponse {
    let logout_url: String = match &data.config.logout_redirect_url {
        Some(u) if !u.is_empty() => u.clone(),
        _ => return HttpResponse::BadRequest().body("logout_redirect_url is not configured"),
    };

    let (path, query_opt) =
    if logout_url.starts_with("http://") || logout_url.starts_with("https://") {
        match logout_url.split_once("://").and_then(|(_, rest)| rest.split_once('/')) {
            Some((_, tail)) => {
                if let Some((p, q)) = tail.split_once('?') {
                    (format!("/{}", p.trim_start_matches('/')), Some(q.to_string()))
                } else {
                    (format!("/{}", tail.trim_start_matches('/')), None)
                }
            }
            None => ("/".to_string(), None),
        }
    } else if let Some((p, q)) = logout_url.split_once('?') {
        (p.to_string(), Some(q.to_string()))
    } else {
        (logout_url.clone(), None)
    };

    let Some(rule) = data.routes.routes.iter().find(|r| path.starts_with(&r.prefix)) else {
        return HttpResponse::BadRequest().body("No matching route for logout_redirect_url path");
    };

    let raw_forward = path
    .strip_prefix(&rule.prefix)
    .unwrap_or("")
    .trim_start_matches('/');
    let cleaned = raw_forward.trim_end_matches('/');

    let forward_path = if cleaned.is_empty() {
        "".to_string()
    } else {
        format!("/{}", cleaned)
    };

    let mut target_url = format!("{}{}", rule.target.trim_end_matches('/'), forward_path);
    if let Some(q) = &query_opt {
        if !q.is_empty() {
            target_url.push('?');
            target_url.push_str(q);
        }
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
                key_path:  rule.cert.get("key").cloned(),
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
                key_path:  rule.cert.get("key").cloned(),
            },
            &data.config.clone(),
        )
    };

    let backend_host = match full_url
    .split_once("://")
    .and_then(|(_, rest)| rest.split_once('/').map(|(h, _)| h))
    {
        Some(h) => h,
        None => "",
    };

    let mut rb = Request::builder()
    .method("GET")
    .uri(&full_url)
    .header("Host", backend_host)
    .header(
        "Accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    )
    .header("Accept-Encoding", "gzip, deflate, br");

    if let Some(ua) = req.headers().get(header::USER_AGENT) {
        rb = rb.header(header::USER_AGENT, ua.clone());
    }
    if let Some(ck) = req.headers().get(header::COOKIE) {
        rb = rb.header(header::COOKIE, ck.clone());
    }
    if let Some(al) = req.headers().get(header::ACCEPT_LANGUAGE) {
        rb = rb.header(header::ACCEPT_LANGUAGE, al.clone());
    }
    if let Some(ori) = req.headers().get(header::ORIGIN) {
        rb = rb.header(header::ORIGIN, ori.clone());
    }
    let hyper_req = match rb.body(Body::empty()) {
        Ok(r) => r,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to build backend request"),
    };

    let response_result = if !rule.backends.is_empty() {
        let backends: Vec<BackendConfig> = rule
        .backends
        .iter()
        .map(|b| match b {
            BackendInput::Simple(url) => BackendConfig { url: url.clone(), weight: 1 },
            BackendInput::Detailed(cfg) => cfg.clone(),
        })
        .collect();

        match forward_failover(hyper_req, &backends, None).await {
            Ok(res) => res,
            Err(_e) => {
                return HttpResponse::ServiceUnavailable()
                .insert_header(("server", "ProxyAuth"))
                .body("Failover failed");
            }
        }
    } else {
        match timeout(Duration::from_millis(500), client.request(hyper_req)).await {
            Ok(Ok(res)) => res,
            Ok(Err(_e)) => {
                return HttpResponse::ServiceUnavailable()
                .insert_header(("server", "ProxyAuth"))
                .body("Upstream client error");
            }
            Err(_to) => {
                return HttpResponse::ServiceUnavailable()
                .insert_header(("server", "ProxyAuth"))
                .body("Upstream timeout");
            }
        }
    };

    if response_result.status().is_client_error() || response_result.status().is_server_error() {
        return HttpResponse::BadRequest()
        .insert_header(("server", "ProxyAuth"))
        .body(format!("Backend status: {}", response_result.status()));
    }

    let (parts, body) = response_result.into_parts();
    let headers = parts.headers;
    let encoding = headers
    .get(header::CONTENT_ENCODING)
    .and_then(|v| v.to_str().ok())
    .map(|s| s.to_lowercase());

    let body_bytes = match to_bytes(body).await {
        Ok(b) => b,
        Err(_) => return HttpResponse::InternalServerError().body("Failed to read backend body"),
    };

    let mut html = match encoding.as_deref() {
        Some("gzip") => {
            let mut d = GzDecoder::new(&body_bytes[..]);
            let mut out = String::new();
            d.read_to_string(&mut out).unwrap_or(0);
            out
        }
        Some("deflate") => {
            let mut d = DeflateDecoder::new(&body_bytes[..]);
            let mut out = String::new();
            d.read_to_string(&mut out).unwrap_or(0);
            out
        }
        Some("br") => {
            let mut out = Vec::new();
            let mut d = Decompressor::new(&body_bytes[..], 4096);
            d.read_to_end(&mut out).unwrap_or(0);
            String::from_utf8_lossy(&out).into_owned()
        }
        _ => String::from_utf8_lossy(&body_bytes).into_owned(),
    };

    html = toggle_error_block(html, error_text);

    let mut plain: Bytes = Bytes::from(html.into_bytes());

    let mut inj_headers = headers.clone();
    inj_headers.remove(header::CONTENT_ENCODING);
    if !inj_headers.contains_key(header::CONTENT_TYPE) {
        inj_headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/html; charset=utf-8"),
        );
    } else if let Some(ct) = inj_headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        if !ct.to_ascii_lowercase().contains("html") {
            inj_headers.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/html; charset=utf-8"),
            );
        }
    }

    if data.config.session_cookie && data.config.csrf_token {
        if let Some((new_body, _)) = inject_csrf_token(&inj_headers, &plain, &data.config.secret) {
            plain = new_body; // Bytes
        }
    }

    let (final_body, final_ce_opt) = match encoding.as_deref() {
        Some("gzip") => {
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(plain.as_ref()).ok();
            (e.finish().unwrap_or_default(), Some("gzip"))
        }
        Some("deflate") => {
            let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
            e.write_all(plain.as_ref()).ok();
            (e.finish().unwrap_or_default(), Some("deflate"))
        }
        Some("br") => {
            let mut e = CompressorWriter::new(Vec::new(), 4096, 5, 22);
            e.write_all(plain.as_ref()).ok();
            (e.into_inner(), Some("br"))
        }
        _ => (plain.to_vec(), None),
    };

    let mut resp = HttpResponse::Unauthorized();
    resp.insert_header(("server", "ProxyAuth"));
    resp.insert_header((header::CACHE_CONTROL, "no-store, no-cache, must-revalidate, max-age=0"));
    resp.insert_header(("Pragma", "no-cache"));
    resp.insert_header(("Expires", "0"));
    resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));
    if let Some(enc) = final_ce_opt {
        resp.insert_header((header::CONTENT_ENCODING, enc));
    }
    resp.insert_header((header::CONTENT_LENGTH, final_body.len().to_string()));
    resp.body(final_body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::{header, StatusCode}, test};
    use bytes::Bytes;
    use hyper::{Body, Response, Request as HyperRequest, Server};
    use hyper::service::{make_service_fn, service_fn};
    use hyper::header::{CONTENT_ENCODING, CONTENT_TYPE};
    use std::convert::Infallible;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::task::JoinHandle;

    use crate::config::config::{AppConfig, AppState, RouteConfig, RouteRule};
    use crate::stats::tokencount::CounterToken;
    use dashmap::DashMap;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper::client::HttpConnector;
    use hyper::Client as HyperClient;
    use hyper_proxy::ProxyConnector;
    use hyper_proxy::Proxy;
    use hyper_proxy::Intercept;


    // -------- helpers --------------------------------------------------------

    fn https_client() -> HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        HyperClient::builder().build::<_, Body>(https)
    }

    fn proxy_client() -> HyperClient<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        HyperClient::builder().build(pc)
    }


    fn base_config() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "test-secret".into(),
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
            client_timeout: 1_000,
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

    fn make_state(routes: Vec<RouteRule>, cfg: AppConfig) -> actix_web::web::Data<AppState> {
        actix_web::web::Data::new(AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes }),
            counter: Arc::new(CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        })
    }

    fn rr(prefix: &str, target: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: target.to_string(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
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

    async fn start_backend(
        status: StatusCode,
        body_html: String,
        content_encoding: Option<&'static str>,
        delay_ms: u64,
    ) -> (SocketAddr, JoinHandle<Result<(), hyper::Error>>) {
        let make = make_service_fn(move |_| {
            let body_html = body_html.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |_req: HyperRequest<Body>| {
                    let body_html = body_html.clone();
                    async move {
                        if delay_ms > 0 {
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                        }

                        let (bytes, enc_header) = match content_encoding {
                            Some("gzip") => {
                                use flate2::{write::GzEncoder, Compression};
                                let mut enc = GzEncoder::new(Vec::new(), Compression::default());
                                std::io::Write::write_all(&mut enc, body_html.as_bytes()).ok();
                                let v = enc.finish().unwrap();
                                (v, Some("gzip"))
                            }
                            Some("deflate") => {
                                use flate2::{write::DeflateEncoder, Compression};
                                let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
                                std::io::Write::write_all(&mut enc, body_html.as_bytes()).ok();
                                let v = enc.finish().unwrap();
                                (v, Some("deflate"))
                            }
                            Some("br") => {
                                use brotli::CompressorWriter;
                                let mut enc = CompressorWriter::new(Vec::new(), 4096, 5, 22);
                                std::io::Write::write_all(&mut enc, body_html.as_bytes()).ok();
                                let v = enc.into_inner();
                                (v, Some("br"))
                            }
                            _ => (body_html.into_bytes(), None),
                        };

                        let mut resp = Response::builder()
                        .status(status)
                        .header(CONTENT_TYPE, "text/html; charset=utf-8");
                        if let Some(enc) = enc_header {
                            resp = resp.header(CONTENT_ENCODING, enc);
                        }
                        Ok::<_, Infallible>(resp.body(Body::from(bytes)).unwrap())
                    }
                }))
            }
        });

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = Server::try_bind(&addr).unwrap();
        let local_addr = server.local_addr();
        let join = tokio::spawn(server.serve(make));
        (local_addr, join)
    }

    async fn resp_to_string(resp: actix_web::HttpResponse) -> String {
        use actix_web::body::to_bytes;
        let bytes = to_bytes(resp.into_body()).await.expect("read body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    async fn unpack_response(
        resp: actix_web::HttpResponse,
    ) -> (StatusCode, actix_web::http::header::HeaderMap, Bytes) {
        use actix_web::body::to_bytes;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = to_bytes(resp.into_body()).await.expect("read body");
        (status, headers, body)
    }

    fn contains_csrf_token(s: &str) -> bool {
        let mut dots = 0;
        for ch in s.chars() {
            if ch == '.' { dots += 1; }
        }
        dots >= 2 && s.contains("csrf") || dots >= 2
    }

    // -------- tests ----------------------------------------------------------

    #[tokio::test]
    async fn logout_redirect_url_not_configured_returns_400() {
        let cfg = base_config(); // logout_redirect_url = None
        let state = make_state(vec![rr("/", "http://127.0.0.1:0")], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = render_error_page(&req, state, "ERR").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = resp_to_string(resp).await;
        assert!(body.contains("logout_redirect_url is not configured"));
    }

    #[tokio::test]
    async fn no_matching_route_for_path_returns_400() {
        let mut cfg = base_config();
        cfg.logout_redirect_url = Some("/oops".to_string());
        let state = make_state(vec![rr("/api", "http://127.0.0.1:0")], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = render_error_page(&req, state, "E").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = resp_to_string(resp).await;
        assert!(body.contains("No matching route"));
    }

    #[tokio::test]
    async fn ok_plaintext_injects_error_block_and_csrf_returns_401() {
        let html = r#"<!doctype html>
        <html>
        <body>
        <!-- BEGIN_BLOCK_ERROR -->
        <!--<div class="error">{{ error }}</div>-->
        <!-- END_BLOCK_ERROR -->
        <p>csrf here: {{ csrf_token }}</p>
        </body></html>"#;

        let (addr, _join) = start_backend(StatusCode::OK, html.to_string(), None, 0).await;

        let mut cfg = base_config();
        cfg.logout_redirect_url = Some("/err?x=1".into());
        let target = format!("http://{}", addr);
        let state = make_state(vec![rr("/", &target)], cfg);

        let req = test::TestRequest::default()
        .insert_header((header::USER_AGENT, "UA"))
        .insert_header((header::COOKIE, "sid=abc"))
        .to_http_request();

        let resp = render_error_page(&req, state, "BOOM!").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let (_status, headers, body) = unpack_response(resp).await;
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
                   "text/html; charset=utf-8"
        );
        assert!(headers.get(header::CONTENT_ENCODING).is_none());

        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains(r#"<div class="error">BOOM!</div>"#));
        assert!(contains_csrf_token(&body_str));
    }

    #[tokio::test]
    async fn ok_gzip_recompressed_and_contains_error_and_csrf() {
        let html = r#"<!doctype html><body>
        <!-- BEGIN_BLOCK_ERROR --><!--<b>{{ error }}</b>--><!-- END_BLOCK_ERROR -->
        {{ csrf_token }}
        </body>"#;

        let (addr, _join) = start_backend(StatusCode::OK, html.into(), Some("gzip"), 0).await;

        let mut cfg = base_config();
        cfg.logout_redirect_url = Some("/g".into());
        let target = format!("http://{}", addr);
        let state = make_state(vec![rr("/", &target)], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = render_error_page(&req, state, "GZ").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let (_status, headers, body) = unpack_response(resp).await;
        assert_eq!(
            headers.get(header::CONTENT_ENCODING).unwrap(),
                   "gzip"
        );

        use flate2::read::GzDecoder;
        use std::io::Read;
        let mut dec = GzDecoder::new(body.as_ref());
        let mut s = String::new();
        dec.read_to_string(&mut s).unwrap();

        assert!(s.contains("<b>GZ</b>"));
        assert!(contains_csrf_token(&s));
    }

    #[tokio::test]
    async fn ok_deflate_and_br_work_too() {
        for enc in ["deflate", "br"] {
            let html = r#"<!doctype html><body>
            <!-- BEGIN_BLOCK_ERROR --><!--ERROR: {{ error }}--><!-- END_BLOCK_ERROR -->
            csrf={{ csrf_token }}
            </body>"#;

            let (addr, _join) = start_backend(StatusCode::OK, html.into(), Some(enc), 0).await;

            let mut cfg = base_config();
            cfg.logout_redirect_url = Some("/x".into());
            let target = format!("http://{}", addr);
            let state = make_state(vec![rr("/", &target)], cfg);

            let req = test::TestRequest::default().to_http_request();
            let resp = render_error_page(&req, state, enc).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

            let (_status, headers, body) = unpack_response(resp).await;
            assert_eq!(
                headers.get(header::CONTENT_ENCODING).unwrap(),
                       enc
            );

            let s = match enc {
                "deflate" => {
                    use flate2::read::DeflateDecoder;
                    use std::io::Read;
                    let mut d = DeflateDecoder::new(body.as_ref());
                    let mut out = String::new();
                    d.read_to_string(&mut out).unwrap();
                    out
                }
                "br" => {
                    use brotli::Decompressor;
                    use std::io::Read;
                    let mut dec = Decompressor::new(body.as_ref(), 4096);
                    let mut out = Vec::new();
                    dec.read_to_end(&mut out).unwrap();
                    String::from_utf8_lossy(&out).into_owned()
                }
                _ => unreachable!(),
            };

            assert!(s.contains(&format!("ERROR: {enc}")));
            assert!(contains_csrf_token(&s));
        }
    }

    #[tokio::test]
    async fn backend_500_returns_400_backend_status() {
        let (addr, _join) = start_backend(StatusCode::INTERNAL_SERVER_ERROR, "<html>500</html>".into(), None, 0).await;

        let mut cfg = base_config();
        cfg.logout_redirect_url = Some("/err".into());
        let state = make_state(vec![rr("/", &format!("http://{}", addr))], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = render_error_page(&req, state, "x").await;

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = resp_to_string(resp).await;
        assert!(body.contains("Backend status: 500"));
    }

    #[tokio::test]
    async fn backend_timeout_returns_503() {
        let (addr, _join) = start_backend(StatusCode::OK, "<html>slow</html>".into(), None, 1_000).await;

        let mut cfg = base_config();
        cfg.logout_redirect_url = Some("/slow".into());
        let state = make_state(vec![rr("/", &format!("http://{}", addr))], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = render_error_page(&req, state, "slow").await;

        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = resp_to_string(resp).await;
        assert!(body.contains("Upstream timeout"));
    }

    #[tokio::test]
    async fn error_text_empty_keeps_block_commented_but_injects_csrf() {
        let html = r#"<!doctype html><body>
        <!-- BEGIN_BLOCK_ERROR --><!--<p>ERR: {{ error }}</p>--><!-- END_BLOCK_ERROR -->
        token={{ csrf_token }}
        </body>"#;

        let (addr, _join) = start_backend(StatusCode::OK, html.into(), None, 0).await;

        let mut cfg = base_config();
        cfg.logout_redirect_url = Some("/empty".into());
        let state = make_state(vec![rr("/", &format!("http://{}", addr))], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = render_error_page(&req, state, "").await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let (_status, _headers, body) = unpack_response(resp).await;
        let s = String::from_utf8_lossy(&body);

        assert!(s.contains("<!-- BEGIN_BLOCK_ERROR -->"));
        assert!(s.contains("<!-- END_BLOCK_ERROR -->"));
        assert!(contains_csrf_token(&s));
    }
}

