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

    // 7) Lire encodage + body
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

    // 11) Recompresser selon l’encodage d’origine
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
