use actix_web::HttpRequest;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use blake3;
use bytes::Bytes;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use hyper::header::{CONTENT_ENCODING, CONTENT_TYPE};
use memchr::memmem;
use once_cell::sync::Lazy;
use rand::RngCore;
use std::io::{Read, Write};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use actix_web::HttpResponseBuilder;
use actix_web::http::{header::{CONTENT_TYPE as CONTENT_TYPE_ACTIX, HeaderValue as HeaderValue_ACTIX}, StatusCode};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
pub static PURGE_HOOK: AtomicUsize = AtomicUsize::new(0);

impl CsrfNonceStore {
    pub fn new() -> Self {
        Self {
            used: Arc::new(DashMap::new()),
        }
    }

    pub fn try_consume(&self, nonce: &[u8], exp: i64) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if exp <= now {
            return false;
        }

        match self.used.entry(nonce.to_vec()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(exp);
                true
            }
        }
    }

    pub fn purge_expired(&self) {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.used.retain(|_, exp| *exp > now);

        // + compteur test-only
        #[cfg(test)]
        {
            PURGE_HOOK.fetch_add(1, Ordering::SeqCst);
        }
    }
}

pub fn spawn_csrf_purger(store: CsrfNonceStore) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                store.purge_expired();
            }
        });
    } else {
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
                store.purge_expired();
            }
        });
    }
}

#[cfg(test)]
pub fn spawn_csrf_purger_for_tests(store: CsrfNonceStore, period: std::time::Duration) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut tick = tokio::time::interval(period);
            loop {
                tick.tick().await;
                store.purge_expired();
            }
        });
    } else {
        std::thread::spawn(move || {
            store.purge_expired();
            loop {
                std::thread::sleep(period);
                store.purge_expired();
            }
        });
    }
}

#[cfg(test)]
impl CsrfNonceStore {
    pub fn clear_for_tests(&self) {
        self.used.clear();
    }
}

#[derive(Clone)]
pub struct CsrfNonceStore {
    used: Arc<DashMap<Vec<u8>, i64>>,
}

pub static CSRF_STORE: Lazy<CsrfNonceStore> = Lazy::new(|| {
    let store = CsrfNonceStore::new();
    spawn_csrf_purger(store.clone());
    store
});


pub fn validate_csrf_token(
    method: &actix_web::http::Method,
    req: &HttpRequest,
    body: &Bytes,
    secret: &str,
) -> bool {
    let p = req.uri().path();
    if is_static_asset(p) {
        return true;
    }

    if matches!(
        method,
        &actix_web::http::Method::GET
        | &actix_web::http::Method::HEAD
        | &actix_web::http::Method::OPTIONS
    ) {
        return true;
    }

    if let Some(header_token) = req
        .headers()
        .get("X-CSRF-Token")
        .or_else(|| req.headers().get("X-CSRFToken"))
        {
            if let Ok(token_str) = header_token.to_str() {
                if verify_csrf_token(secret, token_str) {
                    return true;
                }
            }
        }

        let content_type = req
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

        let ct_lower = content_type.to_ascii_lowercase();

        if ct_lower.starts_with("application/x-www-form-urlencoded") {
            if let Ok(body_str) = std::str::from_utf8(body) {
                if let Some(token) = get_form_param(body_str, "csrf_token") {
                    return verify_csrf_token(secret, &token);
                }
            }
        }

        if ct_lower.starts_with("application/json") {
            if let Ok(body_str) = std::str::from_utf8(body) {
                if let Some(token) = extract_json_csrf_token(body_str) {
                    return verify_csrf_token(secret, &token);
                }
            }
        }

        if ct_lower.starts_with("multipart/form-data") {
            return false;
        }

        false
}

fn extract_json_csrf_token(json_str: &str) -> Option<String> {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(token) = json.get("csrf_token") {
            if let Some(token_str) = token.as_str() {
                return Some(token_str.to_string());
            }
        }
    }
    None
}

pub fn make_csrf_token(secret: &str) -> String {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let exp = (OffsetDateTime::now_utc() + Duration::minutes(10)).unix_timestamp();
    let exp_b = exp.to_be_bytes();

    let mut payload = Vec::with_capacity(32 + 8);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&exp_b);

    let key = blake3::hash(secret.as_bytes()); // 32 bytes
    let sig = blake3::keyed_hash(key.as_bytes(), &payload);

    format!(
        "{}.{}.{}",
        B64.encode(&nonce),
            B64.encode(exp_b),
            B64.encode(sig.as_bytes())
    )
}

pub fn verify_csrf_token(secret: &str, token: &str) -> bool {
    let mut it = token.split('.');
    let n_b64 = it.next().unwrap_or("");
    let e_b64 = it.next().unwrap_or("");
    let s_b64 = it.next().unwrap_or("");

    let nonce = match B64.decode(n_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let exp_b = match B64.decode(e_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_b = match B64.decode(s_b64) {
        Ok(v) => v,
        Err(_) => return false,
    };

    if nonce.len() != 32 || exp_b.len() != 8 || sig_b.len() != 32 {
        return false;
    }

    let mut exp_arr = [0u8; 8];
    exp_arr.copy_from_slice(&exp_b);
    let exp = i64::from_be_bytes(exp_arr);

    let mut payload = Vec::with_capacity(32 + 8);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&exp_b);

    let key = blake3::hash(secret.as_bytes());
    let expected = blake3::keyed_hash(key.as_bytes(), &payload);

    if !bool::from(expected.as_bytes().ct_eq(&sig_b)) {
        return false;
    }

    CSRF_STORE.try_consume(&nonce, exp)
}

fn get_form_param(body_utf8: &str, name: &str) -> Option<String> {
    for pair in body_utf8.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == name {
                return Some(urlencoding::decode(v).ok()?.into_owned());
            }
        }
    }
    None
}

pub fn inject_csrf_token(
    headers: &hyper::HeaderMap,
    body: &Bytes,
    secret: &str,
) -> Option<(Bytes, usize)> {
    const P1: &[u8] = b"{{ csrf_token }}";
    const P2: &[u8] = b"{{csrf_token}}";

    let ct = headers
    .get(CONTENT_TYPE)
    .and_then(|v| v.to_str().ok())
    .unwrap_or("");
    let ct_l = ct.to_ascii_lowercase();
    let ct_main = ct_l.split(';').next().unwrap_or("").trim();
    let allow =
    ct_main == "text/html" || ct_main.ends_with("+html") || ct_main.starts_with("text/html");

    if !allow {
        return None;
    }

    let enc = headers
    .get(CONTENT_ENCODING)
    .and_then(|v| v.to_str().ok())
    .map(|s| s.to_ascii_lowercase());

    let replace_in = |plain: &[u8]| -> Option<Vec<u8>> {
        if memmem::find(plain, P1).is_none() && memmem::find(plain, P2).is_none() {
            return None;
        }
        let token = make_csrf_token(secret);
        let repl = token.as_bytes();

        let mut out = Vec::with_capacity(plain.len() + 64);
        let mut i = 0usize;
        while let Some(pos) = memmem::find(&plain[i..], P1) {
            out.extend_from_slice(&plain[i..i + pos]);
            out.extend_from_slice(repl);
            i += pos + P1.len();
        }

        if i == 0 {
            let mut j = 0usize;
            while let Some(pos) = memmem::find(&plain[j..], P2) {
                out.extend_from_slice(&plain[j..j + pos]);
                out.extend_from_slice(repl);
                j += pos + P2.len();
            }
            out.extend_from_slice(&plain[j..]);
            if j == 0 {
                return None;
            }
            return Some(out);
        }
        out.extend_from_slice(&plain[i..]);
        Some(out)
    };

    match enc.as_deref() {
        Some("gzip") => {
            let mut dec = GzDecoder::new(body.as_ref());
            let mut plain = Vec::new();
            if dec.read_to_end(&mut plain).is_err() {
                return None;
            }
            let out = replace_in(&plain)?;
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            if enc.write_all(&out).is_err() {
                return None;
            }
            let compressed = enc.finish().ok()?;
            let len = compressed.len();
            Some((Bytes::from(compressed), len))
        }
        _ => {
            let out = replace_in(body.as_ref())?;
            let b = Bytes::from(out);
            let len = b.len();
            Some((b, len))
        }
    }
}

fn is_static_asset(path: &str) -> bool {
    path.starts_with("/assets/")
    || path.ends_with(".css")
    || path.ends_with(".js")
    || path.ends_with(".png")
    || path.ends_with(".jpg")
    || path.ends_with(".jpeg")
    || path.ends_with(".svg")
    || path.ends_with(".ico")
    || path.ends_with(".webp")
}

pub fn fix_mime_actix(req_path: &str, resp: &mut HttpResponseBuilder, _status: StatusCode) {
    if req_path.ends_with(".css") {
        resp.insert_header((CONTENT_TYPE_ACTIX, HeaderValue_ACTIX::from_static("text/css; charset=utf-8")));
    }
    if req_path.ends_with(".js") {
        resp.insert_header((CONTENT_TYPE_ACTIX, HeaderValue_ACTIX::from_static("text/javascript; charset=utf-8")));
    }
    if req_path.ends_with(".html") {
        resp.insert_header((CONTENT_TYPE_ACTIX, HeaderValue_ACTIX::from_static("text/html; charset=utf-8")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use actix_web::http::{Method};
    use actix_web::test::TestRequest;
    use bytes::Bytes;
    use flate2::{Compression, write::GzEncoder};
    use hyper::HeaderMap as HyperHeaderMap;
    use std::io::Write;

    // ------------ CsrfNonceStore ------------
    #[test]
    fn csrf_store_try_consume_and_replay() {
        let store = CsrfNonceStore::new();
        let nonce = b"12345678901234567890123456789012"; // 32 bytes
        let exp = (OffsetDateTime::now_utc() + Duration::minutes(10)).unix_timestamp();

        assert!(store.try_consume(nonce, exp));
        assert!(!store.try_consume(nonce, exp));
    }

    #[test]
    fn csrf_store_purge_expired() {
        let store = CsrfNonceStore::new();
        let nonce = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let exp_past = (OffsetDateTime::now_utc() - Duration::minutes(1)).unix_timestamp();

        store.used.insert(nonce.to_vec(), exp_past);
        store.purge_expired();
        assert!(store.used.is_empty());
    }

    // ------------ make/verify CSRF token ------------
    #[tokio::test(flavor = "current_thread")]
    async fn csrf_make_and_verify_ok() {
        let _ = &*CSRF_STORE;
        CSRF_STORE.clear_for_tests();

        let secret = "s3cr3t";
        let token = make_csrf_token(secret);
        assert!(verify_csrf_token(secret, &token));
    }

    #[test]
    fn csrf_verify_reject_tampered_sig() {
        let secret = "s3cr3t";
        let mut token = make_csrf_token(secret);
        let last = token.pop().unwrap();
        let tweaked = if last == 'A' { 'B' } else { 'A' };
        token.push(tweaked);
        assert!(!verify_csrf_token(secret, &token));
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial]
    async fn csrf_verify_reject_replay() {
        let _ = &*CSRF_STORE;
        CSRF_STORE.clear_for_tests();

        let secret = "s3cr3t";
        let token = make_csrf_token(secret);
        assert!(verify_csrf_token(secret, &token));
        assert!(!verify_csrf_token(secret, &token));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn csrf_verify_reject_expired() {
        let _ = &*CSRF_STORE;
        CSRF_STORE.clear_for_tests();

        let secret = "s3cr3t";
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        let exp = (OffsetDateTime::now_utc() - Duration::seconds(10)).unix_timestamp();
        let exp_b = exp.to_be_bytes();

        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&exp_b);

        let key = blake3::hash(secret.as_bytes());
        let sig = blake3::keyed_hash(key.as_bytes(), &payload);
        let tok = format!(
            "{}.{}.{}",
            B64.encode(&nonce),
                          B64.encode(exp_b),
                          B64.encode(sig.as_bytes())
        );

        assert!(!verify_csrf_token(secret, &tok));
    }

    // ------------ inject_csrf_token ------------
    #[test]
    #[serial]
    fn inject_replaces_placeholder_in_plain_html() {
        let secret = "s3cr3t";
        let mut headers = HyperHeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/html".parse().unwrap());

        let html = b"<html>{{ csrf_token }}</html>";
        let (out, _len) = inject_csrf_token(&headers, &Bytes::from_static(html), secret)
        .expect("injection should happen");

        let s = String::from_utf8(out.to_vec()).unwrap();
        assert!(!s.contains("{{ csrf_token }}"));
        let _token = s.trim_matches(|c| c == '<' || c == '>' || c == 'h' || c == 't' || c == 'm' || c == 'l' || c == '/' || c == ' ');
        let tok = s.split('>').nth(1).unwrap().split('<').next().unwrap().trim();
        assert!(verify_csrf_token(secret, tok));
    }

    #[test]
    fn inject_replaces_compact_placeholder() {
        let secret = "s3cr3t";
        let mut headers = HyperHeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());

        let html = b"<!doctype html>{{csrf_token}}";
        let (out, _len) = inject_csrf_token(&headers, &Bytes::from_static(html), secret)
        .expect("injection should happen");

        let s = String::from_utf8(out.to_vec()).unwrap();
        assert!(!s.contains("{{csrf_token}}"));
        let tok = s.split("html>").nth(1).unwrap().trim();
        assert!(verify_csrf_token(secret, tok));
    }

    #[test]
    #[serial]
    fn inject_handles_gzip_encoded_html() {
        let secret = "s3cr3t";
        // headers HTML + gzip
        let mut headers = HyperHeaderMap::new();
        headers.insert(CONTENT_TYPE, "text/html".parse().unwrap());
        headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());

        let html = b"<b>{{ csrf_token }}</b>";
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(html).unwrap();
        let gz = enc.finish().unwrap();

        let (out, len) = inject_csrf_token(&headers, &Bytes::from(gz), secret)
        .expect("gzip injection should happen");
        assert!(len > 0);

        let mut dec = flate2::read::GzDecoder::new(out.as_ref());
        let mut plain = String::new();
        dec.read_to_string(&mut plain).unwrap();

        assert!(!plain.contains("{{ csrf_token }}"));
        let tok = plain.trim_matches(|c| c == '<' || c == '>' || c == 'b' || c == '/' || c == ' ');
        assert!(verify_csrf_token(secret, tok));
    }

    #[test]
    fn inject_skips_non_html() {
        let secret = "s3cr3t";
        let mut headers = HyperHeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());

        let body = br#"{"x":"{{ csrf_token }}"}"#;
        assert!(inject_csrf_token(&headers, &Bytes::from_static(body), secret).is_none());
    }

    // ------------ validate_csrf_token (chemins & formats) ------------
    #[test]
    fn validate_allows_static_assets_and_safe_methods() {
        let secret = "s3cr3t";
        // static asset
        let req = TestRequest::get().uri("/assets/app.js").to_http_request();
        assert!(validate_csrf_token(&Method::GET, &req, &Bytes::new(), secret));

        // GET générique
        let req2 = TestRequest::get().uri("/api").to_http_request();
        assert!(validate_csrf_token(&Method::GET, &req2, &Bytes::new(), secret));

        // HEAD
        let req3 = TestRequest::default().method(Method::HEAD).uri("/api").to_http_request();
        assert!(validate_csrf_token(&Method::HEAD, &req3, &Bytes::new(), secret));

        // OPTIONS
        let req4 = TestRequest::default().method(Method::OPTIONS).uri("/api").to_http_request();
        assert!(validate_csrf_token(&Method::OPTIONS, &req4, &Bytes::new(), secret));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn validate_post_with_header_token() {
        let _ = &*CSRF_STORE;
        CSRF_STORE.clear_for_tests();

        let secret = "s3cr3t";
        let tok = make_csrf_token(secret);

        let req = TestRequest::post()
        .uri("/api")
        .insert_header(("X-CSRF-Token", tok.clone()))
        .insert_header((CONTENT_TYPE, "application/json"))
        .set_payload(r#"{"a":1}"#)
        .to_http_request();

        assert!(validate_csrf_token(&Method::POST, &req, &Bytes::from_static(br#"{"a":1}"#), secret));
    }

    #[test]
    fn validate_post_form_token() {
        let secret = "s3cr3t";
        let tok = make_csrf_token(secret);
        let body = format!("a=1&csrf_token={}", urlencoding::encode(&tok));

        let req = TestRequest::post()
        .uri("/api")
        .insert_header((CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload(body.clone())
        .to_http_request();

        assert!(validate_csrf_token(&Method::POST, &req, &Bytes::from(body), secret));
    }

    #[test]
    fn validate_post_json_token() {
        let secret = "s3cr3t";
        let tok = make_csrf_token(secret);
        let body = format!(r#"{{"a":1,"csrf_token":"{}"}}"#, tok);

        let req = TestRequest::post()
        .uri("/api")
        .insert_header((CONTENT_TYPE, "application/json"))
        .set_payload(body.clone())
        .to_http_request();

        assert!(validate_csrf_token(&Method::POST, &req, &Bytes::from(body), secret));
    }

    #[test]
    fn validate_post_json_missing_token_fails() {
        let secret = "s3cr3t";
        let body = r#"{"a":1}"#;

        let req = TestRequest::post()
        .uri("/api")
        .insert_header((CONTENT_TYPE, "application/json"))
        .set_payload(body)
        .to_http_request();

        assert!(!validate_csrf_token(&Method::POST, &req, &Bytes::from_static(body.as_bytes()), secret));
    }

    #[test]
    fn validate_multipart_is_rejected() {
        let secret = "s3cr3t";
        let req = TestRequest::post()
        .uri("/upload")
        .insert_header((CONTENT_TYPE, "multipart/form-data; boundary=XXX"))
        .set_payload("--XXX\r\n...")
        .to_http_request();

        assert!(!validate_csrf_token(&Method::POST, &req, &Bytes::from_static(b"--XXX\r\n..."), secret));
    }

    // ------------ is_static_asset ------------
    #[test]
    fn static_asset_detection() {
        assert!(is_static_asset("/assets/app.js"));
        assert!(is_static_asset("/logo.png"));
        assert!(!is_static_asset("/api/v1/users"));
    }

    // ------------ fix_mime_actix ------------
    #[test]
    fn fix_mime_sets_expected_types() {
        use actix_web::HttpResponse;

        // CSS
        let mut b1 = HttpResponse::Ok();
        fix_mime_actix("/style.css", &mut b1, StatusCode::OK);
        let r1 = b1.finish();
        assert_eq!(
            r1.headers().get(CONTENT_TYPE_ACTIX).unwrap(),
                   "text/css; charset=utf-8"
        );

        // JS
        let mut b2 = HttpResponse::Ok();
        fix_mime_actix("/app.js", &mut b2, StatusCode::OK);
        let r2 = b2.finish();
        assert_eq!(
            r2.headers().get(CONTENT_TYPE_ACTIX).unwrap(),
                   "text/javascript; charset=utf-8"
        );

        // HTML
        let mut b3 = HttpResponse::Ok();
        fix_mime_actix("/index.html", &mut b3, StatusCode::OK);
        let r3 = b3.finish();
        assert_eq!(
            r3.headers().get(CONTENT_TYPE_ACTIX).unwrap(),
                   "text/html; charset=utf-8"
        );
    }
}

#[cfg(test)]
mod tests_spawn_purger {
    use super::*;
    use std::time::Duration;
    use std::sync::atomic::Ordering;

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_csrf_purger_tokio_branch_purges() {
        PURGE_HOOK.store(0, Ordering::SeqCst);
        let store = CsrfNonceStore::new();

        spawn_csrf_purger_for_tests(store, Duration::from_millis(5));

        tokio::time::sleep(Duration::from_millis(30)).await;

        let n = PURGE_HOOK.load(Ordering::SeqCst);
        assert!(n >= 1, "purge_expired (n={n})");
    }

    #[test]
    fn spawn_csrf_purger_thread_branch_purges() {
        PURGE_HOOK.store(0, Ordering::SeqCst);
        let store = CsrfNonceStore::new();

        spawn_csrf_purger_for_tests(store, Duration::from_millis(5));

        std::thread::sleep(Duration::from_millis(30));

        let n = PURGE_HOOK.load(Ordering::SeqCst);
        assert!(n >= 1, "purge_expired (thread) (n={n})");
    }
}
