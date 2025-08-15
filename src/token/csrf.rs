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
use tokio::time::{MissedTickBehavior, interval};
use actix_web::http::{header::{CONTENT_TYPE as CONTENT_TYPE_ACTIX, HeaderValue as HeaderValue_ACTIX}, StatusCode};
use std::sync::atomic::{AtomicUsize, Ordering};

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


pub trait IntoStdDuration {
    fn into_std(self) -> std::time::Duration;
}

impl IntoStdDuration for std::time::Duration {
    #[inline]
    fn into_std(self) -> std::time::Duration { self }
}

impl IntoStdDuration for time::Duration {
    #[inline]
    fn into_std(self) -> std::time::Duration {
        self.try_into().expect("negative duration not supported")
    }
}


#[allow(dead_code)]
pub fn spawn_csrf_purger_for_tests(
    store: CsrfNonceStore,
    period: impl IntoStdDuration,
) {
    let period_std: std::time::Duration = period.into_std();

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut tick = tokio::time::interval(period_std);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tick.tick().await;
                let count: usize = purge_and_count(&store);
                PURGE_HOOK.fetch_add(count, Ordering::SeqCst);
            }
        });
    } else {
        std::thread::spawn(move || {
            // purge immédiate au lancement (utile pour les tests)
            let count0: usize = purge_and_count(&store);
            PURGE_HOOK.fetch_add(count0, Ordering::SeqCst);

            loop {
                std::thread::sleep(period_std);
                let count: usize = purge_and_count(&store);
                PURGE_HOOK.fetch_add(count, Ordering::SeqCst);
            }
        });
    }
}

#[allow(dead_code)]
pub fn spawn_csrf_purger_for_tests_with_notify(
    store: CsrfNonceStore,
    period: std::time::Duration,
    notify: Option<tokio::sync::oneshot::Sender<usize>>,
) {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            let mut tick = interval(period);
            tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

            tick.tick().await;
            let count = purge_and_count(&store);
            PURGE_HOOK.fetch_add(count, Ordering::SeqCst);
            if let Some(tx) = notify { let _ = tx.send(count); }

            loop {
                tick.tick().await;
                let c = purge_and_count(&store);
                PURGE_HOOK.fetch_add(c, Ordering::SeqCst);
            }
        });
    } else {
        std::thread::spawn(move || {
            let count0 = purge_and_count(&store);
            PURGE_HOOK.fetch_add(count0, Ordering::SeqCst);
            if let Some(tx) = notify {

                let _ = tx.send(count0);
            }
            loop {
                std::thread::sleep(period);
                let c = purge_and_count(&store);
                PURGE_HOOK.fetch_add(c, Ordering::SeqCst);
            }
        });
    }
}


fn purge_and_count(store: &CsrfNonceStore) -> usize {
    store.purge_expired();
    1
}





impl CsrfNonceStore {
    #[allow(dead_code)]
    pub fn clear_for_tests(&self) {
        self.used.clear();
    }

    #[allow(dead_code)]
    pub fn insert_expired_for_tests(&self, key: &str) {
        use time::Duration;
        use time::OffsetDateTime;

        // exemple : un timestamp dans le passé
        let exp = (OffsetDateTime::now_utc() - Duration::seconds(5)).unix_timestamp();
        self.used.insert(key.as_bytes().to_vec(), exp);
    }
}

#[derive(Clone)]
pub struct CsrfNonceStore {
    pub used: Arc<DashMap<Vec<u8>, i64>>,
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

pub fn is_static_asset(path: &str) -> bool {
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
