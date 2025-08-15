use proxyauth::token::csrf::CsrfNonceStore;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};

use time::{Duration, OffsetDateTime};
use proxyauth::token::csrf::CSRF_STORE;
use proxyauth::token::csrf::make_csrf_token;
use proxyauth::token::csrf::verify_csrf_token;
use proxyauth::token::csrf::validate_csrf_token;
use proxyauth::token::csrf::inject_csrf_token;
use proxyauth::token::csrf::is_static_asset;
use hyper::header::{CONTENT_ENCODING, CONTENT_TYPE};
use actix_web::http::{header::CONTENT_TYPE as CONTENT_TYPE_ACTIX, StatusCode};
use proxyauth::token::csrf::fix_mime_actix;
use std::io::Read;
use rand::RngCore;


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
    
    #[tokio::test(start_paused = true, flavor = "current_thread")]
    async fn spawn_csrf_purger_tokio_branch_purges() {
        use tokio::time::advance;
        use std::time::Duration;
         use std::sync::atomic::Ordering;
        use proxyauth::token::csrf::{PURGE_HOOK, spawn_csrf_purger_for_tests_with_notify};

        PURGE_HOOK.store(0, Ordering::SeqCst);

        let store = CsrfNonceStore::new();
        store.insert_expired_for_tests("dead");

        let (tx, rx) = tokio::sync::oneshot::channel();
        spawn_csrf_purger_for_tests_with_notify(store, Duration::from_millis(5), Some(tx));

        // Déclenche le tick virtuel
        advance(Duration::from_millis(5)).await;

        // Synchronise sur la notification (pas de sleep arbitraire)
        let purged = rx.await.expect("first cycle");
        assert!(purged >= 1);

        let n = PURGE_HOOK.load(Ordering::SeqCst);
        assert!(n >= 1, "purge_expired (n={n})");
    }


    #[test]
    fn spawn_csrf_purger_thread_branch_purges() {
        use std::time::{Duration, Instant};
        use proxyauth::token::csrf::{spawn_csrf_purger_for_tests, PURGE_HOOK};

        PURGE_HOOK.store(0, std::sync::atomic::Ordering::SeqCst);

        let store = CsrfNonceStore::new();
        store.insert_expired_for_tests("dead");

        spawn_csrf_purger_for_tests(store, Duration::from_millis(5));

        let deadline = Instant::now() + Duration::from_millis(200);
        loop {
            let n = PURGE_HOOK.load(std::sync::atomic::Ordering::SeqCst);
            if n >= 1 { break; }
            if Instant::now() >= deadline {
                panic!("purge_expired (thread) (n=0)");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
