use crate::AppConfig;
use crate::AppState;
use crate::config::config::{AuthRequest, User};
use crate::network::proxy::client_ip;
use crate::network::error::render_error_page;
use crate::token::crypto::{calcul_cipher, derive_key_from_secret, encrypt};
use crate::token::csrf::verify_csrf_token;
use crate::token::security::{generate_token, validate_token};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{
    Error as ActixError, FromRequest, HttpRequest, HttpResponse, Responder,
    dev::Payload,
    error::ErrorBadRequest,
    http::{StatusCode, header},
    web::{self, Form, Json},
};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use blake3;
use chrono::{DateTime, Duration, TimeZone, Utc};
use chrono_tz::Tz;
use futures_util::FutureExt;
use futures_util::future::{LocalBoxFuture, ready};
use hex;
use ipnet::IpNet;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;
use totp_rs::{Algorithm, TOTP};
use tracing::{info, warn};

pub enum EitherAuth {
    Json(AuthRequest),
    Form(AuthRequest),
}

impl FromRequest for EitherAuth {
    type Error = ActixError;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let content_type = req
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();

        if content_type.contains("application/json") {
            Json::<AuthRequest>::from_request(req, payload)
                .map(|res| res.map(|json| EitherAuth::Json(json.into_inner())))
                .boxed_local()
        } else if content_type.contains("application/x-www-form-urlencoded") {
            Form::<AuthRequest>::from_request(req, payload)
                .map(|res| res.map(|form| EitherAuth::Form(form.into_inner())))
                .boxed_local()
        } else {
            ready(Err(ErrorBadRequest("Unsupported Content-Type"))).boxed_local()
        }
    }
}

fn validate_csrf(req: &HttpRequest, payload: &EitherAuth, secret: &str) -> bool {
    let m = req.method();
    if matches!(
        m,
        &actix_web::http::Method::GET
            | &actix_web::http::Method::HEAD
            | &actix_web::http::Method::OPTIONS
    ) {
        return true;
    }

    let t_opt = match *payload {
        EitherAuth::Json(ref j) => j.csrf_token.as_deref(),
        EitherAuth::Form(ref f) => f.csrf_token.as_deref(),
    };

    if let Some(t) = t_opt {
        return verify_csrf_token(secret, t);
    }

    false
}

pub fn is_ip_allowed(ip_str: &str, user: &User) -> bool {
    let Ok(ip) = ip_str.parse::<IpAddr>() else {
        return false;
    };

    match &user.allow {
        None => true,
        Some(list) if list.is_empty() => true,
        Some(list) => list.iter().any(|net_str| {
            net_str
                .parse::<IpNet>()
                .map_or(false, |net| net.contains(&ip))
        }),
    }
}

pub fn verify_password(input: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(input.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn generate_random_string(len: usize) -> String {
    let charset: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*()+-=";
    let mut rng = OsRng;

    let base: Vec<u8> = (0..len)
        .map(|_| *charset.choose(&mut rng).unwrap())
        .collect();

    let now = Utc::now().timestamp() as u64;
    let shift: u8 = (now ^ (now >> 3) ^ (now << 1)).wrapping_rem(97) as u8;

    let random_char: Vec<u8> = base
        .into_iter()
        .map(|byte| {
            let idx = charset.iter().position(|&c| c == byte).unwrap_or(0);
            let new_idx = (idx as u8 + shift) as usize % charset.len();
            charset[new_idx]
        })
        .collect();

    let mut full_input = random_char.clone();
    full_input.extend_from_slice(&now.to_le_bytes());

    let hash = blake3::hash(&full_input);

    hex::encode(hash.as_bytes())
}

fn get_expiry_with_timezone(
    config: Arc<AppConfig>,
    optional_timestamp: Option<i64>,
) -> DateTime<Tz> {
    let tz: Tz = config.timezone.parse().expect("Invalid timezone in config");

    let utc_now = optional_timestamp
        .map(|ts| {
            Utc.timestamp_opt(ts, 0)
                .single()
                .expect("Invalid timestamp")
        })
        .unwrap_or_else(Utc::now);

    let utc_expiry = utc_now + Duration::seconds(config.token_expiry_seconds);
    utc_expiry.with_timezone(&tz)
}

pub fn get_expiry_with_timezone_format(
    config: Arc<AppConfig>,
    optional_timestamp: Option<i64>,
) -> String {
    let tz: Tz = config.timezone.parse().expect("Invalid timezone in config");

    let utc_now = optional_timestamp
        .map(|ts| {
            Utc.timestamp_opt(ts, 0)
                .single()
                .expect("Invalid timestamp")
        })
        .unwrap_or_else(Utc::now);

    let utc_expiry = utc_now + Duration::seconds(config.token_expiry_seconds);

    let local_expiry: DateTime<Tz> = utc_expiry.with_timezone(&tz);

    local_expiry.format("%Y-%m-%d %H:%M:%S %:z").to_string()
}

pub async fn auth_options(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
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
        HttpResponse::Ok()
            .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str))
            .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS"))
            .insert_header((
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Authorization, Content-Type, Accept",
            ))
            .insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
            .insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"))
            .finish()
    } else {
        HttpResponse::Forbidden().body("CORS origin not allowed")
    }
}

pub async fn auth(
    req: HttpRequest,
    data: web::Data<AppState>,
    payload: EitherAuth,
) -> impl Responder {

    if data.config.session_cookie
        && data.config.csrf_token
        && !validate_csrf(&req, &payload, &data.config.secret)
    {
        return render_error_page(&req, data.clone(), "invalid csrf request").await;
    }

    let auth = match payload {
        EitherAuth::Json(j) => j,
        EitherAuth::Form(f) => f,
    };

    let ip = client_ip(&req)
    .map(|s| s.to_string())
    .or_else(|| {
        // replis classiques en HTTP
        req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| req.connection_info().realip_remote_addr().map(|s| s.to_string()))
    })
    .unwrap_or_else(|| "-".to_string());

    // Check if session_cookie is enabled
    if data.config.session_cookie {
        let redirect_target = data.config.login_redirect_url.as_deref().unwrap_or("/");

        match req.cookie("session_token") {
            Some(cookie) => {
                let session_token = cookie.value();

                if let Ok((_username, _token_id, _expires_at)) =
                    validate_token(session_token, &data, &data.config, &ip).await
                {
                    let mut resp = HttpResponse::Ok();
                    resp.append_header(("server", "ProxyAuth"));

                    // CORS headers
                    if let Some(origin_header) = req.headers().get(header::ORIGIN) {
                        if let Ok(origin_str) = origin_header.to_str() {
                            if let Some(cors_origins) = &data.config.cors_origins {
                                let origin_normalized = origin_str.trim_end_matches('/');
                                if cors_origins.iter().any(|allowed| {
                                    allowed.trim_end_matches('/') == origin_normalized
                                }) {
                                    resp.append_header((
                                        header::ACCESS_CONTROL_ALLOW_ORIGIN,
                                        origin_str,
                                    ));
                                    resp.append_header((
                                        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                                        "true",
                                    ));
                                    resp.append_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
                                }
                            }
                        }
                    }

                    let redirect_target = data.config.login_redirect_url.as_deref().unwrap_or("/");

                    if redirect_target.starts_with('/') {
                        return resp
                            .insert_header(("location", redirect_target))
                            .insert_header(("server", "ProxyAuth"))
                            .status(StatusCode::SEE_OTHER)
                            .finish();
                    }
                }
            }
            None => {
                if !redirect_target.starts_with('/') {
                    return HttpResponse::BadRequest()
                        .append_header(("server", "ProxyAuth"))
                        .body("Invalid redirect URL");
                }
            }
        }
    }

    if let Some(index_user) = data
        .config
        .users
        .iter()
        .enumerate()
        .find(|(_, user)| {
            user.username == auth.username && verify_password(&auth.password, &user.password)
        })
        .map(|(i, _)| i)
    {
        let user = &data.config.users[index_user];

        if !is_ip_allowed(&ip, &user) {
            warn!("[{}] Access ip denied for user {}", ip, user.username);
            return render_error_page(&req, data.clone(), "Access denied").await;
        }

        // totp method
        if data.config.login_via_otp {
            let totp_code = match &auth.totp_code {
                Some(code) => code.trim(),
                None => {
                    warn!("[{}] Missing TOTP code for user {}", ip, user.username);
                    return render_error_page(&req, data.clone(), "Missing TOTP code").await;
                }
            };

            let totp_key = match user.otpkey.as_deref() {
                Some(key) => key,
                None => {
                    warn!("[{}] Missing TOTP secret for user {}", ip, user.username);
                    return render_error_page(&req, data.clone(), "Missing TOTP secret").await;

                }
            };

            let decoded_secret =
                match base32::decode(base32::Alphabet::RFC4648 { padding: false }, totp_key) {
                    Some(bytes) => bytes,
                    None => {
                        warn!("Invalid base32 TOTP secret for user {}", user.username);
                        return render_error_page(&req, data.clone(), "Internal TOTP error").await;

                    }
                };

            let totp = TOTP::new(Algorithm::SHA512, 6, 0, 30, decoded_secret)
                .expect("TOTP creation failed");

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let generated_code = totp.generate(now);

            let is_valid = generated_code == totp_code;

            if !is_valid {
                warn!("Invalid TOTP code for user {}", user.username);
                return render_error_page(&req, data.clone(), "Invalid TOTP code").await;
            }
        }

        let expiry = get_expiry_with_timezone(data.config.clone(), None);

        let id_token = generate_random_string(48);

        let expiry_ts = expiry.with_timezone(&Utc).timestamp().to_string();
        let expires_at_str = get_expiry_with_timezone_format(data.config.clone(), None);

        let token = generate_token(&auth.username, &data.config, &expiry_ts, &id_token);

        let key = derive_key_from_secret(&data.config.secret);

        let cipher_token = format!(
            "{}|{}|{}|{}",
            calcul_cipher(token.clone()),
            expiry_ts,
            index_user,
            id_token
        );

        let token_encrypt = encrypt(&cipher_token, &key);

        info!(
            "[{}] new token generated for user {} expirated at {}",
            ip, user.username, expires_at_str
        );

        let mut resp = HttpResponse::Ok();
        resp.append_header(("server", "ProxyAuth"));

        if data.config.session_cookie {
            let session_max_age = data
                .config
                .max_age_session_cookie
                .min(data.config.token_expiry_seconds);

            let seconds = expiry
                .signed_duration_since(Utc::now())
                .num_seconds()
                .clamp(60, session_max_age);

            let cookie_expiry = Utc::now() + Duration::seconds(seconds);
            let cookie_expiry_time =
                OffsetDateTime::from_unix_timestamp(cookie_expiry.timestamp()).unwrap();

            let cookie = Cookie::build("session_token", token_encrypt.clone())
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::Strict)
                .expires(cookie_expiry_time)
                .finish();

            // check cors
            if let Some(origin_header) = req.headers().get(header::ORIGIN) {
                if let Ok(origin_str) = origin_header.to_str() {
                    if let Some(cors_origins) = &data.config.cors_origins {
                        let origin_normalized = origin_str.trim_end_matches('/');

                        if cors_origins
                            .iter()
                            .any(|allowed| allowed.trim_end_matches('/') == origin_normalized)
                        {
                            resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str));
                            resp.insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
                            resp.insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
                        }
                    }
                }
            }

            resp.cookie(cookie);

            let redirect_target = data.config.login_redirect_url.as_deref().unwrap_or("/");

            if redirect_target.starts_with('/') {
                return resp
                    .insert_header(("location", redirect_target))
                    .insert_header(("server", "ProxyAuth"))
                    .status(StatusCode::SEE_OTHER)
                    .finish();
            }
        }

        resp.json(serde_json::json!({
            "token": token_encrypt,
            "expires_at": expires_at_str,
        }))
    } else {
        let ip = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                req.connection_info()
                    .realip_remote_addr()
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "-".to_string());

        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-");

        let method = req.method().as_str();
        let path = req.path();

        warn!(
            "[{}] - {} {} Invalid {} credentials provided {}",
            ip, path, method, auth.username, user_agent
        );

        return render_error_page(&req, data.clone(), "Invalid credentials").await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, http::header};
    use actix_web::body::to_bytes as actix_to_bytes;
    use crate::config::config::{AppConfig, RouteConfig, RouteRule, User};
    use crate::revoke::db::RevokedTokenMap;
    use crate::token::csrf::make_csrf_token;
    use rand_chacha::rand_core;
    use dashmap::DashMap;
    use hyper::Body;
    
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper::client::HttpConnector;
    
    use std::sync::Arc;
    use argon2::{Argon2, password_hash::{PasswordHasher, SaltString}};
    
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};

    // --------- Helpers -------------------------------------------------------

    fn https_client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        hyper::Client::builder().build::<_, Body>(https)
    }

    fn proxy_client() -> hyper::Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        hyper::Client::builder().build(pc)
    }

    fn start_backend(html: &'static str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use std::net::TcpListener;
        use hyper::{Body, Response, Server};
        use hyper::service::{make_service_fn, service_fn};
        use actix_web::http::header;

        // listener std
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let local_addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let make = make_service_fn(move |_conn| {
            async move {
                Ok::<_, hyper::Error>(service_fn(move |_req| {
                    let body = Body::from(html.as_bytes().to_vec());
                    async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                            .status(200)
                            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
                            .body(body)
                            .unwrap()
                        )
                    }
                }))
            }
        });

        let server = Server::from_tcp(listener).unwrap().serve(make);

        let join = tokio::spawn(async move {
            let _ = server.await;
        });

        (local_addr, join)
    }

    fn hash_pwd(plain: &str) -> String {
        let salt = SaltString::generate(&mut rand_core::OsRng);
        Argon2::default().hash_password(plain.as_bytes(), &salt).unwrap().to_string()
    }

    fn base_config() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "unit-secret-xyz".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 16,
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
            login_redirect_url: Some("/home".into()),
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
        }
    }

    fn mk_state(routes: Vec<RouteRule>, cfg: AppConfig) -> actix_web::web::Data<AppState> {
        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes }),
            counter: Arc::new(crate::stats::tokencount::CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()) as RevokedTokenMap,
        };
        actix_web::web::Data::new(state)
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
            cache: true,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    // --------- EitherAuth ----------------------------------------------------

    #[tokio::test]
    async fn either_auth_json_and_form_and_unsupported() {
        // JSON
        let payload = r#"{"username":"u","password":"p","csrf_token":"t"}"#;
        let (req, mut pl) = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .set_payload(payload)
        .to_http_parts();

        let got = super::EitherAuth::from_request(&req, &mut pl).await.unwrap();
        match got {
            super::EitherAuth::Json(j) => {
                assert_eq!(j.username, "u");
                assert_eq!(j.password, "p");
                assert_eq!(j.csrf_token.as_deref(), Some("t"));
            }
            _ => panic!("attendu Json"),
        }

        // Form
        let (req, mut pl) = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("username=u&password=p&csrf_token=t2")
        .to_http_parts();

        let got = super::EitherAuth::from_request(&req, &mut pl).await.unwrap();
        match got {
            super::EitherAuth::Form(f) => {
                assert_eq!(f.username, "u");
                assert_eq!(f.password, "p");
                assert_eq!(f.csrf_token.as_deref(), Some("t2"));
            }
            _ => panic!("attendu Form"),
        }

        // Unsupported
        let (req, mut pl) = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "text/plain"))
        .set_payload("x")
        .to_http_parts();
        assert!(super::EitherAuth::from_request(&req, &mut pl).await.is_err());
    }

    // --------- validate_csrf -------------------------------------------------

    #[tokio::test]
    async fn validate_csrf_allows_safe_and_checks_post() {
        let secret = "s3cr3t";

        // GET allow no token
        let req_get = test::TestRequest::default()
        .method(actix_web::http::Method::GET)
        .to_http_request();
        let ok = super::validate_csrf(&req_get, &super::EitherAuth::Json(AuthRequest{
            username:"".into(), password:"".into(), totp_code:None, csrf_token:None
        }), secret);
        assert!(ok);

        // POST no token => false
        let req_post = test::TestRequest::default()
        .method(actix_web::http::Method::POST)
        .to_http_request();
        let bad = super::validate_csrf(&req_post, &super::EitherAuth::Json(AuthRequest{
            username:"".into(), password:"".into(), totp_code:None, csrf_token:None
        }), secret);
        assert!(!bad);

        // POST token valid
        let tok = make_csrf_token(secret);
        let good = super::validate_csrf(&req_post, &super::EitherAuth::Json(AuthRequest{
            username:"".into(), password:"".into(), totp_code:None, csrf_token:Some(tok)
        }), secret);
        assert!(good);
    }

    // --------- is_ip_allowed -------------------------------------------------

    #[test]
    async fn is_ip_allowed_variants() {
        let base = || User { username:"u".into(), password:"h".into(), otpkey:None, allow:None, roles:None };

        let user_none = base();
        assert!(super::is_ip_allowed("203.0.113.7", &user_none));

        let user_empty = User { allow: Some(vec![]), ..base() };
        assert!(super::is_ip_allowed("203.0.113.7", &user_empty));

        let user_ipv4 = User { allow: Some(vec!["203.0.113.0/24".into()]), ..base() };
        assert!(super::is_ip_allowed("203.0.113.7", &user_ipv4));
        assert!(!super::is_ip_allowed("203.0.114.1", &user_ipv4));

        let user_ipv6 = User { allow: Some(vec!["2001:db8::/32".into()]), ..base() };
        assert!(super::is_ip_allowed("2001:db8::1", &user_ipv6));
        assert!(!super::is_ip_allowed("2001:dead::1", &user_ipv6));
    }

    // --------- verify_password ----------------------------------------------

    #[test]
    async fn verify_password_ok_bad() {
        let hashed = hash_pwd("hunter2");
        assert!(super::verify_password("hunter2", &hashed));
        assert!(!super::verify_password("wrong", &hashed));
    }

    // --------- generate_random_string ---------------------------------------

    #[test]
    async fn generate_random_string_is_hex64() {
        let s = super::generate_random_string(32);
        assert_eq!(s.len(), 64, "blake3 en hex → 64 chars");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --------- expiry helpers ------------------------------------------------

    #[test]
    async fn expiry_helpers_are_deterministic() {
        let mut cfg = base_config();
        cfg.token_expiry_seconds = 3600;
        cfg.timezone = "Europe/Paris".into();
        let cfg = Arc::new(cfg);

        let ts = 1_700_000_000i64;
        let dt = super::get_expiry_with_timezone(cfg.clone(), Some(ts));
        assert_eq!(dt.timezone().name(), "Europe/Paris");

        let fmt = super::get_expiry_with_timezone_format(cfg, Some(ts));
        assert!(fmt.contains(':'));
        assert!(fmt.len() >= 10);
    }

    // --------- auth_options (CORS) ------------------------------------------

    #[tokio::test]
    async fn auth_options_cors_ok_and_forbidden() {
        // OK
        let mut cfg_ok = base_config();
        cfg_ok.cors_origins = Some(vec!["https://app.example.com".into()]);
        let state_ok = mk_state(vec![], cfg_ok);

        let req = test::TestRequest::default()
        .insert_header((header::ORIGIN, "https://app.example.com"))
        .to_http_request();

        let resp = super::auth_options(req, state_ok).await
        .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(resp.status(), StatusCode::OK);
        let b_res = actix_to_bytes(resp.into_body()).await;
        let b = b_res.unwrap_or_else(|_| bytes::Bytes::new());
        assert!(b.is_empty());

        // Forbidden
        let state_ko = mk_state(vec![], base_config());
        let req2 = test::TestRequest::default()
        .insert_header((header::ORIGIN, "https://not-allowed.example"))
        .to_http_request();
        let resp2 = super::auth_options(req2, state_ko).await
        .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    }

    // --------- auth handler --------------------------------------------------

    #[tokio::test]
    async fn auth_success_json_with_csrf_sets_cookie_and_redirects() {
        let user = User {
            username: "alice".into(),
            password: hash_pwd("passw0rd"),
            otpkey: None,
            allow: None,
            roles: Some(vec!["user".into()]),
        };

        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_redirect_url = Some("/home".into());
        let data = mk_state(vec![], cfg);

        let tok = make_csrf_token(&data.config.secret);

        let req = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-forwarded-for", "203.0.113.7"))
        .set_payload(r#"{"username":"alice","password":"passw0rd","csrf_token":""}"#)
        .to_http_request();

        let payload = super::EitherAuth::Json(AuthRequest{
            username:"alice".into(),
            password:"passw0rd".into(),
            totp_code: None,
            csrf_token: Some(tok),
        });

        let resp = super::auth(req, data.clone(), payload).await
        .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let mut has_cookie = false;
        for v in resp.headers().get_all(header::SET_COOKIE).into_iter() {
            if v.to_str().unwrap_or("").starts_with("session_token=") {
                has_cookie = true;
                break;
            }
        }
        assert!(has_cookie);

        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/home");
    }

    #[tokio::test]
    async fn auth_invalid_password_renders_error_page_401() {
        static HTML: &str = r#"<!doctype html>
        <html><head><title>Logout</title></head>
        <body>
        <!-- BEGIN_BLOCK_ERROR -->
        <!-- <div class="err">{{ error }}</div> -->
        <!-- END_BLOCK_ERROR -->
        {{ csrf_token }}
        </body></html>"#;

        let (addr, _join) = start_backend(HTML);

        let logout_url = format!("http://{}/logout", addr);
        let routes = vec![ rr("/logout", &format!("http://{}/logout", addr)) ];

        let mut cfg = base_config();
        cfg.users = vec![ User {
            username: "bob".into(),
            password: hash_pwd("correct"),
            otpkey: None,
            allow: None,
            roles: None,
        }];
        cfg.logout_redirect_url = Some(logout_url);
        let data = mk_state(routes, cfg);

        let tok = make_csrf_token(&data.config.secret);
        let req = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-forwarded-for", "198.51.100.9"))
        .to_http_request();

        let payload = super::EitherAuth::Json(AuthRequest{
            username:"bob".into(),
            password:"wrong".into(),
            totp_code: None,
            csrf_token: Some(tok),
        });

        let resp = super::auth(req, data.clone(), payload).await
        .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body_res = actix_to_bytes(resp.into_body()).await;
        let body = body_res.unwrap_or_else(|_| bytes::Bytes::new());
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("err"));
    }

    fn build_valid_session_cookie_for_user(
        data: &actix_web::web::Data<AppState>,
        index_user: usize,
        token_id: &str,
        seconds_from_now: i64,
    ) -> String {
        use chrono::Utc;
        let user = &data.config.users[index_user];
        let expiry_ts = (Utc::now() + chrono::Duration::seconds(seconds_from_now)).timestamp().to_string();

        // même token applicatif que validate_token attend
        let token_plain = generate_token(&user.username, &data.config, &expiry_ts, token_id);

        // pré-hash appli « transport »
        let cipher_part = calcul_cipher(token_plain);

        // concatène les 4 segments
        let clear = format!("{cipher_part}|{expiry_ts}|{index_user}|{token_id}");

        // chiffre avec la clé dérivée du secret (exactement comme dans le handler)
        let key = derive_key_from_secret(&data.config.secret);
        encrypt(&clear, &key)
    }

    // ---------- EitherAuth::Form end-to-end ----------

    #[tokio::test]
    async fn either_auth_form_end_to_end_with_csrf_ok_redirects_and_sets_cookie() {
        // Config de base avec un user « alice »
        let user = User {
            username: "alice".into(),
            password: hash_pwd("passw0rd"),
            otpkey: None,
            allow: None,
            roles: None,
        };
        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_redirect_url = Some("/home".into());
        let data = mk_state(vec![], cfg);

        // CSRF
        let tok = make_csrf_token(&data.config.secret);

        // Requête Form
        let form = format!(
            "username=alice&password=passw0rd&csrf_token={}",
            urlencoding::encode(&tok)
        );
        let req = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .insert_header(("x-forwarded-for", "203.0.113.7"))
        .set_payload(form)
        .to_http_request();

        // EitherAuth::Form
        let payload = super::EitherAuth::Form(AuthRequest {
            username: "alice".into(),
            password: "passw0rd".into(),
            totp_code: None,
            csrf_token: Some(tok),
        });

        let resp = super::auth(req, data.clone(), payload)
        .await
        .respond_to(&test::TestRequest::default().to_http_request());

        // On est redirigé et un cookie session est posé
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/home");
        let has_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .into_iter() // <- IMPORTANT: pas `.iter()`
        .any(|v| v.to_str().unwrap_or("").starts_with("session_token="));
        assert!(has_cookie);
    }

    // ---------- Session cookie déjà présent (early return) + CORS reflété ----------

    #[tokio::test]
    async fn auth_with_valid_session_cookie_short_circuits_and_reflects_cors() {
        // User + CORS autorisé
        let user = User {
            username: "alice".into(),
            password: hash_pwd("irrelevant"),
            otpkey: None,
            allow: None,
            roles: None,
        };
        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_redirect_url = Some("/dashboard".into());
        cfg.cors_origins = Some(vec!["https://app.example.com".into()]);
        let data = mk_state(vec![], cfg);

        let token_enc = build_valid_session_cookie_for_user(&data, 0, "tid-cookie", 300);

        let req = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((header::ORIGIN, "https://app.example.com"))
        .cookie(Cookie::build("session_token", token_enc).finish())
        .to_http_request();

        let payload = super::EitherAuth::Json(AuthRequest {
            username: "alice".into(),
            password: "does-not-matter".into(),
            totp_code: None,
            csrf_token: Some(make_csrf_token(&data.config.secret)),
        });

        let resp = super::auth(req, data.clone(), payload)
        .await
        .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/dashboard");
        assert_eq!(
            resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
                   Some("https://app.example.com")
        );
        assert_eq!(
            resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .and_then(|v| v.to_str().ok()),
                   Some("true")
        );
    }

    // ---------- Session cookie: redirect URL invalide (pas un chemin relatif) ----------

    #[tokio::test]
    async fn auth_session_cookie_redirect_url_must_be_relative() {
        let user = User {
            username: "alice".into(),
            password: hash_pwd("passw0rd"),
            otpkey: None,
            allow: None,
            roles: None,
        };
        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_redirect_url = Some("https://evil.example/path".into());
        let data = mk_state(vec![], cfg);

        let req = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .to_http_request();

        let payload = super::EitherAuth::Json(AuthRequest {
            username: "alice".into(),
            password: "passw0rd".into(),
            totp_code: None,
            csrf_token: Some(make_csrf_token(&data.config.secret)),
        });

        let resp = super::auth(req, data.clone(), payload)
        .await
        .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ---------- TOTP: succès ----------

    #[tokio::test]
    async fn auth_totp_success_sets_cookie_and_redirects() {
        use base32::Alphabet;
        // secret TOTP aléatoire RFC4648 (sans padding)
        let raw_secret: [u8; 20] = *b"0123456789ABCDEFGHIJ";
        let b32 = base32::encode(Alphabet::RFC4648 { padding: false }, &raw_secret);

        let user = User {
            username: "carol".into(),
            password: hash_pwd("otp-pass"),
            otpkey: Some(b32.clone()),
            allow: None,
            roles: None,
        };

        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_via_otp = true;
        cfg.login_redirect_url = Some("/after-otp".into());
        let data = mk_state(vec![], cfg);

        let secret_bytes =
        base32::decode(Alphabet::RFC4648 { padding: false }, &b32).expect("decode b32");
        let totp = TOTP::new(Algorithm::SHA512, 6, 0, 30, secret_bytes).expect("totp");
        let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
        let code = totp.generate(now);

        let tok = make_csrf_token(&data.config.secret);

        let req = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-forwarded-for", "203.0.113.9"))
        .to_http_request();

        let payload = super::EitherAuth::Json(AuthRequest {
            username: "carol".into(),
                                              password: "otp-pass".into(),
                                              totp_code: Some(code),
                                              csrf_token: Some(tok),
        });

        let resp = super::auth(req, data.clone(), payload)
        .await
        .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/after-otp");
        let has_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .into_iter() // <- IMPORTANT: pas `.iter()`
        .any(|v| v.to_str().unwrap_or("").starts_with("session_token="));
        assert!(has_cookie);
    }

    // ---------- CORS dans le flux « nouvelle session » (pas cookie existant) ----------

    #[tokio::test]
    async fn auth_sets_cors_headers_when_origin_allowed_on_new_session() {
        let user = User {
            username: "erin".into(),
            password: hash_pwd("pw"),
            otpkey: None,
            allow: None,
            roles: None,
        };

        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.cors_origins = Some(vec!["https://front.example".into()]);
        cfg.login_redirect_url = Some("/ok".into());
        let data = mk_state(vec![], cfg);

        let tok = make_csrf_token(&data.config.secret);

        let req = test::TestRequest::default()
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((header::ORIGIN, "https://front.example"))
        .insert_header(("x-forwarded-for", "203.0.113.10"))
        .to_http_request();

        let payload = super::EitherAuth::Json(AuthRequest {
            username: "erin".into(),
            password: "pw".into(),
            totp_code: None,
            csrf_token: Some(tok),
        });

        let resp = super::auth(req, data.clone(), payload)
        .await
        .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok()),
                   Some("https://front.example")
        );
        assert_eq!(
            resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
            .and_then(|v| v.to_str().ok()),
                   Some("true")
        );
        assert_eq!(
            resp.headers()
            .get(header::ACCESS_CONTROL_MAX_AGE)
            .and_then(|v| v.to_str().ok()),
                   Some("3600")
        );
    }
}

#[cfg(test)]
mod render_error_page_tests {
    use super::*;
    use actix_web::{test, http::header};
    use bytes::Bytes as ActixBytes;
    use std::sync::Arc;
    use dashmap::DashMap;
    use hyper::{Body, Response, Server};
    use hyper::client::HttpConnector;
    use hyper::service::{make_service_fn, service_fn};
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};
    use crate::config::config::{AppConfig, RouteConfig, RouteRule};
    use crate::revoke::db::RevokedTokenMap;

    // ------------ helpers clients ------------
    fn https_client() -> hyper::Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        hyper::Client::builder().build::<_, Body>(https)
    }
    fn proxy_client() -> hyper::Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        hyper::Client::builder().build(pc)
    }

    fn mk_state(routes: Vec<RouteRule>, mut cfg: AppConfig) -> actix_web::web::Data<AppState> {
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes }),
            counter: Arc::new(crate::stats::tokencount::CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()) as RevokedTokenMap,
        };
        actix_web::web::Data::new(state)
    }

    fn base_cfg() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "unit-secret-xyz".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 16,
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
            login_redirect_url: Some("/home".into()),
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
        }
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
            cache: true,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
        }
    }

    // ------------ backend util (hyper) ------------
    fn start_backend(html: &'static str, status: u16) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let local_addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let make = make_service_fn(move |_conn| {
            let html = html.to_string();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |_req| {
                    let html = html.clone();
                    async move {
                        let mut builder = Response::builder().status(status);
                        // on renvoie HTML compressable
                        builder = builder.header(header::CONTENT_TYPE, "text/html; charset=utf-8");
                        Ok::<_, hyper::Error>(builder.body(Body::from(html)).unwrap())
                    }
                }))
            }
        });

        let server = Server::from_tcp(listener).unwrap().serve(make);
        let j = tokio::spawn(async move { let _ = server.await; });
        (local_addr, j)
    }

    // ------------ tests ------------

    #[tokio::test]
    async fn render_error_page_missing_logout_config_returns_400() {
        let mut cfg = base_cfg();
        cfg.logout_redirect_url = None; // <- manquant
        let data = mk_state(vec![], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = super::render_error_page(&req, data, "boom").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap_or_else(|_| ActixBytes::new());
        assert_eq!(&body[..], b"logout_redirect_url is not configured");
    }

    #[tokio::test]
    async fn render_error_page_no_matching_route_returns_400() {
        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some("/logout".into()); // pas de règle /logout
        let data = mk_state(vec![ rr("/only", "http://127.0.0.1:9") ], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = super::render_error_page(&req, data, "x").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap_or_else(|_| ActixBytes::new());
        assert_eq!(&body[..], b"No matching route for logout_redirect_url path");
    }

    #[tokio::test]
    async fn render_error_page_backend_500_maps_to_400() {
        static HTML_ERR: &str = "<html><!-- BEGIN_BLOCK_ERROR -->{{ error }}<!-- END_BLOCK_ERROR --></html>";
        let (addr, _j) = start_backend(HTML_ERR, 500);
        let url = format!("http://{}/logout", addr);

        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some(url);
        let routes = vec![ rr("/logout", &format!("http://{}/logout", addr)) ];
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = super::render_error_page(&req, data, "msg").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn render_error_page_upstream_client_error_maps_to_503() {
        // cible invalide: port 1 → connection refused => branche Upstream client error
        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some("http://127.0.0.1:1/logout".into());
        let routes = vec![ rr("/logout", "http://127.0.0.1:1/logout") ];
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = super::render_error_page(&req, data, "x").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn render_error_page_happy_path_returns_401_and_is_html() {
        static HTML_OK: &str = r#"<!doctype html>
        <html><head><title>Logout</title></head>
        <body>
        <!-- BEGIN_BLOCK_ERROR --><div class="err">{{ error }}</div><!-- END_BLOCK_ERROR -->
        {{ csrf_token }}
        </body></html>"#;

        let (addr, _j) = start_backend(HTML_OK, 200);
        let url = format!("http://{}/logout?x=1", addr);

        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some(url.clone());
        let routes = vec![ rr("/logout", &format!("http://{}/logout", addr)) ];
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default()
        .insert_header((header::ORIGIN, "https://app.example.com"))
        .insert_header((header::USER_AGENT, "UA"))
        .to_http_request();

        let resp = super::render_error_page(&req, data, "Invalid credentials").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap().to_ascii_lowercase();
        assert!(ct.contains("text/html"));

        let body = actix_web::body::to_bytes(resp.into_body()).await.unwrap_or_else(|_| ActixBytes::new());
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("Invalid credentials")); // bloc d’erreur injecté
        assert!(!s.contains("{{ csrf_token }}"));
    }

    #[tokio::test]
    async fn render_error_page_absolute_url_with_query_is_forwarded() {
        static HTML_OK: &str = "<html><!-- BEGIN_BLOCK_ERROR -->{{ error }}<!-- END_BLOCK_ERROR -->OK</html>";
        let (addr, _j) = start_backend(HTML_OK, 200);

        // URL ABSOLUE avec query
        let logout = format!("http://{}/logout/path?q=42", addr);
        let routes = vec![ rr("/logout", &format!("http://{}/logout", addr)) ];

        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some(logout);
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = super::render_error_page(&req, data, "boom").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn render_error_page_forces_html_content_type_when_backend_non_html() {
        use std::net::TcpListener;
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let make = make_service_fn(move |_conn| {
            async move {
                Ok::<_, hyper::Error>(service_fn(move |_req| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                        .status(200)
                        .header(header::CONTENT_TYPE, "text/plain") // <- non HTML
                        .body(Body::from("NOT HTML {{ csrf_token }}"))
                        .unwrap()
                    )
                }))
            }
        });
        let server = Server::from_tcp(listener).unwrap().serve(make);
        let _j = tokio::spawn(async move { let _ = server.await; });

        let abs = format!("http://{}/logout", addr);
        let routes = vec![ rr("/logout", &format!("http://{}/logout", addr)) ];

        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some(abs);
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = super::render_error_page(&req, data, "x").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let ct = resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap().to_ascii_lowercase();
        assert!(ct.contains("text/html"));
    }
}
