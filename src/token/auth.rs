use crate::AppConfig;
use crate::AppState;
use crate::config::config::{AuthRequest, User};
use crate::network::proxy::client_ip;
use crate::token::crypto::{calcul_cipher, derive_key_from_secret, encrypt};
use crate::token::security::{generate_token, validate_token};
use actix_web::{HttpRequest, http::header, HttpResponse, Responder, web};
use actix_web::cookie::{Cookie, SameSite};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use blake3;
use chrono::{DateTime, Duration, TimeZone, Utc};
use chrono_tz::Tz;
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
        .insert_header((header::ACCESS_CONTROL_ALLOW_HEADERS, "Authorization, Content-Type, Accept"))
        .insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"))
        .insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"))
        .finish()
    } else {
        HttpResponse::Forbidden().body("CORS origin not allowed")
    }
}

pub async fn auth(
    req: HttpRequest,
    auth: web::Json<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {

    let ip = client_ip(&req).expect("?").to_string();

    // Check if session_cookie is enabled
    if data.config.session_cookie {
        if let Some(cookie) = req.cookie("session_token") {
            let session_token = cookie.value();
            info!("[{}] Found session cookie: {}", ip, session_token);

            if let Ok((username, _token_id, expires_at)) = validate_token(
                session_token,
                &data,
                &data.config,
                &ip,
            ).await {
                let mut resp = HttpResponse::Ok();
                resp.append_header(("server", "ProxyAuth"));

                // CORS check
                if let Some(origin_header) = req.headers().get(header::ORIGIN) {
                    if let Ok(origin_str) = origin_header.to_str() {
                        if let Some(cors_origins) = &data.config.cors_origins {
                            let origin_normalized = origin_str.trim_end_matches('/');

                            if cors_origins.iter().any(|allowed| allowed.trim_end_matches('/') == origin_normalized) {
                                resp.append_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str));
                                resp.append_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
                                resp.append_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
                            }
                        }
                    }
                }

                return resp.json(serde_json::json!({
                    "user": username,
                    "expires_at": expires_at,
                }));
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
            return HttpResponse::Forbidden()
                .append_header(("server", "ProxyAuth"))
                .body("Access denied");
        }

        // totp method
        if data.config.login_via_otp {
            let totp_code = match &auth.totp_code {
                Some(code) => code.trim(),
                None => {
                    warn!("[{}] Missing TOTP code for user {}", ip, user.username);
                    return HttpResponse::Unauthorized()
                        .append_header(("server", "ProxyAuth"))
                        .body("Missing TOTP code");
                }
            };

            let totp_key = match user.otpkey.as_deref() {
                Some(key) => key,
                None => {
                    warn!("[{}] Missing TOTP secret for user {}", ip, user.username);
                    return HttpResponse::InternalServerError()
                        .append_header(("server", "ProxyAuth"))
                        .body("Missing TOTP secret");
                }
            };

            let decoded_secret =
                match base32::decode(base32::Alphabet::RFC4648 { padding: false }, totp_key) {
                    Some(bytes) => bytes,
                    None => {
                        warn!("Invalid base32 TOTP secret for user {}", user.username);
                        return HttpResponse::InternalServerError()
                            .append_header(("server", "ProxyAuth"))
                            .body("Internal TOTP error");
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
                return HttpResponse::Unauthorized()
                    .append_header(("server", "ProxyAuth"))
                    .body("Invalid TOTP code");
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
            let cookie_expiry_time = OffsetDateTime::from_unix_timestamp(cookie_expiry.timestamp()).unwrap();

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

                        if cors_origins.iter().any(|allowed| allowed.trim_end_matches('/') == origin_normalized) {
                            resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str));
                            resp.insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
                            resp.insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
                        }
                    }
                }
            }

            resp.cookie(cookie);

        }

        resp.json(serde_json::json!({
            "token": token_encrypt,
            "expires_at": expires_at_str,
        }))

    } else {
        warn!("Invalid credential for enter user {}.", auth.username);
        return HttpResponse::Unauthorized()
            .append_header(("server", "ProxyAuth"))
            .body("Invalid credentials");
    }
}
