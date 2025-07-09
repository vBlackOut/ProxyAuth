use crate::AppConfig;
use crate::AppState;
use crate::config::config::AuthRequest;
use crate::network::proxy::client_ip;
use crate::token::crypto::{calcul_cipher, derive_key_from_secret, encrypt};
use crate::token::security::generate_token;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use blake3;
use chrono::{DateTime, Duration, TimeZone, Utc};
use chrono_tz::Tz;
use hex;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};
use tracing::{info, warn};

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

    let local_time = utc_now.with_timezone(&tz);
    local_time + Duration::seconds(config.token_expiry_seconds)
}

pub async fn auth(
    req: HttpRequest,
    auth: web::Json<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let ip = client_ip(&req).expect("?").to_string();

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

        // totp method
        if data.config.login_via_otp {
            let totp_code = match &auth.totp_code {
                Some(code) => code.trim(),
                None => {
                    warn!("Missing TOTP code for user {}", user.username);
                    return HttpResponse::Unauthorized()
                        .append_header(("server", "ProxyAuth"))
                        .body("Missing TOTP code");
                }
            };

            let totp_key = match user.otpkey.as_deref() {
                Some(key) => key,
                None => {
                    warn!("Missing TOTP secret for user {}", user.username);
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

        let expiry_ts = expiry.naive_utc().and_utc().timestamp().to_string();
        let expires_at_str = expiry.format("%Y-%m-%d %H:%M:%S").to_string();

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
        HttpResponse::Ok()
            .append_header(("server", "ProxyAuth"))
            .json(serde_json::json!({
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
