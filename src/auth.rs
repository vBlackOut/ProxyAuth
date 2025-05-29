use crate::AppState;
use crate::config::AuthRequest;
use crate::crypto::{calcul_cipher, derive_key_from_secret, encrypt};
use crate::proxy::client_ip;
use crate::security::generate_token;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use chrono::{Duration, Utc, TimeZone};
use chrono_tz::Tz;
use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use sha2::{Sha256, Digest};
use crate::AppConfig;
use std::sync::Arc;
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
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*()+-=";
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

    let hash = Sha256::digest(&full_input);

    hex::encode(hash)
}

fn get_expiry_with_timezone(config: Arc<AppConfig>, optional_timestamp: Option<i64>) -> String {
    let tz: Tz = config
        .timezone
        .parse()
        .expect("Invalid timezone in config");

    let utc_now = optional_timestamp
        .map(|ts| Utc.timestamp_opt(ts, 0).single().expect("Invalid timestamp"))
        .unwrap_or_else(Utc::now);

    let local_time = utc_now.with_timezone(&tz);
    let expiry = local_time + Duration::seconds(config.token_expiry_seconds);

    expiry.timestamp().to_string()
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


        let expiry = get_expiry_with_timezone(data.config.clone(), None);

        let id_token = generate_random_string(48);

        let token = generate_token(
            &auth.username,
            &data.config,
            &expiry,
            &id_token,
        );

        let key = derive_key_from_secret(&data.config.secret);

        let cipher_token = format!(
            "{}|{}|{}|{}",
            calcul_cipher(token.clone()),
            expiry,
            index_user,
            id_token
        );

        let token_encrypt = encrypt(&cipher_token, &key);

        let expiry_ts: i64 = expiry
            .parse()
            .expect("Invalid timestamp string");

        let expiry_utc = Utc
            .timestamp_opt(expiry_ts, 0)
            .single()
            .expect("Invalid timestamp value");

        let tz: Tz = data.config
            .timezone
            .parse()
            .expect("Invalid timezone");

        let expiry_dt_local = expiry_utc.with_timezone(&tz);
        let expires_at_str = expiry_dt_local.format("%Y-%m-%d %H:%M:%S").to_string();

        info!(
            "[{}] new token generated for user {} expirated at {}",
            ip, user.username, expires_at_str
        );
        HttpResponse::Ok().json(serde_json::json!({
            "token": token_encrypt,
            "expires_at": expires_at_str,
        }))
    } else {
        warn!("Invalid credential for enter user {}.", auth.username);
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }
}
