use crate::AppState;
use crate::config::AuthRequest;
use crate::crypto::{calcul_cipher, derive_key_from_secret, encrypt};
use crate::proxy::client_ip;
use crate::security::generate_token;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use chrono::{Duration, Utc};
use chrono_tz::Europe::Paris;
use rand::seq::SliceRandom;
use rand::{Rng, thread_rng};
use tracing::{info, warn};

pub fn verify_password(input: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(input.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn generate_random_string(max_len: usize) -> String {
    let mut rng = thread_rng();
    let charset: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^*()+-=";
    let filtered: Vec<u8> = charset.iter().cloned().filter(|&c| c != b'|').collect();

    let len = rng.gen_range(max_len..=max_len);
    (0..len)
        .map(|_| *filtered.choose(&mut rng).unwrap() as char)
        .collect()
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

        let now = Utc::now();
        let fr_time = now.with_timezone(&Paris);
        let expiry = fr_time + Duration::seconds(data.config.token_expiry_seconds);

        let id_token = generate_random_string(48);

        let token = generate_token(
            &auth.username,
            &data.config.secret,
            &expiry.timestamp().to_string(),
            &id_token,
        );

        let key = derive_key_from_secret(&data.config.secret);

        let cipher_token = format!(
            "{}|{}|{}|{}",
            calcul_cipher(token.clone()),
            expiry.timestamp(),
            index_user,
            id_token
        );

        let token_encrypt = encrypt(&cipher_token, &key);
        let expires_at_str = expiry.format("%Y-%m-%d %H:%M:%S").to_string();

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
