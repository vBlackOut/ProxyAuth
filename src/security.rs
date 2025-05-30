use crate::AppConfig;
use crate::AppState;
use crate::crypto::{calcul_factorhash, decrypt, derive_key_from_secret};
use crate::timezone::check_date_token;
use actix_web::web;
use chrono::{Timelike, Utc};
use hex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{error, info, warn};
use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/shuffle_generated.rs"));

fn get_build_time() -> u64 {
    env!("BUILD_TIME").parse().expect("Invalid build time")
}

pub fn get_build_rand() -> u64 {
    env!("BUILD_RAND").parse().expect("Invalid build random")
}

static DERIVED_KEY: OnceLock<[u8; 32]> = OnceLock::new();

pub fn init_derived_key(secret: &str) {
    let key = derive_key_from_secret(secret); // ta fonction custom
    DERIVED_KEY.set(key).expect("Key already initialized");
}

pub fn generate_secret(secret: &str) -> String {
    let now = Utc::now();

    let today = now
        .with_hour(0)
        .expect("Failed to set hour to 0")
        .with_minute(0)
        .expect("Failed to set minute to 0")
        .with_second(0)
        .expect("Failed to set second to 0")
        .with_nanosecond(0)
        .expect("Failed to set nanosecond to 0");

    let timestamp = today.timestamp();
    let dynamic_secret = format!("{}:{}", secret, timestamp);
    dynamic_secret
}

pub fn generate_token(username: &str, secret: &str, time_expire: &str, token_id: &str) -> String {
    let values_map = HashMap::from([
        ("username", username.to_string()),
        ("secret_with_timestamp", generate_secret(secret)),
        ("build_time", get_build_time().to_string()),
        ("time_expire", time_expire.to_string()),
        ("build_rand", get_build_rand().to_string()),
        ("token_id", token_id.to_string()),
    ]);

    let shuffled: Vec<String> = SHUFFLED_ORDER
        .iter()
        .map(|k| values_map[*k].clone())
        .collect();

    let shuffle_data = shuffled.join(":");
    let mut signature = Sha256::new();
    signature.update(shuffle_data.as_bytes());
    format!("{:x}", signature.finalize())
}

pub async fn validate_token(
    token: &str,
    data_app: &web::Data<AppState>,
    config: &AppConfig,
    ip: &str,
) -> Result<String, String> {
    let key = derive_key_from_secret(&config.secret);

    let decrypt_token = decrypt(token, &key).map_err(|_| "Invalid token format")?;

    let data: [&str; 4] = decrypt_token
        .splitn(4, '|')
        .collect::<Vec<&str>>()
        .try_into()
        .map_err(|_| "Invalid token format")?;

    let (token_hash_decrypt, factor) = data[0]
        .rsplit_once('=')
        .and_then(|(hash, factor_str)| factor_str.parse::<i64>().ok().map(|f| (hash, f)))
        .ok_or("Invalid token format or factor")?;

    let index_user = data[2].parse::<usize>().map_err(|_| "Index invalide")?;
    let user = config
        .users
        .get(index_user)
        .ok_or("Utilisateur introuvable")?;

    let time_expire = check_date_token(data[1], &user.username, ip)
        .map_err(|_| "Your token is expired")?;

    if (time_expire > (config.token_expiry_seconds as i64).try_into().unwrap()).try_into().unwrap() {
        error!(
            "[{}] username {} try to access token limit config {} value request {}",
            ip, user.username, config.token_expiry_seconds, time_expire
        );
        return Err("Bad time token".to_string());
    }

    let token_generated = generate_token(&user.username, &config.secret, data[1], data[3]);
    let token_hash = calcul_factorhash(token_generated, factor);

    if hex::encode(Sha256::digest(token_hash)) != token_hash_decrypt {
        warn!("[{}] Invalid token", ip);
        return Err("no valid token".to_string());
    }

    if config.stats {
        let count = data_app.counter.record_and_get(&user.username, data[3]);

        info!(
            "[{}] user {} is logged token expire in {} seconds [token used: {}]",
            ip, user.username, time_expire, count
        );
    }

    Ok(user.username.to_string())
}

pub fn extract_token_user(token: &str, config: &AppConfig, ip: String) -> Result<String, String> {
    let key = derive_key_from_secret(&config.secret);

    let decrypt_token = match decrypt(token, &key) {
        Ok(val) => val,
        Err(_) => {
            warn!("[{}] Failed to decrypt token (invalid format)", ip);
            return Err("Invalid token format".into());
        }
    };

    let data: Vec<&str> = decrypt_token.split('|').collect();

    if data.len() < 3 {
        warn!("[{}] Token structure is invalid (not enough segments)", ip);
        return Err("Invalid token content".into());
    }

    let index_user: usize = match data[2].parse() {
        Ok(i) => i,
        Err(_) => {
            warn!("[{}] Failed to parse user index from token", ip);
            return Err("Invalid user index".into());
        }
    };

    if let Some(user) = config.users.get(index_user) {
        Ok(user.username.clone())
    } else {
        warn!("[{}] User index out of bounds: {}", ip, index_user);
        Err("User not found".into())
    }
}
