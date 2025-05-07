use crate::crypto::{calcul_factorhash, decrypt, derive_key_from_secret};
use crate::AppConfig;
use crate::AppState;
use actix_web::web;
use chrono::{Timelike, Utc};
use chrono_tz::Europe::Paris;
use hex;
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

fn get_build_time() -> u64 {
    env!("BUILD_TIME").parse().expect("Invalid build time")
}

pub fn get_build_rand() -> u64 {
    env!("BUILD_RAND").parse().expect("Invalid build random")
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

pub fn generate_token(username: &str, secret: &str, time_expire: &str) -> String {
    let secret_with_timestamp = generate_secret(secret);
    let data = format!(
        "{}:{}:{}:{}:{}",
        username,
        secret_with_timestamp,
        get_build_time(),
        time_expire,
        get_build_rand(),
    );

    let mut signature = Sha256::new();
    signature.update(data.as_bytes());

    format!("{:x}", signature.finalize())
}

fn check_date_token(time_str: &str, username: &str, ip: &str) -> Result<u64, ()> {
    let expire: i64 = time_str.parse().expect("Error"); // check hour
                                                        //println!("{:?}", expire);
    let now = Utc::now();
    let fr_time = now.with_timezone(&Paris).timestamp();

    if fr_time >= expire {
        warn!("[{}] token is expired for user {}", ip, username);
        return Err(());
    }

    let diff = expire - fr_time;
    diff.try_into().map_err(|_| ())
}

pub fn validate_token(token: &str, data_app: &web::Data<AppState>, config: &AppConfig, ip: &str) -> Result<String, String> {
    let mut username = String::new();

    let key = derive_key_from_secret(&config.secret);

    let decrypt_token = match decrypt(token, &key) {
        Ok(val) => val,
        Err(_) => "Invalid token format".to_string(),
    };

    let data: Vec<&str> = decrypt_token.split('|').collect();

    info!("{:?}", data[3]);

    // Access the CounterToken
    let mut counter = data_app.counter.lock().map_err(|_| "Failed to lock counter")?;

    // record counter_token
    counter.record_call(data[3]);

    // give counter
    let count = counter.get_count(data[3]);

    let cleaned_token = decrypt_token
        .split('|')
        .next()
        .ok_or("Invalid token format")?;


    let (token_hash_decrypt, factor) = match cleaned_token.rsplit_once('=') {
        Some((hash, factor_str)) => match factor_str.parse::<i64>() {
            Ok(factor) => (hash.to_string(), factor),
            Err(_) => return Err("Invalid factor".into()),
        },
        None => return Err("Invalid token format".into()),
    };

    let index_user: usize = data[2].parse().map_err(|_| "Index invalide")?;
    let user = &config.users[index_user];

    let time_expire = match check_date_token(data[1], &user.username, ip) {
        Ok(time) => time,
        Err(_) => return Err("Your token is expired".into()),
    };

    if time_expire > config.token_expiry_seconds.try_into().unwrap() {
        error!(
            "[{}] username {} try to access token limit config {} value request {}",
            ip, user.username, config.token_expiry_seconds, time_expire
        );
        return Err("Bad time token".into());
    }

    let token_generated = generate_token(&user.username, &config.secret, data[1]);

    let token_hash = calcul_factorhash(token_generated, factor);

    let mut token_hash_bytes = Sha256::new();
    token_hash_bytes.update(token_hash.as_bytes());

    if hex::encode(token_hash_bytes.finalize().as_slice()) == token_hash_decrypt {
        username = user.username.clone();
    }

    if !username.is_empty() {
        info!(
            "[{}] user {} is logged token expire in {} seconds [token used: {}]",
            ip, user.username, time_expire, count
        );
        Ok(username)
    } else {
        warn!("[{}] Invalid token", ip);
        Err("no valid token".into())
    }
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
