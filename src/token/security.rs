use crate::AppConfig;
use crate::AppState;
use crate::build::build_info::get;
use crate::timezone::check_date_token;
use crate::token::crypto::{calcul_factorhash, decrypt, derive_key_from_secret};
use actix_web::web;
use chrono::{Duration, TimeZone, Timelike, Utc};
use hex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{error, info, warn};

fn get_build_time() -> u64 {
    let get_build = get();
    let data = get_build.build_time;
    data
}

pub fn get_build_rand() -> u64 {
    let get_build = get();
    let data = get_build.build_rand;
    data
}

pub fn get_build_seed2() -> u64 {
    let get_build = get();
    let data = get_build.build_seed2;
    data
}

pub fn get_build_epochdate() -> i64 {
    let get_build = get();
    let data = get_build.build_epoch;
    data
}

pub fn get_build_datetime() -> chrono::DateTime<chrono::Utc> {
    let seconds = get_build_epochdate();
    let naive = Utc.timestamp_opt(seconds, 0).unwrap();
    naive
}

static DERIVED_KEY: OnceLock<[u8; 32]> = OnceLock::new();

#[allow(dead_code)]
fn format_long_date(seconds: u128) -> String {
    let seconds_per_year = 31_557_600u128;
    let year = seconds / seconds_per_year;
    let remaining = seconds % seconds_per_year;

    let _days = remaining / 86400;
    let hours = (remaining % 86400) / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    format!(
        "+{:0>8}-01-01T{:02}:{:02}:{:02}Z",
        year, hours, minutes, seconds
    )
}

pub fn init_derived_key(secret: &str) {
    let key = derive_key_from_secret(secret);
    DERIVED_KEY.set(key).expect("Key already initialized");
}

pub fn generate_secret(secret: &str, token_expiry_seconds: &i64) -> String {
    let base = get_build_datetime();

    let next_reset_time = match *token_expiry_seconds {
        0..=86_400 => base + Duration::seconds(*token_expiry_seconds),

        86_401..=2_419_200 => {
            let weeks = (*token_expiry_seconds as f64 / (7.0 * 86400.0)).ceil() as i64;
            base + Duration::days(weeks * 7)
        }

        2_419_201..=31_104_000 => {
            let months = (*token_expiry_seconds as f64 / (30.0 * 86400.0)).ceil() as u32;

            let mut year = 0;
            let mut month = 1 + months;

            while month > 12 {
                month -= 12;
                year += 1;
            }

            let (next_year, next_month) = if month == 12 {
                (year + 1, 1)
            } else {
                (year, month + 1)
            };

            let first_of_next_month = Utc
                .with_ymd_and_hms(next_year as i32, next_month, 1, 0, 0, 0)
                .unwrap();

            let last_day = first_of_next_month - Duration::days(1);
            last_day
                .with_hour(23)
                .unwrap()
                .with_minute(59)
                .unwrap()
                .with_second(59)
                .unwrap()
        }

        31_104_001..=157_680_000 => {
            let years = (*token_expiry_seconds as f64 / (365.0 * 86400.0)).ceil() as i32;
            Utc.with_ymd_and_hms(0 + years, 12, 31, 23, 59, 59).unwrap()
        }

        _ => base + Duration::seconds(86_400),
    };

    let now = Utc::now();
    let _remaining_seconds = (next_reset_time - now).num_seconds();

    format!("{}:{}", secret, next_reset_time.timestamp())
}

pub fn generate_token(
    username: &str,
    config: &AppConfig,
    time_expire: &str,
    token_id: &str,
) -> String {
    let values_map = HashMap::from([
        ("username", username.to_string()),
        (
            "secret_with_timestamp",
            generate_secret(&config.secret, &config.token_expiry_seconds),
        ),
        ("build_time", get_build_time().to_string()),
        ("time_expire", time_expire.to_string()),
        ("build_rand", get_build_rand().to_string()),
        ("token_id", token_id.to_string()),
    ]);

    let shuffled: Vec<String> = get()
        .shuffled_order_list()
        .iter()
        .map(|k| values_map[k.as_str()].clone())
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
) -> Result<(String, String), String> {
    let key = derive_key_from_secret(&config.secret);

    let decrypt_token = decrypt(token, &key).map_err(|_| "Invalid token format")?;

    let data: [&str; 4] = decrypt_token
        .splitn(4, '|')
        .collect::<Vec<&str>>()
        .try_into()
        .map_err(|_| "Invalid token format")?;

    let token_hash_decrypt = data[0];

    let index_user = data[2].parse::<usize>().map_err(|_| "Index invalide")?;
    let user = config.users.get(index_user).ok_or("User not found")?;

    let time_expire = check_date_token(data[1], &user.username, ip, &config.timezone)
        .map_err(|_| "Your token is expired")?;

    if (time_expire > (config.token_expiry_seconds as i64).try_into().unwrap())
        .try_into()
        .unwrap()
    {
        error!(
            "[{}] username {} try to access token limit config {} value request {}",
            ip, user.username, config.token_expiry_seconds, time_expire
        );
        return Err("Bad time token".to_string());
    }

    let token_generated = generate_token(&user.username, &config, data[1], data[3]);
    let token_hash = calcul_factorhash(token_generated);

    if hex::encode(Sha256::digest(token_hash)) != token_hash_decrypt {
        warn!("[{}] Invalid token", ip);
        return Err("no valid token".to_string());
    }

    if config.stats {
        let count =
            data_app
                .counter
                .record_and_get(&user.username, data[3], &time_expire.to_string());

        info!(
            "[{}] user {} is logged token expire in {} seconds [token used: {}]",
            ip, user.username, time_expire, count
        );
    } else {
        info!(
            "[{}] user {} is logged token expire in {} seconds",
            ip, user.username, time_expire
        );
    }

    Ok((user.username.to_string(), data[3].to_string()))
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
