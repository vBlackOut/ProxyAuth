use chrono::{DateTime, TimeZone, Utc};
use tracing::warn;

pub fn check_date_token(time_str: &str, username: &str, ip: &str) -> Result<u64, ()> {
    let expire_time = time_str
        .parse::<DateTime<Utc>>()
        .or_else(|_| {
            time_str
                .parse::<i64>()
                .map(|ts| Utc.timestamp_opt(ts, 0).single().unwrap())
        })
        .map_err(|_| {
            warn!("[{}] failed to parse expiration time: {}", ip, time_str);
            ()
        })?;

    let now = Utc::now();

    if now.timestamp() >= expire_time.timestamp() {
        warn!("[{}] token is expired for user {}", ip, username);
        return Err(());
    }

    let diff = expire_time.timestamp() - now.timestamp();
    diff.try_into().map_err(|_| ())
}
