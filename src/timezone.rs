use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use tracing::warn;

pub fn check_date_token(
    time_str: &str,
    username: &str,
    ip: &str,
    timezone: &str,
) -> Result<u64, ()> {
    let tz: Tz = timezone.parse().map_err(|_| {
        warn!("[{}] invalid timezone '{}'", ip, timezone);
        ()
    })?;

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

    // Convert to local time
    let expire_local = expire_time.with_timezone(&tz);
    let now_local = Utc::now().with_timezone(&tz);

    if now_local.timestamp() >= expire_local.timestamp() {
        warn!("[{}] token is expired for user {}", ip, username);
        return Err(());
    }

    let diff = expire_local.timestamp() - now_local.timestamp();
    diff.try_into().map_err(|_| ())
}
