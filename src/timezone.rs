use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use tracing::warn;

#[cfg(target_os = "linux")]
fn get_system_timezone_name() -> Option<String> {
    use std::process::Command;
    let output = Command::new("timedatectl")
        .arg("show")
        .arg("--property=Timezone")
        .output()
        .ok()?;
    let output_str = String::from_utf8_lossy(&output.stdout);
    Some(output_str.trim().replace("Timezone=", ""))
}

pub fn check_date_token(time_str: &str, username: &str, ip: &str) -> Result<u64, ()> {
    let expire_time: DateTime<Utc> = time_str.parse().map_err(|_| {
        warn!("[{}] failed to parse expiration time: {}", ip, time_str);
        ()
    })?;

    let system_tz = get_system_timezone_name()
        .and_then(|tz| tz.parse::<Tz>().ok())
        .unwrap_or(chrono_tz::UTC);

    let now = Utc::now().with_timezone(&system_tz);

    if now.timestamp() >= expire_time.timestamp() {
        warn!("[{}] token is expired for user {}", ip, username);
        return Err(());
    }

    let diff = expire_time.timestamp() - now.timestamp();
    diff.try_into().map_err(|_| ())
}
