use data_encoding::BASE32_NOPAD;
use rand::{RngCore, rngs::OsRng};
use totp_rs::{Algorithm, TOTP};
use urlencoding::encode;

// todo!() this file for create all method generete otpuri/totp/base32 and validate totp.

#[allow(dead_code)]
pub fn generate_base32_secret(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}

#[allow(dead_code)]
pub fn generate_otpauth_uri(
    label: &str,
    issuer: &str,
    secret_base32: &str,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
) -> String {
    let label_raw = format!("{}:{}", issuer, label);
    let label_encoded = encode(&label_raw);
    let issuer_encoded = encode(issuer);
    let algo_str = match algorithm {
        Algorithm::SHA1 => "SHA1",
        Algorithm::SHA256 => "SHA256",
        Algorithm::SHA512 => "SHA512",
    };

    format!(
        "otpauth://totp/{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        label_encoded, secret_base32, issuer_encoded, algo_str, digits, period
    )
}

#[allow(dead_code)]
pub fn generate_totp_code(
    secret_base32: &str,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
) -> Result<String, String> {
    let totp = TOTP::new(
        algorithm,
        digits.try_into().unwrap(),
        0,
        period,
        secret_base32.as_bytes().to_vec(),
    )
    .map_err(|e| format!("Error TOTP: {:?}", e))?;

    totp.generate_current()
        .map_err(|e| format!("Error code totp: {:?}", e))
}

#[allow(dead_code)]
pub fn validate_totp_code(
    user_code: &str,
    secret_base32: &str,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    tolerance: i64,
) -> Result<bool, String> {
    let totp = TOTP::new(
        algorithm,
        digits.try_into().unwrap(),
        0,
        period,
        secret_base32.as_bytes().to_vec(),
    )
    .map_err(|e| format!("TOTP creation error: {:?}", e))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Time error: {:?}", e))?
        .as_secs() as i64;

    for offset in -tolerance..=tolerance {
        let time = (now + offset * period as i64) as u64;

        let code = totp.generate(time);
        if code == user_code {
            return Ok(true);
        }
    }

    Ok(false)
}
