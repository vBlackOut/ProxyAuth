use rand::{rngs::OsRng, RngCore};
use data_encoding::BASE32_NOPAD;
use totp_rs::{Algorithm, TOTP};
use urlencoding::encode;

pub fn generate_base32_secret(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}

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

pub fn generate_totp_code(
    secret_base32: &str,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
) -> Result<String, String> {
    let totp = TOTP::new(algorithm, digits.try_into().unwrap(), 0, period, secret_base32.as_bytes().to_vec())
    .map_err(|e| format!("Erreur TOTP: {:?}", e))?;

    totp.generate_current()
    .map_err(|e| format!("Erreur génération code: {:?}", e))
}
