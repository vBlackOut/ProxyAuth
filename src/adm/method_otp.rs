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

fn decode_b32_nopad(s: &str) -> Result<Vec<u8>, String> {
    let norm = s.trim().replace(' ', "").to_ascii_uppercase();
    BASE32_NOPAD
    .decode(norm.as_bytes())
    .map_err(|e| format!("Base32 decode error: {e:?}"))
}

#[allow(dead_code)]
pub fn generate_totp_code(
    secret_base32: &str,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
) -> Result<String, String> {
    let secret = decode_b32_nopad(secret_base32)?;
    let totp = TOTP::new(
        algorithm,
        digits.try_into().unwrap(),
                         0,
                         period,
                         secret,
    ).map_err(|e| format!("Error TOTP: {e:?}"))?;

    totp.generate_current()
    .map_err(|e| format!("Error code totp: {e:?}"))
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
    let secret = decode_b32_nopad(secret_base32)?;
    let totp = TOTP::new(
        algorithm,
        digits.try_into().unwrap(),
                         0,
                         period,
                         secret,
    ).map_err(|e| format!("TOTP creation error: {e:?}"))?;

    let now = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map_err(|e| format!("Time error: {e:?}"))?
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

#[cfg(test)]
mod tests {
    use super::*;
    use totp_rs::Algorithm;

    fn secret_len_for(algo: Algorithm) -> usize {
        match algo {
            Algorithm::SHA1   => 20,
            Algorithm::SHA256 => 32,
            Algorithm::SHA512 => 64,
        }
    }

    fn gen_secret_for(algo: Algorithm) -> String {
        generate_base32_secret(secret_len_for(algo))
    }

    #[test]
    fn generate_totp_code_has_expected_length_and_numeric() {
        let algo = Algorithm::SHA1;
        let secret_b32 = gen_secret_for(algo);
        let digits = 6;
        let period = 30;

        let code = generate_totp_code(&secret_b32, algo, digits, period)
        .expect("TOTP generation should succeed");
        assert_eq!(code.len(), digits as usize);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn validate_totp_code_with_zero_tolerance() {
        let algo = Algorithm::SHA1;
        let secret_b32 = gen_secret_for(algo);
        let digits = 6;
        let period = 30;

        let code = generate_totp_code(&secret_b32, algo, digits, period)
        .expect("generate");
        let ok = validate_totp_code(&code, &secret_b32, algo, digits, period, 0)
        .expect("validate");
        assert!(ok);
    }

    #[test]
    fn validate_totp_code_rejects_wrong_code() {
        let algo = Algorithm::SHA1;
        let secret_b32 = gen_secret_for(algo);
        let digits = 6;
        let period = 30;

        let code = generate_totp_code(&secret_b32, algo, digits, period)
        .expect("generate");

        let mut wrong_bytes = code.into_bytes();
        let i = wrong_bytes.len() - 1;
        let last = wrong_bytes[i];
        wrong_bytes[i] = if last == b'9' { b'0' } else { last + 1 };
        let wrong = String::from_utf8(wrong_bytes).unwrap();

        let ok = validate_totp_code(&wrong, &secret_b32, algo, digits, period, 0)
        .expect("validate should run");
        assert!(!ok, "wrong code should be rejected");
    }

    #[test]
    fn generate_otpauth_uri_format_is_sane() {
        let algo = Algorithm::SHA1;
        let secret_b32 = gen_secret_for(algo);
        let uri = generate_otpauth_uri(
            "alice@example.com",
            "ProxyAuth",
            &secret_b32,
            algo,
            6,
            30,
        );

        assert!(uri.starts_with("otpauth://totp/"), "URI must start with otpauth://totp/");
        assert!(uri.contains("issuer=ProxyAuth"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("secret="));
    }

    #[test]
    fn generate_base32_secret_roundtrips() {
        let s = generate_base32_secret(20);
        let decoded = data_encoding::BASE32_NOPAD.decode(s.as_bytes())
        .expect("should decode");
        assert_eq!(decoded.len(), 20);
    }

    #[test]
    fn generate_totp_code_all_algorithms() {
        for algo in [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512] {
            let secret_b32 = gen_secret_for(algo);
            let code = generate_totp_code(&secret_b32, algo, 6, 30)
            .expect("totp");
            assert_eq!(code.len(), 6);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
