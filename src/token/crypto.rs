use crate::token::security::get_build_seed2;

use base64::{engine::general_purpose, Engine as _};
use blake3;
use chacha20poly1305::aead::{self, Aead, KeyInit, AeadCore};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use lru::LruCache;
use once_cell::sync::Lazy;
use sha2::Sha256;
use std::fmt::Write;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use rand::rngs::OsRng;
use rand::RngCore;


const KEY_LEN: usize = 32;
const TAG_V1: u8 = 1;
const TAG_V1_PW: u8 = 0xE1;
const HKDF_SALT_CONST: &[u8] = b"proxyauth.hkdf.v1";
const HKDF_INFO_DERIVE: &[u8] = b"derive_key_from_secret.v1";
const HKDF_INFO_PW: &[u8] = b"encrypt_base64.password.v1";

static DERIVED_KEYS: Lazy<Mutex<LruCache<[u8; 32], [u8; 32]>>> = Lazy::new(|| {
    let cap = NonZeroUsize::new(1024).expect("nonzero");
    Mutex::new(LruCache::new(cap))
});

pub fn derive_key_from_secret(secret: &str) -> [u8; 32] {
    let id_hash = blake3::hash(secret.as_bytes());
    let mut id = [0u8; 32];
    id.copy_from_slice(id_hash.as_bytes());

    if let Some(k) = DERIVED_KEYS.lock().unwrap().get(&id).cloned() {
        return k;
    }

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_CONST), secret.as_bytes());
    let mut okm = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO_DERIVE, &mut okm).expect("HKDF expand");

    DERIVED_KEYS.lock().unwrap().put(id, okm);

    okm
}

pub fn encrypt(cleartext: &str, key: &[u8]) -> String {
    assert_eq!(key.len(), KEY_LEN, "key must be 32 bytes");
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad: &[u8] = b"";

    let ct = cipher
    .encrypt(&nonce, aead::Payload { msg: cleartext.as_bytes(), aad })
    .expect("encryption failure!");

    let mut out = Vec::with_capacity(1 + nonce.len() + ct.len());
    out.push(TAG_V1);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    general_purpose::STANDARD.encode(out)
}

pub fn decrypt(obsf: &str, key: &[u8]) -> Result<String, ()> {
    if key.len() != KEY_LEN {
        return Err(());
    }
    let data = match general_purpose::STANDARD.decode(obsf) {
        Ok(b) => b,
        Err(_) => return Err(()),
    };
    if data.len() < 1 + 24 || data[0] != TAG_V1 {
        return Err(());
    }
    let nonce = XNonce::from_slice(&data[1..25]);
    let ct = &data[25..];

    let cipher = XChaCha20Poly1305::new(key.into());
    let aad: &[u8] = b"";
    let pt = match cipher.decrypt(nonce, aead::Payload { msg: ct, aad }) {
        Ok(p) => p,
        Err(_) => return Err(()),
    };
    String::from_utf8(pt).map_err(|_| ())
}

fn split_hash(s: String, n: usize) -> Vec<String> {
    if n == 0 {
        return vec![s];
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() + n - 1) / n);
    for chunk in bytes.chunks(n) {
        out.push(std::str::from_utf8(chunk).unwrap().to_string());
    }
    out
}

struct Blake3Keystream {
    rdr: blake3::OutputReader,
}

impl Blake3Keystream {
    fn new(factor: u64) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"proxyauth.process_string.keystream.v1");
        h.update(&factor.to_le_bytes());
        let rdr = h.finalize_xof();
        Self { rdr }
    }
    #[inline]
    fn next_u8(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.rdr.fill(&mut b);
        b[0]
    }
}

pub fn process_string(s: &str, factor: u64) -> String {
    let mut ks = Blake3Keystream::new(factor);

    let mut result = Vec::with_capacity(s.len() * 2);
    let mut number_acc = 0u64;
    let mut in_digit = false;
    let mut buf = itoa::Buffer::new();

    for &c in s.as_bytes() {
        match c {
            b'0'..=b'9' => {
                in_digit = true;
                number_acc = number_acc * 10 + (c - b'0') as u64;
            }
            b'a'..=b'z' | b'A'..=b'Z' => {
                if in_digit {
                    let computed = buf.format(number_acc ^ factor);
                    result.extend_from_slice(computed.as_bytes());
                    number_acc = 0;
                    in_digit = false;
                }
                let k = ks.next_u8();
                let rot = ((c ^ k) % 26) as u8;
                let mapped = match c {
                    b'a'..=b'z' => b'a' + ((c - b'a' + rot) % 26),
                    b'A'..=b'Z' => b'A' + ((c - b'A' + rot) % 26),
                    _ => c,
                };
                result.push(mapped);
            }
            _ => {
                if in_digit {
                    let computed = buf.format(number_acc ^ factor);
                    result.extend_from_slice(computed.as_bytes());
                    number_acc = 0;
                    in_digit = false;
                }
                result.push(c);
            }
        }
    }

    if in_digit {
        let computed = buf.format(number_acc ^ factor);
        result.extend_from_slice(computed.as_bytes());
    }

    String::from_utf8(result).expect("ASCII-only output")
}

pub fn calcul_cipher(hashdata: String) -> String {
    let factor = get_build_seed2();
    let transformed = transform_hash_parts(&hashdata, factor);
    blake3::hash(transformed.as_bytes()).to_hex().to_string()
}

pub fn calcul_factorhash(hashdata: String) -> String {
    let factor = get_build_seed2();
    transform_hash_parts(&hashdata, factor)
}

fn transform_hash_parts(input: &str, factor: u64) -> String {
    let parts = split_hash(input.to_string(), 10);
    let mut out = String::with_capacity(input.len() + input.len() / 10);
    let mut first = true;

    for part in parts {
        let encoded = process_string(&part, factor);
        if first {
            write!(out, "{}", encoded).unwrap();
            first = false;
        } else {
            write!(out, "-{}", encoded).unwrap();
        }
    }
    out
}

#[allow(dead_code)]
pub fn encrypt_base64(message: &str, password: &str) -> String {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let hk = Hkdf::<Sha256>::new(Some(&salt), password.as_bytes());
    let mut key = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO_PW, &mut key).expect("HKDF expand");

    let cipher = XChaCha20Poly1305::new((&key).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aad: &[u8] = b"pw-aead";

    let ct = cipher
    .encrypt(&nonce, aead::Payload { msg: message.as_bytes(), aad })
    .expect("encrypt");

    let mut out = Vec::with_capacity(1 + salt.len() + nonce.len() + ct.len());
    out.push(TAG_V1_PW);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);

    general_purpose::STANDARD.encode(out)
}

#[allow(dead_code)]
pub fn decrypt_base64(encoded: &str, password: &str) -> String {
    let data = general_purpose::STANDARD
    .decode(encoded.as_bytes())
    .expect("Invalid base64");

    if data.len() < 1 + 16 + 24 || data[0] != TAG_V1_PW {
        panic!("Invalid ciphertext format");
    }
    let salt = &data[1..17];
    let nonce = XNonce::from_slice(&data[17..41]);
    let ct = &data[41..];

    // dérive clé
    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut key = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO_PW, &mut key).expect("HKDF expand");

    let cipher = XChaCha20Poly1305::new((&key).into());
    let aad: &[u8] = b"pw-aead";

    let pt = cipher
    .decrypt(nonce, aead::Payload { msg: ct, aad })
    .expect("decryption/authentication failed");

    String::from_utf8(pt).expect("Invalid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose};

    // ---------------------------- derive_key ---------------------------

    #[test]
    fn derive_key_is_len_32_and_stable() {
        let k1 = derive_key_from_secret("s3cr3t");
        let k2 = derive_key_from_secret("s3cr3t");
        let k3 = derive_key_from_secret("other");
        assert_eq!(k1.len(), 32);
        assert_eq!(k1, k2);
        assert_ne!(k1, k3);
    }

    // --------------------------- split_hash ----------------------------

    #[test]
    fn split_hash_chunks_size() {
        let s = "abcdefghijklmnopqrstuvwxyz";
        let v = split_hash(s.to_string(), 5);
        assert_eq!(v, vec!["abcde","fghij","klmno","pqrst","uvwxy","z"]);
        // n=0 => no split
        let v2 = split_hash(s.to_string(), 0);
        assert_eq!(v2, vec![s.to_string()]);
    }

    // ------------------------ Blake3Keystream --------------------------

    #[test]
    fn blake3_keystream_is_deterministic_for_factor() {
        let mut ks1 = Blake3Keystream::new(42);
        let mut ks2 = Blake3Keystream::new(42);
        for _ in 0..128 {
            assert_eq!(ks1.next_u8(), ks2.next_u8());
        }
        let mut ks3 = Blake3Keystream::new(43);
        let mut diff = 0;
        for _ in 0..64 {
            if ks1.next_u8() != ks3.next_u8() { diff += 1; }
        }
        assert!(diff > 0);
    }

    // ------------------------- process_string --------------------------

    #[test]
    fn process_string_properties() {
        let s = "Abc-12__0079.z!0";
        let out_f0 = process_string(s, 0);
        let out_f5 = process_string(s, 5);

        for ch in ['-','_','_','.','!'] {
            assert!(out_f0.contains(ch));
            assert!(out_f5.contains(ch));
        }

        fn is_ascii_letter(b: u8) -> bool {
            (b'a'..=b'z').contains(&b) || (b'A'..=b'Z').contains(&b)
        }
        for b in out_f5.bytes() {
            if (b as char).is_ascii_alphabetic() {
                assert!(is_ascii_letter(b));
            }
        }

        let nums_src = vec![12u64, 79u64, 0u64];
        let nums_f0 = {
            let mut out = Vec::new();
            let mut acc: Option<u64> = None;
            for c in out_f0.bytes() {
                if (b'0'..=b'9').contains(&c) {
                    acc = Some(acc.unwrap_or(0) * 10 + (c - b'0') as u64);
                } else if let Some(n) = acc.take() {
                    out.push(n);
                }
            }
            if let Some(n) = acc { out.push(n); }
            out
        };
        let nums_f5 = {
            let mut out = Vec::new();
            let mut acc: Option<u64> = None;
            for c in out_f5.bytes() {
                if (b'0'..=b'9').contains(&c) {
                    acc = Some(acc.unwrap_or(0) * 10 + (c - b'0') as u64);
                } else if let Some(n) = acc.take() {
                    out.push(n);
                }
            }
            if let Some(n) = acc { out.push(n); }
            out
        };

        assert_eq!(nums_f0, nums_src.iter().map(|n| n ^ 0).collect::<Vec<_>>());
        assert_eq!(nums_f5, nums_src.iter().map(|n| n ^ 5).collect::<Vec<_>>());

        assert!(!out_f0.is_empty());
        assert!(!out_f5.is_empty());
    }

    // ---------------------- calcul_factorhash/cipher --------------------

    #[test]
    fn calcul_factorhash_is_deterministic_for_same_input() {
        let a = "payload-123";
        let h1 = calcul_factorhash(a.to_string());
        let h2 = calcul_factorhash(a.to_string());
        let h3 = calcul_factorhash("other".to_string());
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert!(!h1.is_empty());
    }

    #[test]
    fn calcul_cipher_is_hex_64() {
        let h = calcul_cipher("something".to_string());
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --------------------------- AEAD (key) ----------------------------

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key_from_secret("roundtrip-key");
        let pt = "hello-ⓩ-世界";
        let ct = encrypt(pt, &key);
        let back = decrypt(&ct, &key).expect("should decrypt");
        assert_eq!(back, pt);
    }

    #[test]
    fn decrypt_err_on_wrong_key_or_bad_base64() {
        let key = derive_key_from_secret("key-a");
        let pt = "data";
        let ct = encrypt(pt, &key);
        assert!(decrypt(&ct, b"123").is_err());
        assert!(decrypt("###NOTBASE64###", &key).is_err());
    }

    #[test]
    fn decrypt_err_on_bad_tag() {
        let mut bogus = vec![0x02u8];
        bogus.extend_from_slice(&[0u8; 24]);     // nonce
        bogus.extend_from_slice(&[1,2,3,4,5,6]); // "ct" fictif
        let s = general_purpose::STANDARD.encode(bogus);
        let key = derive_key_from_secret("k");
        assert!(decrypt(&s, &key).is_err());
    }

    // ----------------------- AEAD (password) ---------------------------

    #[test]
    fn encrypt_base64_decrypt_base64_roundtrip() {
        let pw = "mon-passw0rd!";
        let msg = "payload 👋";
        let enc = encrypt_base64(msg, pw);
        let dec = decrypt_base64(&enc, pw);
        assert_eq!(dec, msg);

        let bin = general_purpose::STANDARD.decode(enc).unwrap();
        assert!(bin.len() >= 1 + 16 + 24 + 1);
        assert_eq!(bin[0], super::TAG_V1_PW);
    }

    #[test]
    #[should_panic]
    fn decrypt_base64_panics_on_wrong_password() {
        let ok = encrypt_base64("x", "pw-ok");
        let _ = decrypt_base64(&ok, "pw-bad");
    }
}

