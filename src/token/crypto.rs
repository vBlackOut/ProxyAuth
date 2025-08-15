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
pub const TAG_V1_PW: u8 = 0xE1;
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

pub fn split_hash(s: String, n: usize) -> Vec<String> {
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

pub struct Blake3Keystream {
    rdr: blake3::OutputReader,
}

impl Blake3Keystream {
    pub fn new(factor: u64) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"proxyauth.process_string.keystream.v1");
        h.update(&factor.to_le_bytes());
        let rdr = h.finalize_xof();
        Self { rdr }
    }
    #[inline]
    pub fn next_u8(&mut self) -> u8 {
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
