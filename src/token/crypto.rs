use crate::token::security::{get_build_rand, get_build_seed2};
use ahash::AHashMap;
use base64::{Engine as _, engine::general_purpose};
use blake3;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305,
    aead::{Aead, KeyInit, OsRng},
};
use data_encoding::BASE64;
use hmac::Mac;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::{Mutex, RwLock};

static DERIVED_KEYS: Lazy<Mutex<AHashMap<String, [u8; 32]>>> =
    Lazy::new(|| Mutex::new(AHashMap::new()));

static LETTER_CACHE: Lazy<RwLock<AHashMap<(u8, u8), char>>> =
    Lazy::new(|| RwLock::new(AHashMap::new()));
static NUMBER_CACHE: Lazy<RwLock<AHashMap<(u64, u64), String>>> =
    Lazy::new(|| RwLock::new(AHashMap::new()));

pub fn derive_key_from_secret(secret: &str) -> [u8; 32] {
    {
        let cache = DERIVED_KEYS.lock().unwrap();
        if let Some(cached) = cache.get(secret) {
            return *cached;
        }
    }

    let key_u64 = get_build_rand();
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&key_u64.to_be_bytes());

    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(secret.as_bytes());
    let hash_output = hasher.finalize();
    let derived = *hash_output.as_bytes();

    DERIVED_KEYS
        .lock()
        .unwrap()
        .insert(secret.to_string(), derived);

    derived
}

pub fn encrypt(cleartext: &str, key: &[u8]) -> String {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96 bits = 12 bytes

    let ciphertext = cipher
        .encrypt(&nonce, cleartext.as_bytes())
        .expect("encryption failure!");

    let mut output = Vec::with_capacity(nonce.len() + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    general_purpose::STANDARD.encode(output)
}

pub fn decrypt(obsf: &str, key: &[u8]) -> Result<String, ()> {
    let obsf_bytes = match general_purpose::STANDARD.decode(obsf) {
        Ok(b) => b,
        Err(_) => return Err(()),
    };

    let nonce_size = <ChaCha20Poly1305 as AeadCore>::NonceSize::to_usize();
    if obsf_bytes.len() < nonce_size {
        return Err(());
    }

    let (nonce_bytes, ciphertext) = obsf_bytes.split_at(nonce_size);

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(nonce_bytes);

    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(p) => p,
        Err(_) => return Err(()),
    };

    match String::from_utf8(plaintext) {
        Ok(s) => Ok(s),
        Err(_) => Err(()),
    }
}

fn split_hash(s: String, n: usize) -> Vec<String> {
    s.chars()
        .collect::<Vec<_>>()
        .chunks(n)
        .map(|chunk| chunk.iter().collect())
        .collect()
}

pub fn process_string(s: &str, factor: u64) -> String {
    let mut result = String::with_capacity(s.len() * 2);
    let mut number_acc = 0u64;
    let mut in_digit = false;
    let shift = (factor % 26) as u8;

    for c in s.bytes() {
        match c {
            b'0'..=b'9' => {
                in_digit = true;
                number_acc = number_acc * 10 + (c - b'0') as u64;
            }
            b'a'..=b'z' | b'A'..=b'Z' => {
                if in_digit {
                    let key = (number_acc, factor);
                    let value = {
                        let cache = NUMBER_CACHE.read().unwrap();
                        cache.get(&key).cloned()
                    }
                    .unwrap_or_else(|| {
                        let computed = (number_acc * factor).to_string();
                        NUMBER_CACHE.write().unwrap().insert(key, computed.clone());
                        computed
                    });

                    result.push_str(&value);
                    number_acc = 0;
                    in_digit = false;
                }

                let key = (c, shift);
                let shifted = {
                    let cache = LETTER_CACHE.read().unwrap();
                    cache.get(&key).copied()
                }
                .unwrap_or_else(|| {
                    let base = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                    let new_char = ((c - base + shift) % 26 + base) as char;
                    LETTER_CACHE.write().unwrap().insert(key, new_char);
                    new_char
                });

                result.push(shifted);
            }
            _ => {
                if in_digit {
                    let key = (number_acc, factor);
                    let value = {
                        let cache = NUMBER_CACHE.read().unwrap();
                        cache.get(&key).cloned()
                    }
                    .unwrap_or_else(|| {
                        let computed = (number_acc * factor).to_string();
                        NUMBER_CACHE.write().unwrap().insert(key, computed.clone());
                        computed
                    });

                    result.push_str(&value);
                    number_acc = 0;
                    in_digit = false;
                }

                result.push(c as char);
            }
        }
    }

    if in_digit {
        let key = (number_acc, factor);
        let value = {
            let cache = NUMBER_CACHE.read().unwrap();
            cache.get(&key).cloned()
        }
        .unwrap_or_else(|| {
            let computed = (number_acc * factor).to_string();
            NUMBER_CACHE.write().unwrap().insert(key, computed.clone());
            computed
        });

        result.push_str(&value);
    }

    result
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
    let mut out = String::with_capacity(parts.len() * 16); // estimation
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
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key = hasher.finalize();

    let encrypted: Vec<u8> = message
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    BASE64.encode(&encrypted)
}

#[allow(dead_code)]
pub fn decrypt_base64(encoded: &str, password: &str) -> String {
    let encrypted = BASE64.decode(encoded.as_bytes()).expect("Invalid base64");

    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let key = hasher.finalize();

    let decrypted: Vec<u8> = encrypted
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect();

    String::from_utf8(decrypted).expect("Invalid UTF-8")
}
