use crate::token::security::get_build_rand;
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::{
    AeadCore, ChaCha20Poly1305,
    aead::{Aead, KeyInit, OsRng},
};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::fmt::Write;

type HmacSha256 = Hmac<Sha256>;

pub fn derive_key_from_secret(secret: &str) -> [u8; 32] {
    let key_u64 = get_build_rand();
    let key = key_u64.to_be_bytes();

    let mut mac = <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&key)
        .expect("HMAC can take key of any size");

    mac.update(secret.as_bytes());
    let result = mac.finalize().into_bytes();

    let mut derived_key = [0u8; 32];
    derived_key.copy_from_slice(&result[..]);
    derived_key
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
    let limited_factor = (factor % 26) as u8;

    let mut number_acc = 0u64;
    let mut has_digits = false;

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            if has_digits {
                write!(result, "{}", number_acc * factor).unwrap();
                number_acc = 0;
                has_digits = false;
            }

            let (_base, new_char) = if c.is_ascii_lowercase() {
                let base = b'a';
                let new_pos = (c as u8 - base + limited_factor) % 26 + base;
                (base, new_pos as char)
            } else {
                let base = b'A';
                let new_pos = (c as u8 - base + limited_factor) % 26 + base;
                (base, new_pos as char)
            };
            result.push(new_char);
        } else if c.is_ascii_digit() {
            has_digits = true;
            number_acc = number_acc * 10 + (c as u64 - b'0' as u64);
        } else {
            if has_digits {
                write!(result, "{}", number_acc * factor).unwrap();
                number_acc = 0;
                has_digits = false;
            }
            result.push(c);
        }
    }

    if has_digits {
        write!(result, "{}", number_acc * factor).unwrap();
    }

    result
}

pub fn calcul_cipher(hashdata: String) -> String {
    let hash_split = split_hash(hashdata, 10);
    let mut rng = rand::thread_rng();
    let factor = rng.gen_range(10..99);

    let mut hash_cypher = "".to_string();
    let totalhash_iter = hash_split.iter().count();

    for (i, hash) in hash_split.iter().enumerate() {
        let transformed = process_string(hash, factor);

        if i == totalhash_iter - 1 {
            hash_cypher += &format!("-{}::{}", &transformed, factor).to_string();
        } else if i >= 1 {
            hash_cypher += &format!("-{}", &transformed).to_string();
        } else {
            hash_cypher += &format!("{}", &transformed).to_string();
        }
    }

    let mut hashed = Sha256::new();
    hashed.update(hash_cypher.as_bytes());

    format!("{:x}={}", hashed.finalize(), factor)
}

pub fn calcul_factorhash(hashdata: String, factor: i64) -> String {
    if !(10..=99).contains(&factor) {
        return String::new();
    }

    let hash_split = split_hash(hashdata, 10);

    let mut hash_cypher = String::with_capacity(hash_split.len() * 16);
    let factor: u32 = factor as u32;

    for (i, hash) in hash_split.iter().enumerate() {
        let transformed = process_string(hash, factor.into());
        if i == 0 {
            write!(hash_cypher, "{}", transformed).unwrap();
        } else if i == hash_split.len() - 1 {
            write!(hash_cypher, "-{}::{}", transformed, factor).unwrap();
        } else {
            write!(hash_cypher, "-{}", transformed).unwrap();
        }
    }

    hash_cypher
}
