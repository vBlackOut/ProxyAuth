use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::aead::generic_array::typenum::Unsigned;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, ChaCha20Poly1305,
};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::error::Error;

pub fn derive_key_from_secret(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
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

fn process_string(s: &str, factor: u64) -> String {
    let mut result = String::new();
    let limited_factor = factor % 26;

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            let new_char = if c.is_lowercase() {
                let base = 'a' as u8;
                let new_pos = (c as u8 - base + limited_factor as u8) % 26 + base;
                new_pos as char
            } else {
                let base = 'A' as u8;
                let new_pos = (c as u8 - base + limited_factor as u8) % 26 + base;
                new_pos as char
            };
            result.push(new_char);
        } else {
            result.push(c);
        }
    }

    let mut final_result = String::new();
    let mut current_number = String::new();

    for c in result.chars() {
        if c.is_ascii_digit() {
            current_number.push(c); // Accumuler les chiffres
        } else {
            if !current_number.is_empty() {
                let num: u64 = current_number.parse().unwrap_or(0);
                let transformed = num * factor;
                final_result.push_str(&transformed.to_string());
                current_number.clear();
            }
            final_result.push(c);
        }
    }

    if !current_number.is_empty() {
        let num: u64 = current_number.parse().unwrap_or(0);
        let transformed = num * factor;
        final_result.push_str(&transformed.to_string());
    }

    final_result
}

fn revert_string(s: &str, factor: u64) -> String {
    let mut result = String::new();
    let limited_factor = factor % 26; // Limiter le facteur au modulo 26 pour l'alphabet

    for c in s.chars() {
        if c.is_ascii_alphabetic() {
            let new_char = if c.is_lowercase() {
                let base = 'a' as u8;
                let new_pos = (c as u8 - base + (26 - limited_factor as u8) % 26) % 26 + base;
                new_pos as char
            } else {
                let base = 'A' as u8;
                let new_pos = (c as u8 - base + (26 - limited_factor as u8) % 26) % 26 + base;
                new_pos as char
            };
            result.push(new_char);
        } else {
            result.push(c);
        }
    }

    let mut final_result = String::new();
    let mut current_number = String::new();

    for c in result.chars() {
        if c.is_ascii_digit() {
            current_number.push(c);
        } else {
            if !current_number.is_empty() {
                let num: u64 = current_number.parse().unwrap_or(0);
                if num >= factor {
                    let original = num / factor;
                    final_result.push_str(&original.to_string());
                } else {
                    final_result.push_str(&current_number);
                }
                current_number.clear();
            }
            final_result.push(c);
        }
    }

    if !current_number.is_empty() {
        let num: u64 = current_number.parse().unwrap_or(0);
        if num >= factor {
            let original = num / factor;
            final_result.push_str(&original.to_string());
        } else {
            final_result.push_str(&current_number);
        }
    }

    final_result
}

pub fn calcul_cipher(hashdata: String) -> String {
    let hash_split = split_hash(hashdata, 10);
    let mut rng = rand::thread_rng();
    let factor = rng.gen_range(10..99);

    let mut hash_cypher = "".to_string();
    let totalhash_iter = hash_split.iter().count();

    for (i, hash) in hash_split.iter().enumerate() {
        let transformed = process_string(hash, factor);
        let _reverted = revert_string(&transformed, factor);
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

#[allow(dead_code)]
pub fn calcul_cipherfromfactor(hashdata: String, factor: i64) -> String {

    let hash_split = split_hash(hashdata, 10);

    if factor < 10 && factor > 99 {
        return format!("");
    }

    let mut hash_cypher = "".to_string();
    let totalhash_iter = hash_split.iter().count();

    for (i, hash) in hash_split.iter().enumerate() {
        let transformed = process_string(hash, factor.try_into().unwrap());
        let _reverted = revert_string(&transformed, factor.try_into().unwrap());
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
    let hash_split = split_hash(hashdata, 10);

    if factor < 10 && factor > 99 {
        return format!("");
    }

    let mut hash_cypher = "".to_string();
    let totalhash_iter = hash_split.iter().count();

    for (i, hash) in hash_split.iter().enumerate() {
        let transformed = process_string(hash, factor.try_into().unwrap());
        let _reverted = revert_string(&transformed, factor.try_into().unwrap());
        if i == totalhash_iter - 1 {
            hash_cypher += &format!("-{}::{}", &transformed, factor).to_string();
        } else if i >= 1 {
            hash_cypher += &format!("-{}", &transformed).to_string();
        } else {
            hash_cypher += &format!("{}", &transformed).to_string();
        }
    }

    hash_cypher
}

#[allow(dead_code)]
pub fn transform_ciphertohash(hashdata: &str) -> Result<String, Box<dyn Error>> {
    if !hashdata.contains("::") {
        return Err("bad token defined".into());
    }

    let mut token = "".to_string();

    let parts: Vec<&str> = hashdata.split("::").collect();
    if parts.len() != 2 {
        return Err("bad token structure".into());
    }

    let hashes_part = parts[0];
    let factor = parts[1].parse::<i64>()?;

    for hash in hashes_part.split('-') {
        token += &revert_string(hash, factor.try_into().unwrap());
    }

    Ok("valid hash".to_string())
}
