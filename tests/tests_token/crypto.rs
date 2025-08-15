use base64::Engine;
use proxyauth::token::crypto::decrypt_base64;
use proxyauth::token::crypto::encrypt_base64;
use proxyauth::token::crypto::decrypt;
use proxyauth::token::crypto::derive_key_from_secret;
use proxyauth::token::crypto::calcul_cipher;
use proxyauth::token::crypto::calcul_factorhash;
use proxyauth::token::crypto::encrypt;
use proxyauth::token::crypto::process_string;
use proxyauth::token::crypto::split_hash;


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
        let mut ks1 = proxyauth::token::crypto::Blake3Keystream::new(42);
        let mut ks2 = proxyauth::token::crypto::Blake3Keystream::new(42);
        for _ in 0..128 {
            assert_eq!(ks1.next_u8(), ks2.next_u8());
        }
        let mut ks3 = proxyauth::token::crypto::Blake3Keystream::new(43);
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
        assert_eq!(bin[0], proxyauth::token::crypto::TAG_V1_PW);
    }

    #[test]
    #[should_panic]
    fn decrypt_base64_panics_on_wrong_password() {
        let ok = encrypt_base64("x", "pw-ok");
        let _ = decrypt_base64(&ok, "pw-bad");
    }
}

