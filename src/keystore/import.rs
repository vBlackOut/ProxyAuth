use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::{BufReader, Read};
use std::collections::HashMap;
use std::sync::Arc;
use sequoia_openpgp as openpgp;
use openpgp::{
    Cert, KeyID, Result,
    parse::Parse,
    parse::stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper},
    packet::{PKESK, SKESK},
    crypto::{KeyPair, SessionKey},
    policy::{Policy, StandardPolicy},
    types::SymmetricAlgorithm,
};

pub fn decrypt_keystore(import_dir_opt: Option<&Path>) -> Result<Option<String>> {
    let import_dir: PathBuf = match import_dir_opt {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from("/etc/proxyauth/import"),
    };

    let key_path = import_dir.join("key.asc");
    let data_path = import_dir.join("data.pgp");

    if !key_path.exists() || !data_path.exists() {
        return Ok(None);
    }

    let cert = Cert::from_reader(BufReader::new(File::open(&key_path)?))?;
    let mut file = File::open(&data_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let policy = &StandardPolicy::new();
    let helper = Helper::new(policy, vec![cert.clone()]);

    let mut decryptor = DecryptorBuilder::from_bytes(&data)?
    .with_policy(policy, None, helper)?;

    let mut output = Vec::new();
    std::io::copy(&mut decryptor, &mut output)?;

    let text = String::from_utf8(output)?;
    Ok(Some(text))
}

struct Helper<'a> {
    keys: HashMap<KeyID, (Arc<Cert>, KeyPair)>,
    #[allow(dead_code)]
    policy: &'a dyn Policy,
}

impl<'a> Helper<'a> {
    pub fn new(policy: &'a dyn Policy, certs: Vec<Cert>) -> Self {
        let mut keys = HashMap::new();
        for cert in certs {
            let cert = Arc::new(cert);
            for ka in cert
                .keys()
                .unencrypted_secret()
                .with_policy(policy, None)
                .supported()
                .for_transport_encryption()
                {
                    if let Ok(pair) = ka.key().clone().into_keypair() {
                        keys.insert(ka.key().keyid(), (cert.clone(), pair));
                    }
                }
        }
        Self { keys, policy }
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<Cert>> {
        let mut recipient: Option<Cert> = None;

        for pkesk in pkesks {
            if let Some((cert, pair)) = self.keys.get_mut(&KeyID::from(pkesk.recipient())) {
                let mut keypair = pair.clone();

                if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                    if decrypt(algo, &session_key) {
                        recipient = Some(cert.as_ref().clone());
                        break;
                    }
                }
            }
        }

        Ok(recipient)
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, io::Write};
    use std::path::PathBuf;

    fn mk_tmpdir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("proxyauth-import-{}-{}", std::process::id(), tag));
        if p.exists() {
            let _ = fs::remove_dir_all(&p);
        }
        fs::create_dir_all(&p).expect("create tmpdir");
        p
    }

    // --- try depandante key -------------------------------

    #[test]
    fn returns_none_if_directory_missing() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("proxyauth-import-missing-{}", std::process::id()));

        let got = decrypt_keystore(Some(&dir)).expect("should not error");
        assert!(got.is_none());
    }

    #[test]
    fn returns_none_if_one_of_files_is_missing() {
        let d1 = mk_tmpdir("only-key");
        fs::write(d1.join("key.asc"), b"not a real key").unwrap();
        let got1 = decrypt_keystore(Some(&d1)).expect("should not error");
        assert!(got1.is_none());

        let d2 = mk_tmpdir("only-data");
        fs::write(d2.join("data.pgp"), b"not pgp data").unwrap();
        let got2 = decrypt_keystore(Some(&d2)).expect("should not error");
        assert!(got2.is_none());
    }

    #[test]
    fn returns_error_with_invalid_files() {
        let d = mk_tmpdir("invalid-both");
        fs::write(d.join("key.asc"), b"--- invalid openpgp key ---").unwrap();
        fs::write(d.join("data.pgp"), b"--- invalid pgp ciphertext ---").unwrap();

        let res = decrypt_keystore(Some(&d));
        assert!(res.is_err(), "Expected error when both files are invalid");
    }

    // --- None  -----------------

    #[test]
    fn passing_none_uses_default_path_and_returns_none_when_missing() {
        let res = decrypt_keystore(None).expect("should not error with None");
        assert!(res.is_none());
    }

    // --- empty key dependant ----------------

    #[test]
    fn helper_new_with_empty_certs_yields_empty_keymap() {
        let policy = StandardPolicy::new();
        let h = Helper::new(&policy, vec![]);

        let mut h2 = h;
        let pkesks: &[PKESK] = &[];
        let skesks: &[SKESK] = &[];
        let mut called = false;
        let mut dec = |algo: Option<SymmetricAlgorithm>, _sk: &SessionKey| {
            called = true;
            algo.is_some()
        };
        let out = DecryptionHelper::decrypt(&mut h2, pkesks, skesks, None, &mut dec)
        .expect("decrypt with empty pkesks should not fail");
        assert!(out.is_none(), "no recipient should be found");
        assert!(!called, "decrypt closure must not be called with empty pkesks");
    }

    #[test]
    fn verification_helper_get_certs_returns_empty() {
        let policy = StandardPolicy::new();
        let mut h = Helper::new(&policy, vec![]);
        let got = VerificationHelper::get_certs(&mut h, &[])
        .expect("get_certs should not fail");
        assert!(got.is_empty());
    }

    #[test]
    fn tries_to_parse_when_both_files_exist() {
        let d = mk_tmpdir("exists-both-but-invalid");
        {
            let mut f = File::create(d.join("key.asc")).unwrap();
            f.write_all(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...").unwrap();
        }
        {
            let mut f = File::create(d.join("data.pgp")).unwrap();
            f.write_all(b"\x99\x01\x02\x03notreallypgp").unwrap();
        }

        let res = decrypt_keystore(Some(&d));
        assert!(res.is_err(), "Parsing should fail with bogus contents");
    }
}

