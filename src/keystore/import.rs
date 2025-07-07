use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;

use openpgp::crypto::{KeyPair, SessionKey};
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::Parse;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper,
};
use openpgp::policy::{Policy, StandardPolicy};
use openpgp::types::SymmetricAlgorithm;
use openpgp::{Cert, KeyHandle, KeyID, Result};
use sequoia_openpgp as openpgp;

pub fn decrypt_keystore() -> Result<Option<String>> {
    let import_dir = "/etc/proxyauth/import";
    let key_path = Path::new(import_dir).join("key.asc");
    let data_path = Path::new(import_dir).join("data.pgp");

    if !key_path.exists() || !data_path.exists() {
        return Ok(None);
    }

    let cert = Cert::from_reader(BufReader::new(File::open(&key_path)?))?;
    let mut file = File::open(&data_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let policy = &StandardPolicy::new();
    let helper = Helper::new(policy, vec![cert.clone()]);

    let mut decryptor = DecryptorBuilder::from_bytes(&data)?.with_policy(policy, None, helper)?;

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
    fn get_certs(&mut self, _ids: &[KeyHandle]) -> Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}
