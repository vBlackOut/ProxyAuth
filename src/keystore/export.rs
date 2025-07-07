use crate::build::build_info;
use anyhow::Context;
use sequoia_openpgp::Result;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::*;
use sequoia_openpgp::{
    armor::{Kind as ArmorKind, Writer as ArmorWriter},
    cert::{Cert, CertBuilder},
    serialize::Serialize,
};
use std::fs::{File, create_dir_all};
use std::io::{BufWriter, Write};

pub fn export_as_file() -> Result<()> {
    let dir = std::env::current_dir()?.to_str().unwrap().to_string();
    create_dir_all(&dir)?;

    // Generate cert from Applications
    let userid = UserID::from("ProxyAuth <security@proxyauth.app>");
    let (cert, _) = CertBuilder::general_purpose([userid]).generate()?;
    let current = build_info::get();

    // Export private key
    let priv_path = format!("{}/key.asc", dir);

    let mut file = BufWriter::new(File::create(&priv_path)?);
    let mut armor = ArmorWriter::new(&mut file, ArmorKind::SecretKey)?;
    for pkt in cert.as_tsk().into_packets() {
        pkt.serialize(&mut armor)?;
    }
    armor.finalize()?;

    println!("Key export Success");

    // encrypted message
    let path_data = format!("{}/data.pgp", dir);
    let _ = encrypt(&cert, &current.to_string().as_str(), &path_data)?;

    Ok(())
}

fn encrypt(cert: &Cert, text: &str, path: &str) -> anyhow::Result<()> {
    let policy = &StandardPolicy::new();

    let recipient_key = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No suitable encryption key"))?;

    let file =
        File::create(path).with_context(|| format!("Failed to create output file: {}", path))?;
    let mut armor = ArmorWriter::new(file, ArmorKind::Message)?;

    let message = Message::new(&mut armor);

    let encryptor = Encryptor::for_recipients(message, [Recipient::from(recipient_key)]).build()?;

    // Write Text File for valide format GPG.
    let mut literal = LiteralWriter::new(encryptor).build()?;
    literal.write_all(text.as_bytes())?;
    literal.finalize()?;

    armor.finalize()?;

    Ok(())
}
