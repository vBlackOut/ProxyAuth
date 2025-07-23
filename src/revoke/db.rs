use lmdb::{Environment, WriteFlags, Transaction};
use std::path::Path;
use crate::revoke::load::RevokedTokenMap;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub fn is_token_revoked(token_id: &str, revoked_tokens: &RevokedTokenMap) -> bool {
    let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();

    let map = revoked_tokens.read().unwrap();

    match map.get(token_id) {
        Some(&exp) if exp > now => true,
        _ => false,
    }
}

pub fn revoke_token(
    token_id: &str,
    token_exp: u64,
    revoked_tokens: &RevokedTokenMap,
) -> anyhow::Result<()> {
    let env = Environment::new()
    .set_max_dbs(1)
    .open(Path::new("/opt/proxyauth/db"))?;

    let db = env.open_db(Some("revoke"))?;
    let mut txn = env.begin_rw_txn()?;

    let exp_bytes = token_exp.to_be_bytes();
    txn.put(db, &token_id, &exp_bytes, WriteFlags::empty())?;
    txn.commit()?;

    let mut map = revoked_tokens.write().unwrap();
    map.insert(token_id.to_string(), token_exp);

    Ok(())
}

