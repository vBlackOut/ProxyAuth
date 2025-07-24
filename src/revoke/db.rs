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
        Some(&0) => true,
        Some(&exp) if now >= exp => true,
        _ => false,
    }
}

pub fn revoke_token(
    token_id: &str,
    token_exp: Option<u64>,
    revoked_tokens: &RevokedTokenMap,
) -> anyhow::Result<()> {
    let env = Environment::new()
    .set_max_dbs(1)
    .open(Path::new("/opt/proxyauth/db"))?;

    let db = env.open_db(Some("revoke"))?;
    let mut txn = env.begin_rw_txn()?;

    let value = if let Some(exp) = token_exp {
        exp.to_be_bytes().to_vec()
    } else {
        Vec::new()
    };

    txn.put(db, &token_id, &value, WriteFlags::empty())?;
    txn.commit()?;

    let mut map = revoked_tokens.write().unwrap();
    match token_exp {
        Some(exp) => {
            map.insert(token_id.to_string(), exp);
        }
        None => {
            map.insert(token_id.to_string(), 0);
        }
    }

    Ok(())
}

