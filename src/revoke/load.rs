use crate::revoke::db::{LMDB_ENV, REDIS, RevokedTokenMap};
use anyhow::Result;
use lmdb::{Transaction, WriteFlags};
use redis::Commands;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn is_token_revoked(token_id: &str, revoked_tokens: &RevokedTokenMap) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    match revoked_tokens.get(token_id) {
        Some(exp) if *exp == 0 || *exp <= now => true,
        _ => false,
    }
}

pub async fn revoke_token(
    token_id: &str,
    token_exp: Option<u64>,
    revoked_tokens: &RevokedTokenMap,
) -> Result<()> {
    let value = token_exp.unwrap_or(0);

    // Update RAM
    revoked_tokens.insert(token_id.to_string(), value);

    // Update Redis
    if let Some(client) = REDIS.get() {
        let mut con = client.get_connection()?;
        let _: () = con.set(format!("token:{}", token_id), value)?;
        let _: () = con.set(format!("{}_action", token_id), 1)?; // 1 = Add
        let _: () = con.incr(format!("{}_count", token_id), 1)?;
        return Ok(());
    }

    // Update LMDB
    if let Some(env) = LMDB_ENV.get() {
        let db = env.open_db(Some("revoke"))?;
        let mut txn = env.begin_rw_txn()?;
        let key = token_id.as_bytes();

        let bytes = if value == 0 {
            &[][..]
        } else {
            &value.to_be_bytes()[..]
        };

        txn.put(db, &key, &bytes, WriteFlags::empty())?;
        txn.commit()?;

        return Ok(());
    }

    Err(anyhow::anyhow!("No Redis or LMDB backend configured"))
}
