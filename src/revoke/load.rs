use lmdb::{Environment, Cursor, Transaction};
use std::path::Path;
use std::sync::Arc;
use std::sync::RwLock;
use std::collections::HashMap;
use std::time::Duration;
use std::time::SystemTime;
use lmdb::DatabaseFlags;
use std::time::UNIX_EPOCH;

pub type RevokedTokenMap = Arc<RwLock<HashMap<String, u64>>>;

pub async fn start_revoked_token_ttl(
    revoked_tokens: RevokedTokenMap,
    every: Duration,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;

            let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

            let mut map = revoked_tokens.write().unwrap();
            let before = map.len();
            map.retain(|_, &mut exp| exp > now);
            let after = map.len();

            if before != after {
                println!("[RevokedCleaner] Purged {} expired tokens", before - after);
            }
        }
    });
}

pub fn load_revoked_tokens() -> Result<RevokedTokenMap, anyhow::Error> {
    let env = Environment::new()
    .set_max_dbs(1)
    .open(Path::new("/opt/proxyauth/db"))?;

    let db = env.create_db(Some("revoke"), DatabaseFlags::empty())?;
    let txn = env.begin_ro_txn()?;
    let mut map = HashMap::new();
    let mut cursor = txn.open_ro_cursor(db)?;

    for (key, value) in cursor.iter() {
        let token_id = match std::str::from_utf8(key) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        let exp = if value.len() == 8 {
            match value.try_into().map(u64::from_be_bytes) {
                Ok(exp) => exp,
                Err(_) => continue,
            }
        } else if value.is_empty() {
            0
        } else {
            continue;
        };

        map.insert(token_id, exp);
    }

    Ok(Arc::new(RwLock::new(map)))
}
