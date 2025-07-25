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
    let env = Environment::new()
    .set_max_dbs(1)
    .set_map_size(1048576000)
    .open(Path::new("/opt/proxyauth/db"))
    .map_err(|e| anyhow::anyhow!("Failed to open LMDB environment at {}: {}", db_path, e))
    .expect("Failed to open LMDB environment");

    let db = env
    .create_db(Some("revoke"), DatabaseFlags::empty())
    .map_err(|e| anyhow::anyhow!("Failed to create LMDB database: {}", e))
    .expect("Failed to create LMDB database");

    tokio::spawn(async move {
        loop {
            match load_revoked_tokens_from_db(&env, db) {
                Ok((new_map, db_count)) => {
                    let mut map = revoked_tokens.write().unwrap();
                    let ram_count = map.len();

                    if ram_count != db_count {
                        let before = ram_count;
                        *map = new_map;
                        let after = map.len();
                        println!(
                            "[RevokedCleaner] Synchronized token map",
                        );
                    } else {
                        println!("[RevokedCleaner] No synchronization needed",);
                    }

                    // Nettoyer les jetons expirés
                    let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                    let before = map.len();
                    map.retain(|_, &mut exp| exp > now);
                    let after = map.len();

                    if before != after {
                        println!("[RevokedCleaner] Purged {} expired tokens", before - after);
                    }
                }
                Err(e) => {
                    eprintln!("[RevokedCleaner] Failed to load tokens from database: {}", e);
                }
            }

            tokio::time::sleep(every).await;
        }
    });
}

fn load_revoked_tokens_from_db(
    env: &Environment,
    db: lmdb::Database,
) -> Result<(HashMap<String, u64>, usize), anyhow::Error> {
    let txn = env.begin_ro_txn()?;
    let mut map = HashMap::new();
    let mut cursor = txn.open_ro_cursor(db)?;
    let mut count = 0;

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
        count += 1;
    }

    Ok((map, count))
}

pub fn load_revoked_tokens() -> Result<RevokedTokenMap, anyhow::Error> {
    if !Path::new(db_path).exists() {
        std::fs::create_dir_all("/opt/proxyauth/db")
        .map_err(|e| anyhow::anyhow!("Failed to create directory {}: {}", db_path, e))?;
    }

    let env = Environment::new()
    .set_max_dbs(1)
    .set_map_size(1048576000)
    .open(Path::new(db_path))
    .map_err(|e| anyhow::anyhow!("Failed to open LMDB environment at {}: {}", db_path, e))?;

    let db = env
    .create_db(Some("revoke"), DatabaseFlags::empty())
    .map_err(|e| anyhow::anyhow!("Failed to create LMDB database: {}", e))?;

    let (map, _) = load_revoked_tokens_from_db(&env, db)?;
    Ok(Arc::new(RwLock::new(map)))
}
