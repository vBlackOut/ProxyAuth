use anyhow::Error;
use dashmap::DashMap;
use lmdb::{Cursor, Environment, Transaction};
use std::path::Path;
use std::sync::Arc;
use std::thread::{self, sleep};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use lmdb::WriteFlags;
use once_cell::sync::OnceCell;
use redis::{Client, Commands};

pub static REDIS: OnceCell<Client> = OnceCell::new();
pub static LMDB_ENV: OnceCell<lmdb::Environment> = OnceCell::new();

pub type RevokedTokenMap = Arc<DashMap<String, u64>>;


pub async fn start_revoked_token_ttl(
    revoked_tokens: RevokedTokenMap,
    every: Duration,
    redis_url: Option<String>,
) {
    let opt_path = Some("/opt/proxyauth/db/".to_string());

    // Init LMDB
    if let Some(path) = opt_path {
        if LMDB_ENV.get().is_none() {
            let env = Environment::new()
            .set_max_dbs(1)
            .open(Path::new(&path))
            .expect("Failed to open LMDB");
            LMDB_ENV.set(env).expect("LMDB already initialized");
        }
    }

    // Init Redis
    if let Some(url) = redis_url {
        if REDIS.get().is_none() {
            let client = Client::open(url).expect("Invalid Redis URL");
            REDIS.set(client).expect("REDIS client already initialized");
        }

        thread::spawn(move || {
            loop {
                // Redis -> LMDB + RAM
                if let Some(client) = REDIS.get() {
                    if let Ok(mut con) = client.get_connection() {
                        let action_keys: Vec<String> = match con.scan_match::<String, String>("*_action".to_string()) {
                            Ok(iter) => iter.collect::<Vec<String>>(),
                      Err(_) => Vec::new(),
                        };

                        for action_key in action_keys {
                            let token_id = action_key.trim_end_matches("_action");
                            //println!("[RevokedSync] Processing token_id: {}", token_id);

                            let action: Result<String, _> = con.get(&action_key);

                            match action.as_deref() {
                                Ok("1") => {
                                    let exp_result = con.get::<_, u64>(&format!("token:{}", token_id));
                                    let key: &[u8] = token_id.as_bytes();
                                    let value_buf;
                                    let value: &[u8] = match exp_result {
                                        Ok(exp) => {
                                            value_buf = exp.to_be_bytes();
                                            &value_buf
                                        }
                                        Err(_) => &[],
                                    };

                                    let mut should_update = true;

                                    if let Some(env) = LMDB_ENV.get() {
                                        if let Ok(db) = env.open_db(Some("revoke")) {
                                            if let Ok(txn) = env.begin_ro_txn() {
                                                if let Ok(existing) = txn.get::<&[u8]>(db, &key) {
                                                    should_update = existing != value;
                                                }
                                            }
                                        }
                                    }

                                    if should_update {
                                        if let Some(env) = LMDB_ENV.get() {
                                            if let Ok(db) = env.open_db(Some("revoke")) {
                                                if let Ok(mut txn) = env.begin_rw_txn() {
                                                    if let Err(e) = txn.put::<&[u8], &[u8]>(db, &key, &value, WriteFlags::empty()) {
                                                        eprintln!("[RevokedSync] LMDB put error for {}: {}", token_id, e);
                                                    }
                                                    let _ = txn.commit();
                                                }
                                            }
                                        }
                                    }

                                    let exp_val = match value.len() {
                                        8 => Some(u64::from_be_bytes(value.try_into().unwrap())),
                                        0 => Some(0),
                                        _ => None,
                                    };

                                    if let Some(exp) = exp_val {
                                        revoked_tokens.insert(token_id.to_string(), exp);
                                    }
                                }
                                Ok("2") => {
                                    if let Some(env) = LMDB_ENV.get() {
                                        if let Ok(db) = env.open_db(Some("revoke")) {
                                            if let Ok(mut txn) = env.begin_rw_txn() {
                                                let key = token_id.as_bytes();
                                                let _ = txn.del::<&[u8]>(db, &key, None)
                                                .map_err(|e| eprintln!("[RevokedSync] LMDB delete error for {}: {}", token_id, e));
                                                let _ = txn.commit();
                                            }
                                        }
                                    }
                                    revoked_tokens.remove(token_id);
                                }
                                other => {
                                    //println!("[RevokedSync] Unknown or missing action for {}: {:?}", token_id, other);
                                    continue;
                                }
                            }
                        }
                    }
                }

                // LMDB -> RAM
                if let Some(env) = LMDB_ENV.get() {
                    if let Ok(db) = env.open_db(Some("revoke")) {
                        if let Ok(txn) = env.begin_ro_txn() {
                            if let Ok(mut cursor) = txn.open_ro_cursor(db) {
                                for (key, value) in cursor.iter() {
                                    let token_id = match std::str::from_utf8(key) {
                                        Ok(s) => s.to_string(),
                                        Err(_) => continue,
                                    };

                                    let exp = if value.len() == 8 {
                                        match value.try_into().map(u64::from_be_bytes) {
                                            Ok(e) => e,
                                            Err(_) => continue,
                                        }
                                    } else if value.is_empty() {
                                        0
                                    } else {
                                        continue
                                    };

                                    revoked_tokens.insert(token_id, exp);
                                }
                            }
                        }
                    }
                }

                // RAM purge
                let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
                let before = revoked_tokens.len();
                revoked_tokens.retain(|_, &mut exp| exp == 0 || exp > now);
                let after = revoked_tokens.len();

                if before != after {
                    println!("[RevokedSync] Purged {} expired tokens", before - after);
                }

                sleep(every);
            }
        });
    }
}


pub fn load_revoked_tokens() -> Result<Arc<DashMap<String, u64>>, Error> {
    let map = DashMap::new();

    if let Some(env) = LMDB_ENV.get() {
        let db = env.open_db(Some("revoke"))?;
        let txn = env.begin_ro_txn()?;
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

        return Ok(Arc::new(map));
    }

    Err(anyhow::anyhow!("LMDB is not initialized"))
}

