use anyhow::Error;
use dashmap::DashMap;
use lmdb::{Cursor, Environment, Transaction, WriteFlags};
use once_cell::sync::OnceCell;
use redis::{Client, Commands};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{debug, error, info};

pub static REDIS: OnceCell<Client> = OnceCell::new();
pub static LMDB_ENV: OnceCell<lmdb::Environment> = OnceCell::new();
pub static LMDB_MUTEX: Mutex<()> = Mutex::new(());

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

    // Load tokens from LMDB at startup
    if let Ok(loaded_tokens) = load_revoked_tokens() {
        for entry in loaded_tokens.iter() {
            let (token_id, exp) = (entry.key().clone(), *entry.value());
            revoked_tokens.insert(token_id, exp);
        }
        debug!("[RevokedSync] Loaded {} tokens from LMDB at startup", loaded_tokens.len());
    } else {
        error!("[RevokedSync] Failed to load tokens from LMDB at startup");
    }

    // Init Redis with retries
    if let Some(url) = redis_url {
        if REDIS.get().is_none() {
            let mut attempts = 3;
            while attempts > 0 {
                match Client::open(url.clone()) {
                    Ok(client) => {
                        REDIS.set(client).expect("REDIS client already initialized");
                        debug!("[RevokedSync] Redis initialized successfully");
                        break;
                    }
                    Err(e) => {
                        error!("[RevokedSync] Failed to initialize Redis: {}. Retrying... ({} attempts left)", e, attempts);
                        attempts -= 1;
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
            if REDIS.get().is_none() {
                error!("[RevokedSync] Failed to initialize Redis after retries");
                // Optionally panic or handle as needed
            }
        }

        let revoked_tokens_clone = revoked_tokens.clone();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        // Handle SIGTERM and SIGINT for graceful shutdown
        tokio::spawn(async move {
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to listen for SIGTERM");
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to listen for SIGINT");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("[RevokedSync] Received SIGTERM, initiating shutdown");
                }
                _ = sigint.recv() => {
                    info!("[RevokedSync] Received SIGINT, initiating shutdown");
                }
            }

            // Signal shutdown
            shutdown_tx.send(true).expect("Failed to send shutdown signal");
        });

        tokio::spawn(async move {
            let mut interval = time::interval(every);
            debug!("[RevokedSync] Starting sync loop with interval {:?}", every);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        debug!("[RevokedSync] Fetched tokens from Redis");

                        if let Some(client) = REDIS.get() {
                            let mut con = match client.get_connection_with_timeout(Duration::from_secs(5)) {
                                Ok(con) => con,
                                Err(e) => {
                                    error!("[RevokedSync] Failed to get Redis connection: {}. Retrying next tick.", e);
                                    continue;
                                }
                            };

                            let action_keys: Vec<String> = match con.scan_match::<String, String>("*_action".to_string()) {
                                Ok(iter) => iter.collect::<Vec<String>>(),
                                Err(e) => {
                                    error!("[RevokedSync] Failed to scan Redis: {}", e);
                                    Vec::new()
                                }
                            };

                            for action_key in action_keys {
                                let token_id = action_key.trim_end_matches("_action");
                                debug!("[RevokedSync] Processing action_key: {}", action_key);

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

                                        let _guard = LMDB_MUTEX.lock().unwrap();
                                        if let Some(env) = LMDB_ENV.get() {
                                            if let Ok(db) = env.open_db(Some("revoke")) {
                                                debug!("[LMDB] Starting read transaction for {}", token_id);
                                                if let Ok(txn) = env.begin_ro_txn() {
                                                    if let Ok(existing) = txn.get::<&[u8]>(db, &key) {
                                                        should_update = existing != value;
                                                    }
                                                    info!("[LMDB] Read transaction completed for {}", token_id);
                                                }
                                            }
                                        }

                                        if should_update {
                                            if let Some(env) = LMDB_ENV.get() {
                                                if let Ok(db) = env.open_db(Some("revoke")) {
                                                    debug!("[LMDB] Starting write transaction for {}", token_id);
                                                    if let Ok(mut txn) = env.begin_rw_txn() {
                                                        if let Err(e) = txn.put::<&[u8], &[u8]>(db, &key, &value, WriteFlags::empty()) {
                                                            error!("[RevokedSync] LMDB put error for {}: {}", token_id, e);
                                                        }
                                                        let _ = txn.commit();
                                                        info!("[LMDB] Write transaction committed for {}", token_id);
                                                    }
                                                }
                                            }
                                        }
                                        drop(_guard); // Relâcher le mutex

                                        let exp_val = match value.len() {
                                            8 => Some(u64::from_be_bytes(value.try_into().unwrap())),
                                            0 => Some(0),
                                            _ => None,
                                        };

                                        if let Some(exp) = exp_val {
                                            revoked_tokens_clone.insert(token_id.to_string(), exp);
                                        }
                                    }
                                    Ok("2") => {
                                        let _guard = LMDB_MUTEX.lock().unwrap();
                                        if let Some(env) = LMDB_ENV.get() {
                                            if let Ok(db) = env.open_db(Some("revoke")) {
                                                debug!("[LMDB] Starting delete transaction for {}", token_id);
                                                if let Ok(mut txn) = env.begin_rw_txn() {
                                                    let key = token_id.as_bytes();
                                                    let _ = txn.del::<&[u8]>(db, &key, None)
                                                    .map_err(|e| error!("[RevokedSync] LMDB delete error for {}: {}", token_id, e));
                                                    let _ = txn.commit();
                                                    info!("[LMDB] Delete transaction committed for {}", token_id);
                                                }
                                            }
                                        }
                                        drop(_guard);
                                        revoked_tokens_clone.remove(token_id);
                                    }
                                    _ => continue,
                                }
                            }
                        }

                        // LMDB -> RAM
                        let _guard = LMDB_MUTEX.lock().unwrap();
                        if let Some(env) = LMDB_ENV.get() {
                            if let Ok(db) = env.open_db(Some("revoke")) {
                                if let Ok(txn) = env.begin_ro_txn() {
                                    debug!("[LMDB] Starting cursor iteration");
                                    if let Ok(mut cursor) = txn.open_ro_cursor(db) {
                                        for result in cursor.iter() {
                                            let (key, value) = match result {
                                                Ok((key, value)) => (key, value),
                                                Err(_) => continue,
                                            };

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
                                                continue;
                                            };

                                            revoked_tokens_clone.insert(token_id, exp);
                                        }
                                        info!("[LMDB] Cursor iteration completed");
                                    }
                                }
                            }
                        }
                        drop(_guard); // Relâcher le mutex

                        // RAM purge and sync with LMDB
                        let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                        let before = revoked_tokens_clone.len();
                        let _guard = LMDB_MUTEX.lock().unwrap(); // Sérialiser l'accès LMDB
                        revoked_tokens_clone.retain(|token_id, &mut exp| {
                            let keep = exp == 0 || exp > now;
                            if !keep {
                                if let Some(env) = LMDB_ENV.get() {
                                    if let Ok(db) = env.open_db(Some("revoke")) {
                                        debug!("[LMDB] Starting delete transaction for expired token {}", token_id);
                                        if let Ok(mut txn) = env.begin_rw_txn() {
                                            let key = token_id.as_bytes();
                                            if let Err(e) = txn.del::<&[u8]>(db, &key, None) {
                                                error!("[RevokedSync] LMDB delete error for expired token {}: {}", token_id, e);
                                            }
                                            let _ = txn.commit();
                                            info!("[LMDB] Delete transaction committed for expired token {}", token_id);
                                        }
                                    }
                                }
                            }
                            keep
                        });
                        drop(_guard); // Relâcher le mutex
                        let after = revoked_tokens_clone.len();

                        if before != after {
                            debug!("[RevokedSync] Purged {} expired tokens", before - after);
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            info!("[RevokedSync] Shutting down token sync loop");
                            break;
                        }
                    }
                }
            }

            // Cleanup on shutdown
            info!("[RevokedSync] Cleaning up resources");
            let _guard = LMDB_MUTEX.lock().unwrap();
            if let Some(env) = LMDB_ENV.get() {
                if let Err(e) = env.sync(true) {
                    error!("[RevokedSync] Failed to sync LMDB on shutdown: {}", e);
                } else {
                    info!("[RevokedSync] LMDB synced successfully");
                }
            }
            drop(_guard);
        });
    }
}

pub fn load_revoked_tokens() -> Result<Arc<DashMap<String, u64>>, Error> {
    let map = DashMap::new();

    let _guard = LMDB_MUTEX.lock().unwrap();
    if let Some(env) = LMDB_ENV.get() {
        let db = env.open_db(Some("revoke"))?;
        let txn = env.begin_ro_txn()?;
        debug!("[LMDB] Starting cursor iteration for load_revoked_tokens");
        let mut cursor = txn.open_ro_cursor(db)?;

        for result in cursor.iter() {
            let (key, value) = match result {
                Ok((key, value)) => (key, value),
                Err(e) => {
                    error!("[LMDB] Error while iterating LMDB: {}", e);
                    continue;
                }
            };

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
        info!("[LMDB] Cursor iteration completed for load_revoked_tokens");
        return Ok(Arc::new(map));
    }
    drop(_guard);

    Err(anyhow::anyhow!("LMDB is not initialized"))
}
