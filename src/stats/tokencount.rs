use chrono::DateTime;
use chrono::TimeZone;
use chrono::{Duration, Utc};
use dashmap::DashMap;
use rustc_hash::FxHasher;
use serde::Serialize;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

type FxDashMap<K, V> = DashMap<K, V, BuildHasherDefault<FxHasher>>;

#[derive(Debug)]
pub struct CounterToken {
    counts: FxDashMap<Arc<str>, TokenUsage>,
    key_cache: FxDashMap<(String, String), Arc<str>>, // Cache for reuse key
}

#[derive(Debug, Serialize)]
pub struct TokenUsage {
    pub token_id: String,
    pub count: AtomicU64,
    pub delivery_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AllTokenUsage {
    pub user: String,
    pub tokens: Vec<TokenUsage>,
}

impl CounterToken {
    pub fn new() -> Self {
        Self {
            counts: FxDashMap::default(),
            key_cache: FxDashMap::default(),
        }
    }

    fn make_key(&self, user: &str, token_id: &str) -> Arc<str> {
        let key_tuple = (user.to_string(), token_id.to_string());
        self.key_cache
            .entry(key_tuple)
            .or_insert_with(|| Arc::from(format!("{}:{}", user, token_id)))
            .clone()
    }

    //     pub fn record_and_get(&self, user: &str, token_id: &str) -> u64 {
    //         let key = self.make_key(user, token_id);
    //         let entry = self.counts.entry(key).or_insert_with(|| AtomicU64::new(0));
    //         entry.fetch_add(1, Ordering::Relaxed) + 1
    //     }

    pub fn record_and_get(&self, user: &str, token_id: &str, expire_at: &str) -> u64 {
        let key = self.make_key(user, token_id);
        let now = Utc::now();

        let parsed_expire = expire_at.parse::<i64>().expect("Invalid expire_at format");

        let expire_timestamp = now + Duration::seconds(parsed_expire);

        let expire_at_datetime: DateTime<Utc> = Utc
            .timestamp_opt(expire_timestamp.timestamp(), 0)
            .single()
            .expect("timestamp is out of range");

        let usage = self
            .counts
            .entry(key.clone())
            .or_insert_with(|| TokenUsage {
                token_id: token_id.to_string(),
                count: AtomicU64::new(0),
                delivery_at: now,
                expire_at: expire_at_datetime,
            });

        usage.count.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn get_count(&self, user: &str, token_id: &str) -> u64 {
        let key = self.make_key(user, token_id);
        self.counts
            .get(&key)
            .map(|entry| entry.count.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn get_all_tokens_json(&self) -> Vec<AllTokenUsage> {
        let mut grouped: HashMap<String, Vec<TokenUsage>, BuildHasherDefault<FxHasher>> =
            HashMap::with_hasher(BuildHasherDefault::<FxHasher>::default());

        grouped.reserve(self.counts.len() / 2);

        for entry in self.counts.iter() {
            let key = entry.key();
            if let Some((user, token_id)) = key.split_once(':') {
                let usage = entry.value(); // `&TokenUsage`
                let count = entry.value().count.load(Ordering::Relaxed);
                grouped
                    .entry(user.to_string())
                    .or_insert_with(|| Vec::with_capacity(4))
                    .push(TokenUsage {
                        token_id: token_id.to_string().clone(),
                        count: count.into(),
                        delivery_at: usage.delivery_at,
                        expire_at: usage.expire_at,
                    });
            }
        }

        grouped
            .into_iter()
            .map(|(user, tokens)| AllTokenUsage { user, tokens })
            .collect()
    }

    pub fn reset_all(&self) {
        self.counts.clear();
        self.key_cache.clear();
    }
}
