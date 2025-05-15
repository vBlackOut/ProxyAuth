use dashmap::DashMap;
use rustc_hash::FxHasher;
use serde::Serialize;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

type FxDashMap<K, V> = DashMap<K, V, BuildHasherDefault<FxHasher>>;

#[derive(Debug)]
pub struct CounterToken {
    counts: FxDashMap<Arc<str>, AtomicU64>,
    key_cache: FxDashMap<(String, String), Arc<str>>, // Cache for reuse key
}

#[derive(Debug, Serialize, Clone)]
pub struct TokenUsage {
    pub token_id: String,
    pub count: u64,
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

    pub fn record_and_get(&self, user: &str, token_id: &str) -> u64 {
        let key = self.make_key(user, token_id);
        let entry = self.counts.entry(key).or_insert_with(|| AtomicU64::new(0));
        entry.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn get_count(&self, user: &str, token_id: &str) -> u64 {
        let key = self.make_key(user, token_id);
        self.counts
            .get(&key)
            .map(|entry| entry.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn get_all_tokens_json(&self) -> Vec<AllTokenUsage> {
        let mut grouped: HashMap<String, Vec<TokenUsage>, BuildHasherDefault<FxHasher>> =
            HashMap::with_hasher(BuildHasherDefault::<FxHasher>::default());

        grouped.reserve(self.counts.len() / 2);

        for entry in self.counts.iter() {
            let key = entry.key();
            if let Some((user, token_id)) = key.split_once(':') {
                let count = entry.value().load(Ordering::Relaxed);
                grouped
                    .entry(user.to_string())
                    .or_insert_with(|| Vec::with_capacity(4))
                    .push(TokenUsage {
                        token_id: token_id.to_string(),
                        count,
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
