use dashmap::DashMap;
use rustc_hash::FxHasher;
use serde::Serialize;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;
use std::sync::atomic::{AtomicU64, Ordering};

type FxDashMap<K, V> = DashMap<K, V, BuildHasherDefault<FxHasher>>;

#[derive(Debug)]
pub struct CounterToken {
    counts: FxDashMap<String, AtomicU64>,
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
        }
    }

    fn make_key(user: &str, token_id: &str) -> String {
        format!("{}:{}", user, token_id)
    }

    pub fn record_and_get(&self, user: &str, token_id: &str) -> u64 {
        let key = Self::make_key(user, token_id);
        let entry = self
            .counts
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0));
        entry.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn get_count(&self, user: &str, token_id: &str) -> u64 {
        let key = Self::make_key(user, token_id);
        self.counts
            .get(&key)
            .map(|entry| entry.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn get_all_tokens_json(&self) -> Vec<AllTokenUsage> {
        let mut grouped: HashMap<String, Vec<TokenUsage>> = HashMap::new();

        for entry in self.counts.iter() {
            let key = entry.key().clone();
            if let Some((user, token_id)) = key.split_once(':') {
                let count = entry.value().load(Ordering::Relaxed);
                grouped
                    .entry(user.to_string())
                    .or_insert_with(Vec::new)
                    .push(TokenUsage {
                        token_id: token_id.to_string(),
                        count,
                    });
            }
        }

        grouped
            .into_iter()
            .map(|(user, tokens)| AllTokenUsage {
                user: user.to_string(),
                tokens,
            })
            .collect()
    }

    pub fn reset_all(&self) {
        self.counts.clear();
    }
}
