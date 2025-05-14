use dashmap::DashMap;
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct CounterToken {
    counts: DashMap<String, AtomicUsize>, // Key: "user:token_id"
}

#[derive(Debug, Serialize, Clone)]
pub struct TokenUsage {
    pub token_id: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct AllTokenUsage {
    pub user: String,
    pub tokens: Vec<TokenUsage>,
}

impl CounterToken {
    pub fn new() -> Self {
        Self {
            counts: DashMap::new(),
        }
    }

    fn make_key(user: &str, token_id: &str) -> String {
        format!("{}:{}", user, token_id)
    }

    pub fn record_and_get(&self, user: &str, token_id: &str) -> usize {
        let key = Self::make_key(user, token_id);
        let entry = self
            .counts
            .entry(key)
            .or_insert_with(|| AtomicUsize::new(0));
        entry.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn get_count(&self, user: &str, token_id: &str) -> usize {
        let key = Self::make_key(user, token_id);
        self.counts
            .get(&key)
            .map(|entry| entry.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn get_all_tokens_json(&self) -> Vec<AllTokenUsage> {
        let mut grouped: std::collections::HashMap<String, Vec<TokenUsage>> =
            std::collections::HashMap::new();

        for entry in self.counts.iter() {
            let key = entry.key();
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() != 2 {
                continue; // Skip malformed keys
            }
            let (user, token_id) = (parts[0], parts[1]);
            let count = entry.value().load(Ordering::Relaxed);

            grouped
                .entry(user.to_string())
                .or_insert_with(Vec::new)
                .push(TokenUsage {
                    token_id: token_id.to_string(),
                    count,
                });
        }

        grouped
            .into_iter()
            .map(|(user, tokens)| AllTokenUsage { user, tokens })
            .collect()
    }

    /// Resets all counters
    pub fn reset_all(&self) {
        self.counts.clear();
    }
}
