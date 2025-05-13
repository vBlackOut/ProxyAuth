use dashmap::DashMap;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct TokenUsage {
    pub token_id: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct AllTokenUsage {
    pub user: String,
    pub tokens: Vec<TokenUsage>,
}

#[derive(Debug)]
pub struct CounterToken {
    calls: DashMap<String, DashMap<String, usize>>,
    global_tokens: DashMap<String, usize>,
}

impl CounterToken {
    pub fn new() -> Self {
        Self {
            calls: DashMap::new(),
            global_tokens: DashMap::new(),
        }
    }

    pub fn record_call(&self, user: &str, token_id: &str) {
        let user_entry = self
        .calls
        .entry(user.to_string())
        .or_insert_with(DashMap::new);

        user_entry
        .entry(token_id.to_string())
        .and_modify(|e| *e += 1)
        .or_insert(1);

        self.global_tokens
        .entry(token_id.to_string())
        .and_modify(|e| *e += 1)
        .or_insert(1);
    }

    pub fn get_count_user(&self, user: &str) -> usize {
        self.calls
        .get(user)
        .map(|tokens| tokens.iter().map(|r| *r.value()).sum())
        .unwrap_or(0)
    }

    pub fn get_token_count(&self, token_id: &str) -> usize {
        self.global_tokens.get(token_id).map_or(0, |v| *v)
    }

    pub fn show_user(&self, user: &str) -> Vec<(String, usize)> {
        self.calls
        .get(user)
        .map(|tokens| {
            tokens
            .iter()
            .map(|kv| (kv.key().clone(), *kv.value()))
            .collect()
        })
        .unwrap_or_else(Vec::new)
    }

    pub fn get_all_tokens_json(&self) -> Vec<AllTokenUsage> {
        self.calls
        .iter()
        .map(|user_tokens| {
            let tokens: Vec<TokenUsage> = user_tokens
            .value()
            .iter()
            .map(|token| TokenUsage {
                token_id: token.key().clone(),
                 count: *token.value(),
            })
            .collect();

            AllTokenUsage {
                user: user_tokens.key().clone(),
             tokens,
            }
        })
        .collect()
    }

    pub fn reset_user(&self, user: &str) {
        if let Some(user_tokens) = self.calls.remove(user) {
            for token_entry in user_tokens.1.iter() {
                let token_id = token_entry.key();
                let count = *token_entry.value();
                self.global_tokens
                .entry(token_id.clone())
                .and_modify(|e| {
                    *e = e.saturating_sub(count);
                    if *e == 0 {
                        self.global_tokens.remove(token_id);
                    }
                });
            }
        }
    }

    pub fn reset_token(&self, token_id: &str) {
        self.global_tokens.remove(token_id);
        for user_tokens in self.calls.iter() {
            user_tokens.value().remove(token_id);
        }
    }

    pub fn reset_all(&self) {
        self.calls.clear();
        self.global_tokens.clear();
    }
}
