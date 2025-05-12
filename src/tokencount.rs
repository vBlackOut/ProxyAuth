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
}

impl CounterToken {
    pub fn new() -> Self {
        Self {
            calls: DashMap::new(),
        }
    }

    pub fn record_call(&self, user: &str, token_id: &str) {
        let user_entry = self.calls.entry(user.to_string()).or_insert_with(DashMap::new);
        user_entry
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
        self.calls
            .iter()
            .map(|user_tokens| user_tokens.value().get(token_id).map_or(0, |v| *v))
            .sum()
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
}
