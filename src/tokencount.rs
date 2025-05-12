use serde::Serialize;
use std::collections::HashMap;

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
    calls: HashMap<String, HashMap<String, usize>>,
}

impl CounterToken {
    pub fn new() -> Self {
        Self {
            calls: HashMap::new(),
        }
    }

    pub fn record_call<S: Into<String>>(&mut self, user: S, token_id: S) {
        let user = user.into();
        let token_id = token_id.into();
        let user_entry = self.calls.entry(user).or_insert_with(HashMap::new);
        *user_entry.entry(token_id).or_insert(0) += 1;
    }

    pub fn get_count_user<S: AsRef<str>>(&self, user: S) -> usize {
        self.calls
            .get(user.as_ref())
            .map(|tokens| tokens.values().sum())
            .unwrap_or(0)
    }

    pub fn get_token_count<S: AsRef<str>>(&self, token_id: S) -> usize {
        let token_id = token_id.as_ref();
        self.calls
            .values()
            .map(|tokens| tokens.get(token_id).unwrap_or(&0))
            .sum()
    }

    pub fn show_user<S: AsRef<str>>(&self, user: S) -> Vec<(String, usize)> {
        self.calls
            .get(user.as_ref())
            .map(|tokens| {
                tokens
                    .iter()
                    .map(|(token_id, count)| (token_id.clone(), *count))
                    .collect()
            })
            .unwrap_or_else(Vec::new)
    }

    pub fn get_all_tokens_json(&self) -> Vec<AllTokenUsage> {
        self.calls
            .iter()
            .map(|(user, tokens)| {
                let tokens: Vec<TokenUsage> = tokens
                    .iter()
                    .map(|(token, count)| TokenUsage {
                        token_id: token.clone(),
                        count: *count,
                    })
                    .collect();

                AllTokenUsage {
                    user: user.clone(),
                    tokens,
                }
            })
            .collect()
    }
}
