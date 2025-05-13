use dashmap::DashMap;
use serde::Serialize;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub struct CounterToken {
    // clé = (username, token_id), valeur = compteur
    counts: DashMap<(String, String), AtomicUsize>,
}

#[derive(Debug, Serialize, Clone)] // Clone est requis pour le JSON
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

    /// Incrémente et retourne le compteur — O(1)
    pub fn record_and_get(&self, user: &str, token_id: &str) -> usize {
        let entry = self
        .counts
        .entry((user.to_string(), token_id.to_string()))
        .or_insert_with(|| AtomicUsize::new(0));

        entry.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Total des appels pour un utilisateur
    pub fn get_count_user(&self, user: &str) -> usize {
        self.counts
        .iter()
        .filter(|entry| entry.key().0 == user)
        .map(|entry| entry.value().load(Ordering::Relaxed))
        .sum()
    }

    /// Total des appels pour un token
    pub fn get_token_count(&self, token_id: &str) -> usize {
        self.counts
        .iter()
        .filter(|entry| entry.key().1 == token_id)
        .map(|entry| entry.value().load(Ordering::Relaxed))
        .sum()
    }

    /// Détail des tokens pour un utilisateur
    pub fn show_user(&self, user: &str) -> Vec<(String, usize)> {
        self.counts
        .iter()
        .filter(|entry| entry.key().0 == user)
        .map(|entry| (entry.key().1.clone(), entry.value().load(Ordering::Relaxed)))
        .collect()
    }

    /// Format JSON pour toutes les stats
    pub fn get_all_tokens_json(&self) -> Vec<AllTokenUsage> {
        let mut grouped: DashMap<String, Vec<TokenUsage>> = DashMap::new();

        for entry in self.counts.iter() {
            let (user, token_id) = entry.key();
            let count = entry.value().load(Ordering::Relaxed);

            grouped
            .entry(user.clone())
            .or_insert_with(Vec::new)
            .push(TokenUsage {
                token_id: token_id.clone(),
                  count,
            });
        }

        grouped
        .iter()
        .map(|entry| AllTokenUsage {
            user: entry.key().clone(),
             tokens: entry.value().clone(),
        })
        .collect()
    }

    /// Supprimer tous les tokens d'un utilisateur
    pub fn reset_user(&self, user: &str) {
        let keys_to_remove: Vec<_> = self
        .counts
        .iter()
        .filter(|entry| entry.key().0 == user)
        .map(|entry| entry.key().clone())
        .collect();

        for key in keys_to_remove {
            self.counts.remove(&key);
        }
    }

    /// Supprimer un token spécifique (tous utilisateurs)
    pub fn reset_token(&self, token_id: &str) {
        let keys_to_remove: Vec<_> = self
        .counts
        .iter()
        .filter(|entry| entry.key().1 == token_id)
        .map(|entry| entry.key().clone())
        .collect();

        for key in keys_to_remove {
            self.counts.remove(&key);
        }
    }

    /// Réinitialiser tous les compteurs
    pub fn reset_all(&self) {
        self.counts.clear();
    }
}
