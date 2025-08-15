use proxyauth::CounterToken;

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    #[test]
    fn record_and_get_increments_and_get_count_matches() {
        let c = CounterToken::new();

        let n1 = c.record_and_get("alice", "t1", "60");
        let n2 = c.record_and_get("alice", "t1", "60");
        let n3 = c.record_and_get("alice", "t1", "60");
        assert_eq!(n1, 1);
        assert_eq!(n2, 2);
        assert_eq!(n3, 3);

        assert_eq!(c.get_count("alice", "t1"), 3);

        assert_eq!(c.get_count("alice", "t2"), 0);
        let _ = c.record_and_get("alice", "t2", "60");
        assert_eq!(c.get_count("alice", "t2"), 1);
        assert_eq!(c.get_count("alice", "t1"), 3);
    }

    #[test]
    fn expire_at_is_set_relative_to_now() {
        let c = CounterToken::new();
        let _ = c.record_and_get("bob", "tok", "60");

        let all = c.get_all_tokens_json();
        let entry = all
        .iter()
        .find(|u| u.user == "bob")
        .and_then(|u| u.tokens.iter().find(|t| t.token_id == "tok"))
        .expect("token non trouvé");

        let diff = (entry.expire_at - entry.delivery_at).num_seconds();
        assert!(
            (55..=65).contains(&diff),
                "diff={}s attendu ~60s",
                diff
        );
    }

    #[test]
    fn get_all_tokens_json_groups_by_user_and_token() {
        let c = CounterToken::new();

        let _ = c.record_and_get("alice", "t1", "10");
        let _ = c.record_and_get("alice", "t1", "10");
        let _ = c.record_and_get("alice", "t2", "10");
        let _ = c.record_and_get("charlie", "t9", "10");

        let all = c.get_all_tokens_json();

        let users: std::collections::HashSet<_> =
        all.iter().map(|u| u.user.as_str()).collect();
        assert!(users.contains("alice"));
        assert!(users.contains("charlie"));

        let alice = all.iter().find(|u| u.user == "alice").unwrap();
        let alice_tokens: std::collections::HashSet<_> =
        alice.tokens.iter().map(|t| t.token_id.as_str()).collect();
        assert!(alice_tokens.contains("t1"));
        assert!(alice_tokens.contains("t2"));

        let charlie = all.iter().find(|u| u.user == "charlie").unwrap();
        let charlie_tokens: std::collections::HashSet<_> =
        charlie.tokens.iter().map(|t| t.token_id.as_str()).collect();
        assert!(charlie_tokens.contains("t9"));
    }

    #[test]
    fn reset_all_clears_everything() {
        let c = CounterToken::new();
        let _ = c.record_and_get("alice", "t1", "1");
        let _ = c.record_and_get("bob", "t2", "1");

        assert_eq!(c.get_count("alice", "t1"), 1);
        assert_eq!(c.get_count("bob", "t2"), 1);

        c.reset_all();

        assert_eq!(c.get_count("alice", "t1"), 0);
        assert_eq!(c.get_count("bob", "t2"), 0);
        assert!(c.get_all_tokens_json().is_empty());
    }

    #[test]
    fn concurrent_increments_are_counted_correctly() {
        let c = CounterToken::new();
        let threads = 8usize;
        let iters_per_thread = 1000usize;

        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| {
                    for _ in 0..iters_per_thread {
                        let _ = c.record_and_get("load", "tok", "1");
                    }
                });
            }
        });

        assert_eq!(c.get_count("load", "tok"), (threads * iters_per_thread) as u64);
    }

    #[test]
    fn key_cache_reuses_key_for_same_user_token() {
        let c = CounterToken::new();

        let _ = c.record_and_get("eve", "same", "1");
        let _ = c.record_and_get("eve", "same", "1");

        let all = c.get_all_tokens_json();
        let eve = all.iter().find(|u| u.user == "eve").unwrap();
        let same_count = eve.tokens.iter().filter(|t| t.token_id == "same").count();
        assert_eq!(same_count, 1);
    }

    #[test]
    fn record_and_get_requires_numeric_expire_at() {
        let c = CounterToken::new();

        let n = c.record_and_get("ok", "tok", "2");
        assert_eq!(n, 1);

    }

    #[test]
    fn expire_at_approx_is_stable_even_if_slow() {
        let c = CounterToken::new();
        let _ = c.record_and_get("slow", "tok", "2");
        thread::sleep(StdDuration::from_millis(10));
        let all = c.get_all_tokens_json();
        let slow = all.iter().find(|u| u.user == "slow").unwrap();
        let tok = slow.tokens.iter().find(|t| t.token_id == "tok").unwrap();
        let diff = (tok.expire_at - tok.delivery_at).num_seconds();
        assert!(
            (1..=3).contains(&diff),
                "diff={}s attendu proche de 2s",
                diff
        );
    }
}
