

pub fn mode_actix_web(auth_ratelimit_config: &u64, requests_per_second_config: &u64) -> String {
    let mut mode = String::new();

    if *auth_ratelimit_config == 0 && *requests_per_second_config >= 1 {
        mode = "NO_RATELIMIT_AUTH".to_string();
    }

    if *auth_ratelimit_config >= 1 && *requests_per_second_config == 0 {
        mode = "NO_RATELIMIT_PROXY".to_string()
    }

    if *auth_ratelimit_config >= 1 && *requests_per_second_config >= 1 {
        mode = "RATELIMITE_GLOBAL_ON".to_string();
    }

    if *auth_ratelimit_config == 0 && *requests_per_second_config == 0 {
        mode = "RATELIMITE_GLOBAL_OFF".to_string()
    }

    mode
}
