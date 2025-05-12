pub fn mode_actix_web(
    auth_ratelimit_config: &u64,
    requests_per_second_config: &u64,
) -> &'static str {
    if *auth_ratelimit_config == 0 && *requests_per_second_config >= 1 {
        return "NO_RATELIMIT_AUTH";
    }

    if *auth_ratelimit_config >= 1 && *requests_per_second_config == 0 {
        return "NO_RATELIMIT_PROXY";
    }

    if *auth_ratelimit_config >= 1 && *requests_per_second_config >= 1 {
        return "RATELIMIT_GLOBAL_ON";
    }

    if *auth_ratelimit_config == 0 && *requests_per_second_config == 0 {
        return "RATELIMIT_GLOBAL_OFF";
    }

    return "NO_CONFIG";
}
