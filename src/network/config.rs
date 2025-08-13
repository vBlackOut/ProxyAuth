
use crate::config::config::AppConfig;
use once_cell::sync::OnceCell;

#[derive(Debug)]
pub struct LbTuning {
    pub request_timeout_ms: u64,
    pub pool_max_idle_per_host: usize,
    pub keep_alive_secs: u64,

    pub backend_valid_duration_secs: u64,
    pub cooldown_base_secs: u64,
    pub cooldown_max_secs: u64,
    pub backend_reset_threshold_secs: u64,
}

pub static LB_TUNING: OnceCell<LbTuning> = OnceCell::new();

pub fn init_loadbalancer(cfg: &AppConfig) {
    let _ = LB_TUNING.set(LbTuning {
        request_timeout_ms: cfg.client_timeout,
        pool_max_idle_per_host: cfg.max_idle_per_host as usize,
        keep_alive_secs: cfg.keep_alive,

        backend_valid_duration_secs: 5,
        cooldown_base_secs: 2,
        cooldown_max_secs: 15,
        backend_reset_threshold_secs: 6,
    });
}
