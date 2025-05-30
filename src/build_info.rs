use once_cell::sync::Lazy;
use std::env;
use std::sync::Mutex;

include!(concat!(env!("OUT_DIR"), "/shuffle_generated.rs"));

#[derive(Debug, Clone)]
pub struct BuildInfo {
    pub version: String,
    pub build_time: u64,
    pub build_rand: u64,
    pub build_seed: u64,
    pub build_epoch: i64,
    pub shuffled_order: String,
}

fn load_from_env() -> BuildInfo {

    let shuffled = SHUFFLED_ORDER.join(",");

    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_time: env!("BUILD_TIME").parse().unwrap_or(0),
        build_rand: env!("BUILD_RAND").parse().unwrap_or(0),
        build_seed: env!("BUILD_SEED").parse().unwrap_or(0),
        build_epoch: env!("BUILD_EPOCH_DATE").parse().unwrap_or(0),
        shuffled_order: shuffled,
    }
}

pub static BUILD_INFO: Lazy<Mutex<BuildInfo>> = Lazy::new(|| Mutex::new(load_from_env()));

pub fn get() -> BuildInfo {
    BUILD_INFO.lock().unwrap().clone()
}

pub fn update(new_info: BuildInfo) {
    let mut info = BUILD_INFO.lock().unwrap();
    *info = new_info;
}

impl BuildInfo {
    pub fn to_string(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.version,
            self.build_time,
            self.build_rand,
            self.build_seed,
            self.build_epoch,
            self.shuffled_order
        )
    }
}
