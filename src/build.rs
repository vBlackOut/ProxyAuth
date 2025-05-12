use rand::Rng;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut rng = rand::thread_rng();
    let build_rand = rng.gen_range(1..999999999);
    let build_seed = rng.gen_range(1..999);

    let build_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=BUILD_RAND={}", build_rand);
    println!("cargo:rustc-env=BUILD_SEED={}", build_seed);
}
