use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use std::process;
use std::env;

fn main() {
    let version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION not set");

    if is_yanked_version(&version) {
        eprintln!("Build blocked: version {} is marked as yanked", version);
        process::exit(1);
    } else {
        println!("cargo:warning=Version {} is allowed to build", version);
    }

    let mut rng = rand::thread_rng();
    let build_rand = rng.gen_range(1..999_999_999);
    let build_seed = rng.gen_range(1..999);

    let build_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs()
    .to_string();

    let random_epoch: i64 = rng.gen_range(0..999_999_999_999);

    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=BUILD_RAND={}", build_rand);
    println!("cargo:rustc-env=BUILD_SEED={}", build_seed);
    println!("cargo:rustc-env=BUILD_EPOCH_DATE={}", random_epoch);

    // SHUFFLE BUILD
    let mut fields = vec![
        "username".to_string(),
        "secret_with_timestamp".to_string(),
        "build_time".to_string(),
        "time_expire".to_string(),
        "build_rand".to_string(),
        "token_id".to_string(),
    ];

    let mut shuffle_rng = ChaCha8Rng::seed_from_u64(build_seed);
    fields.shuffle(&mut shuffle_rng);

    let const_string = format!(
        "pub const SHUFFLED_ORDER: [&str; {}] = [{}];",
        fields.len(),
                               fields
                               .iter()
                               .map(|s| format!("\"{}\"", s))
                               .collect::<Vec<_>>()
                               .join(", ")
    );

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("shuffle_generated.rs");
    let mut f = fs::File::create(dest_path).unwrap();
    f.write_all(const_string.as_bytes()).unwrap();
}

fn is_yanked_version(version: &str) -> bool {
    let url = format!("https://proxyauth.app/config/build.json#{}", version);

    let response = match reqwest::blocking::get(&url) {
        Ok(resp) => resp,
        Err(err) => {
            eprintln!("Failed to fetch build.json from {}: {}", url, err);
            return false;
        }
    };

    let json_text = match response.text() {
        Ok(text) => text,
        Err(err) => {
            eprintln!("Failed to read build.json content: {}", err);
            return false;
        }
    };

    let data: serde_json::Value = match serde_json::from_str(&json_text) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("Failed to parse build.json: {}", err);
            return false;
        }
    };

    match data.get(version).and_then(|v| v.as_str()) {
        Some("yank") => true,
        _ => false,
    }
}
