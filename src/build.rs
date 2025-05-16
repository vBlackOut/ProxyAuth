use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let mut rng = rand::thread_rng();
    let build_rand = rng.gen_range(1..999_999_999);
    let build_seed = rng.gen_range(1..999);

    let build_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs()
    .to_string();

    println!("cargo:rustc-env=BUILD_TIME={}", build_time);
    println!("cargo:rustc-env=BUILD_RAND={}", build_rand);
    println!("cargo:rustc-env=BUILD_SEED={}", build_seed);

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
