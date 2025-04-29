use std::fs;
use std::path::Path;
use std::io::Write;
use reqwest;

pub async fn create_config(url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(path).exists() {
        return Ok(());
    }

    println!("Config file {} not found. Downloading from {}", path, url);

    let response = reqwest::get(url).await?;
    if !response.status().is_success() {
        return Err(format!("Failed to download config: HTTP {}", response.status()).into());
    }

    let content = response.bytes().await?;

    if let Some(parent) = Path::new(path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = fs::File::create(path)?;
    file.write_all(&content)?;

    println!("Config downloaded and saved to {}", path);

    Ok(())
}
