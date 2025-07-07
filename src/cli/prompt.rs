use crate::cli::command::{Cli, Commands};
use crate::config::config::{AppConfig, load_config};
use crate::config::def_config::{
    ensure_running_as_proxyauth, ensure_running_as_root, ensure_user_proxyauth_exists,
    setup_proxyauth_directory, switch_to_user,
};
use crate::keystore::export::export_as_file;
use clap::Parser;
use reqwest::{
    ClientBuilder,
    header::{HeaderMap, HeaderValue},
};
use std::sync::Arc;

pub async fn prompt() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        None => return Ok(()),

        Some(Commands::Prepare) => {
            switch_to_user("root")?;
            ensure_running_as_root();
            ensure_user_proxyauth_exists()?;
            setup_proxyauth_directory()?;
            std::process::exit(0);
        }

        Some(Commands::Sync { target }) => {
            ensure_running_as_root();

            match target.as_deref() {
                None => {
                    std::process::exit(0);
                }
                Some("export") => {
                    let _ = export_as_file();
                    std::process::exit(0);
                }
                Some(_host) => Ok(()),
            }
        }

        Some(Commands::Stats) => {
            switch_to_user("proxyauth")?;
            ensure_running_as_proxyauth();

            let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

            let mut headers = HeaderMap::new();
            headers.insert("X-Auth-Token", HeaderValue::from_str(&config.token_admin)?);

            let client = ClientBuilder::new()
                .danger_accept_invalid_certs(true)
                .build()?;

            let response = client
                .get("https://127.0.0.1:8080/adm/stats")
                .headers(headers)
                .send()
                .await?;

            if response.status().is_success() {
                let body = response.text().await?;
                println!("{}", body);
                std::process::exit(0);
            } else {
                eprintln!("Server responded with error status: {}", response.status());
                std::process::exit(1);
            }
        }
    }
}
