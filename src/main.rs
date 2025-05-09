mod auth;
mod config;
mod crypto;
mod proxy;
mod ratelimit;
mod security;
mod def_config;
mod command;
mod start_actix;
mod tokencount;
mod stats;


use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{web, App, HttpServer};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue};
use auth::auth;
use stats::stats as metric_stats;
use config::{load_config, AppConfig, AppState, RouteConfig};
use proxy::proxy;
use start_actix::mode_actix_web;
use def_config::{create_config, ensure_running_as_proxyauth, ensure_user_proxyauth_exists, switch_to_user, setup_proxyauth_directory};
use command::{Cli, Commands};
use ratelimit::UserToken;
pub use tokencount::CounterToken;
use std::{fs, sync::Arc, sync::Mutex};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::filter::LevelFilter;
use tracing_loki::url::Url;
use clap::Parser;
use std::{io, process};

const VERSION: &str = env!("CARGO_PKG_VERSION");


#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let cli = Cli::parse();

    if let Some(command) = &cli.command {
        match command {
            Commands::Prepare => {
                let _ = ensure_user_proxyauth_exists();
                let _ = setup_proxyauth_directory();
                return Ok(());
            }

            Commands::Stats => {
                // launch as user proxyauth
                let _ = switch_to_user("proxyauth");

                // detect if program is running proxyauth user
                ensure_running_as_proxyauth();

                let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

                let mut headers = HeaderMap::new();
                headers.insert(
                    "X-Auth-Token",
                    HeaderValue::from_str(&config.token_admin).expect("invalid token string"),
                );

                let client = Client::new();

                match client
                .get("http://127.0.0.1:8080/adm/stats")
                .headers(headers)
                .send()
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            match response.text() {
                                Ok(body) => {
                                    println!("{}", body);
                                    std::process::exit(0);
                                }
                                Err(err) => {
                                    eprintln!("Failed to read response body: {}", err);
                                    std::process::exit(1);
                                }
                            }
                        } else {
                            eprintln!("Server responded with error status: {}", response.status());
                            std::process::exit(1);
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to connect to proxyauth: {}", err);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    // launch as user proxyauth
    let _ = switch_to_user("proxyauth");

    // detect if program is running proxyauth user
    ensure_running_as_proxyauth();

    // download default config from repository
    create_config(
        "https://raw.githubusercontent.com/vBlackOut/ProxyAuth/refs/heads/main/config/config.json",
        "/etc/proxyauth/config/config.json",
    ).await.expect("No possible download config/config.json");

    create_config(
        "https://raw.githubusercontent.com/vBlackOut/ProxyAuth/refs/heads/main/config/routes.yml",
        "/etc/proxyauth/config/routes.yml",
    ).await.expect("No possible download config/routes.yml");

    let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

    let routes: RouteConfig =
        serde_yaml::from_str(&fs::read_to_string("/etc/proxyauth/config/routes.yml")?).unwrap();

    let counter_token = Arc::new(Mutex::new(CounterToken::new()));

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::new(routes),
        counter: counter_token,
    });

    if let Some(logs) = config.log.get("type") {
        if logs == "loki" {

            let host = config.log.get("host").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Missing Loki host config")
            })?;

            let url = Url::parse(host).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid Loki URL: {}", e))
            })?;


            let Ok((layer, task)) = tracing_loki::builder()
            .label("app", "proxyauth").expect("REASON")
            .extra_field("pid", format!("{}", process::id())).expect("REASON")
            .build_url(url) else { todo!() };

            // We need to register our layer with `tracing`.
            tracing_subscriber::registry()
            .with(layer.with_filter(LevelFilter::INFO))
            .with(tracing_subscriber::fmt::Layer::new().with_filter(LevelFilter::INFO))
            .init();

            tokio::spawn(task);
        }

        if logs == "local" {
            tracing_subscriber::fmt::init();
        }
    }


    // configuration proxy ratelimit
    let requests_per_second_proxy_config = config
        .ratelimit_proxy
        .get("requests_per_second")
        .copied()
        .expect("Error value per_second");

    let burst_proxy_config = config
        .ratelimit_proxy
        .get("burst")
        .copied()
        .expect("Error value burst")
        .try_into()
        .unwrap();

    let delay_block_proxy_config = config
        .ratelimit_proxy
        .get("block_delay")
        .copied()
        .expect("Error value block_delay");

    // configuration auth ratelimit
    let requests_per_second_auth_config = config
        .ratelimit_auth
        .get("requests_per_second")
        .copied()
        .expect("Error value per_second");

    let burst_auth_config = config
        .ratelimit_auth
        .get("burst")
        .copied()
        .expect("Error value burst")
        .try_into()
        .unwrap();

    let delay_block_auth_config = config
        .ratelimit_auth
        .get("block_delay")
        .copied()
        .expect("Error value block_delay");

    let governor_auth_conf = GovernorConfigBuilder::default()
        .requests_per_second(requests_per_second_auth_config)
        .burst_size(burst_auth_config)
        .use_headers()
        .period(std::time::Duration::from_millis(delay_block_auth_config))
        .finish()
        .unwrap();

    let governor_proxy_conf = GovernorConfigBuilder::default()
        .requests_per_second(requests_per_second_proxy_config)
        .burst_size(burst_proxy_config)
        .key_extractor(UserToken)
        .period(std::time::Duration::from_millis(delay_block_proxy_config as u64))
        .finish()
        .unwrap();

    let mode_actix = mode_actix_web(&requests_per_second_auth_config, &requests_per_second_proxy_config);

    match mode_actix {
        "NO_RATELIMIT_AUTH" => {
            println!("\nlaunch ProxyAuth v{} \nratelimit On, (Proxy)", VERSION);
            HttpServer::new(move || {
                App::new()
                    .app_data(state.clone())
                    .service(web::resource("/auth").route(web::post().to(auth)))
                    .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                    .default_service(web::to(proxy).wrap(Governor::new(&governor_proxy_conf)))
            })
            .workers((config.worker as u8).into())
            .bind((config.host.as_str(), config.port as u16))?
            .run()
            .await
       }

       "NO_RATELIMIT_PROXY" => {
            println!("\nlaunch ProxyAuth v{} \nratelimit On (Auth)", VERSION);
            HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .service(
                    web::resource("/auth").route(
                        web::post()
                            .to(auth)
                            .wrap(Governor::new(&governor_auth_conf)),
                    ),
                )
                .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                .default_service(web::to(proxy))
            })
            .workers((config.worker as u8).into())
            .bind((config.host.as_str(), config.port as u16))?
            .run()
            .await
       }

       "RATELIMITE_GLOBAL_ON" => {
            println!("\nlaunch ProxyAuth v{} \nratelimit On, (Proxy, Auth)", VERSION);
            HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .service(
                    web::resource("/auth").route(
                        web::post()
                            .to(auth)
                            .wrap(Governor::new(&governor_auth_conf)),
                    ),
                )
                .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                .default_service(web::to(proxy).wrap(Governor::new(&governor_proxy_conf)))
            })
            .workers((config.worker as u8).into())
            .bind((config.host.as_str(), config.port as u16))?
            .run()
            .await
        }

       "RATELIMIT_GLOBAL_OFF" => {
            println!("\nlaunch ProxyAuth v{} \nratelimit Off", VERSION);
            HttpServer::new(move || {
                App::new()
                    .app_data(state.clone())
                    .service(web::resource("/auth").route(web::post().to(auth)))
                    .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                    .default_service(web::to(proxy))
            })
            .workers((config.worker as u8).into())
            .bind((config.host.as_str(), config.port as u16))?
            .run()
            .await
       }

       _ => {
            println!("\nlaunch ProxyAuth v{} \nratelimit Off (No config)", VERSION);
            HttpServer::new(move || {
                App::new()
                    .app_data(state.clone())
                    .service(web::resource("/auth").route(web::post().to(auth)))
                    .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                    .default_service(web::to(proxy))
            })
            .workers((config.worker as u8).into())
            .bind((config.host.as_str(), config.port as u16))?
            .run()
            .await
       }
    }
}
