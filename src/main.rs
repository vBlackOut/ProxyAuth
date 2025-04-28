mod auth;
mod config;
mod crypto;
mod proxy;
mod ratelimit;
mod security;

use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{web, App, HttpServer};
use auth::auth;
use config::{load_config, AppConfig, AppState, RouteConfig};
use proxy::proxy;
use ratelimit::UserToken;
use std::{fs, sync::Arc};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::filter::LevelFilter;
use tracing_loki::url::Url;
use std::process;
use std::io;

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let config: Arc<AppConfig> = load_config("config/config.json");
    let routes: RouteConfig =
        serde_yaml::from_str(&fs::read_to_string("config/routes.yml")?).unwrap();

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::new(routes),
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
            tracing_subscriber::fmt::init();  // ici ton code
        }
    }

    let requests_per_second_config = config
        .ratelimit
        .get("requests_per_second")
        .copied()
        .expect("Error value per_second");
    let burst_config = config
        .ratelimit
        .get("burst")
        .copied()
        .expect("Error value burst")
        .try_into()
        .unwrap();
    let delay_block_config = config
        .ratelimit
        .get("block_delay")
        .copied()
        .expect("Error value block_delay");

    let auth_ratelimit_config = config
        .ratelimit
        .get("auth")
        .copied()
        .expect("Error value auth_ratelimit");

    let governor_auth_conf = GovernorConfigBuilder::default()
        .requests_per_second(auth_ratelimit_config)
        .burst_size(auth_ratelimit_config.try_into().unwrap())
        .use_headers()
        .period(std::time::Duration::from_millis(10000u64))
        .finish()
        .unwrap();

    let governor_proxy_conf = GovernorConfigBuilder::default()
        .requests_per_second(requests_per_second_config)
        .burst_size(burst_config)
        .key_extractor(UserToken)
        .period(std::time::Duration::from_millis(delay_block_config as u64))
        .finish()
        .unwrap();

    println!("\nlaunch ProxyAuth v0.5.3 \nratelimit On, ({} requests per seconds, {} requests burst, blocked delay: {} seconds)", requests_per_second_config, burst_config, delay_block_config);

    if auth_ratelimit_config > 0 {
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
                .default_service(web::to(proxy).wrap(Governor::new(&governor_proxy_conf)))
        })
        .workers((config.worker as u8).into())
        .bind((config.host.as_str(), config.port as u16))?
        .run()
        .await
    } else {
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .service(web::resource("/auth").route(web::post().to(auth)))
                .default_service(web::to(proxy).wrap(Governor::new(&governor_proxy_conf)))
        })
        .workers((config.worker as u8).into())
        .bind((config.host.as_str(), config.port as u16))?
        .run()
        .await
    }
}
