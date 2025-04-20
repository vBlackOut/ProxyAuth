mod config;
mod crypto;
mod proxy;
mod ratelimit;
mod refresh_token;
mod security;

use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{web, App, HttpServer};
use config::{AppConfig, AppState, AuthRequest, RouteConfig};
use proxy::proxy;
use ratelimit::UserToken;
use refresh_token::refresh_token;
use reqwest::Client;
use std::{fs, sync::Arc};
use tracing::info;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let config: Arc<AppConfig> =
        Arc::new(serde_json::from_str(&std::fs::read_to_string("config/config.json")?).unwrap());
    let routes: RouteConfig =
        serde_yaml::from_str(&fs::read_to_string("config/routes.yml")?).unwrap();

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::new(routes),
        client: Client::new(),
    });

    let per_second_config = config
        .ratelimit
        .get("per_second")
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

    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(per_second_config)
        .burst_size(burst_config)
        .key_extractor(UserToken)
        .period(std::time::Duration::from_secs(delay_block_config as u64))
        .finish()
        .unwrap();

    info!("\nlaunch ProxyAuth v0.3.5 \nratelimit On, ({} requests per seconds, {} requests burst, blocked delay: {} seconds)", per_second_config, burst_config, delay_block_config);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(web::resource("/auth").route(web::post().to(refresh_token)))
            .default_service(web::to(proxy).wrap(Governor::new(&governor_conf)))
    })
    .workers((config.worker as u8).into())
    .bind((config.host.as_str(), config.port as u16))?
    .run()
    .await
}
