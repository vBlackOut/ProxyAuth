mod config;
mod protect;
mod network;
mod keystore;
mod cmd;
mod start_actix;
mod stats;
mod timezone;
mod tls;
mod build_info;
mod logs;

use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{App, HttpServer, web};
use protect::security::init_derived_key;
use protect::auth::auth;
use config::config::{AppConfig, AppState, RouteConfig, load_config};
use config::def_config::{
    create_config, ensure_running_as_proxyauth, switch_to_user,
};
use std::net::TcpListener;
use socket2::{Socket, Domain, Type, Protocol};
use network::proxy::global_proxy;
use network::ratelimit::UserToken;
use start_actix::mode_actix_web;
use stats::stats::stats as metric_stats;
use std::{fs, sync::Arc, io, process, time::Duration};
pub use stats::tokencount::CounterToken;
use tracing_loki::url::Url;
use logs::{log_collector, ChannelLogWriter, get_logs};
use tokio::sync::mpsc::unbounded_channel;
use tracing_subscriber::{
    Layer, filter, EnvFilter, filter::LevelFilter,
    layer::SubscriberExt, util::SubscriberInitExt,
    fmt::time::FormatTime
};
use tls::load_rustls_config;
use network::shared_client::{
    build_hyper_client_proxy, build_hyper_client_normal,
    build_hyper_client_cert, ClientOptions
};
use crate::cmd::prompt::prompt;
use crate::keystore::import::decrypt_keystore;
use crate::build_info::update_build_info;
use tracing::{info, warn};
use chrono::Local;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", Local::now().format("%Y-%m-%d %H:%M:%S %:z"))
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {

    let _ = prompt().await;

    // launch as user proxyauth
    let _ = switch_to_user("proxyauth");

    // detect if program is running proxyauth user
    ensure_running_as_proxyauth();

    // download default config from repository
    create_config(
        &format!("https://proxyauth.app/config/{}/config.json", VERSION),
        "/etc/proxyauth/config/config.json",
    )
    .await
    .expect("No possible download config/config.json");

    create_config(
        &format!("https://proxyauth.app/config/{}/routes.yml", VERSION),
        "/etc/proxyauth/config/routes.yml",
    )
    .await
    .expect("No possible download config/routes.yml");

    let config: Arc<AppConfig> = load_config("/etc/proxyauth/config/config.json");

    let routes: RouteConfig =
        serde_yaml::from_str(&fs::read_to_string("/etc/proxyauth/config/routes.yml")?).unwrap();

    let counter_token = Arc::new(CounterToken::new());

    let client_normal = build_hyper_client_normal(&config);
    let client_with_cert = build_hyper_client_cert(ClientOptions {
        use_proxy: false,
        proxy_addr: None,
        use_cert: false,
        cert_path: None,
        key_path: None,
    }, &config);

    let client_with_proxy = build_hyper_client_proxy(ClientOptions {
        use_proxy: true,
        proxy_addr: Some("http://127.0.0.1:8888".to_string()),
        use_cert: false,
        cert_path: None,
        key_path: None,
    }, &config);

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::new(routes),
        counter: counter_token,
        client_normal,
        client_with_cert,
        client_with_proxy,
    });

    init_derived_key(&config.secret);

    if let Some(logs) = config.log.get("type") {
        if logs == "loki" {
            let host = config.log.get("host").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "Missing Loki host config")
            })?;

            let url = Url::parse(host).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid Loki URL: {}", e),
                )
            })?;

            let Ok((layer, task)) = tracing_loki::builder()
                .label("app", "proxyauth")
                .expect("REASON")
                .extra_field("pid", format!("{}", process::id()))
                .expect("REASON")
                .build_url(url)
            else {
                todo!()
            };

            let target_filter = filter::filter_fn(|meta| {
                meta.target().starts_with("proxyauth")
            });

            // We need to register our layer with `tracing`.
            tracing_subscriber::registry()
                .with(layer.with_filter(LevelFilter::INFO))
                .with(tracing_subscriber::fmt::Layer::new().with_timer(LocalTime).with_filter(target_filter))
                .init();

            tokio::spawn(task);
        }

        if logs == "local" {
            tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("proxyauth=trace"))
            .with_timer(LocalTime)
            .with_max_level(tracing::Level::INFO)
            .init();
        }

        if logs == "http" {
            let (tx, rx) = unbounded_channel::<String>();

            tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("proxyauth=trace"))
            .with_timer(LocalTime)
            .with_writer(ChannelLogWriter { sender: tx.clone().into() })
            .with_max_level(tracing::Level::INFO)
            .init();

            let max_logs = config.log.get("max_logs")
            .and_then(|v| v.parse::<usize>().ok())
            .expect("Error value write_max_logs");

            if max_logs <= 100000 {
                println!("Error write_max_logs limit <= 100000");
                std::process::exit(0);
            }

            tokio::spawn(log_collector(rx, max_logs));
            // tracing_subscriber::fmt()
            // .with_writer(|| std::io::sink())
            // .init();
        }
    }

    // check keystore if exist
    match decrypt_keystore() {
        Ok(Some(message)) => {
            let _ = update_build_info(&message);
            info!("Load keystore successfull from /etc/proxyauth/import/data.gpg");
        }
        Ok(None) => {},
        Err(err) => warn!("Failed to decrypt keystore: {:?}", err),
    }

    // configuration proxy ratelimit
    let requests_per_second_proxy_config = config
        .ratelimit_proxy
        .get("requests_per_second")
        .copied()
        .unwrap_or(0);

    let burst_proxy_config = config
        .ratelimit_proxy
        .get("burst")
        .copied()
        .unwrap_or(0)
        .try_into()
        .expect("bad burst_proxy value");

    let delay_block_proxy_config = config
        .ratelimit_proxy
        .get("block_delay")
        .copied()
        .unwrap_or(0)
        .try_into()
        .expect("bad delay_proxy value");

    // configuration auth ratelimit
    let requests_per_second_auth_config = config
        .ratelimit_auth
        .get("requests_per_second")
        .copied()
        .unwrap_or(0);

    let burst_auth_config = config
        .ratelimit_auth
        .get("burst")
        .copied()
        .unwrap_or(0)
        .try_into()
        .expect("bad burst_auth value");

    let delay_block_auth_config = config
        .ratelimit_auth
        .get("block_delay")
        .copied()
        .unwrap_or(0)
        .try_into()
        .expect("bad delay_auth value");

    let mode_actix = mode_actix_web(
        &requests_per_second_auth_config,
        &requests_per_second_proxy_config,
    );


    let addr = format!("{}:{}", config.host, config.port);
    let sock_addr: std::net::SocketAddr = addr.parse().unwrap();

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(1024)?;

    let listener: TcpListener = socket.into();

    match mode_actix {
        "NO_RATELIMIT_AUTH" => {

            let governor_proxy_conf = GovernorConfigBuilder::default()
                .seconds_per_request(requests_per_second_proxy_config)
                .burst_size(burst_proxy_config)
                .key_extractor(UserToken)
                .period(std::time::Duration::from_millis(
                    delay_block_proxy_config,
                ))
                .finish()
                .unwrap();

            println!("\nlaunch ProxyAuth v{} \nratelimit On, (Proxy)\nstarting service: \"proxyauth-service\" worker: {} listening on {}", VERSION, config.worker, addr);
            HttpServer::new(move || {
                App::new()
                    .app_data(state.clone())
                    .service(web::resource("/auth").route(web::post().to(auth)))
                    .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                    .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                    .default_service(web::to(global_proxy).wrap(Governor::new(&governor_proxy_conf)))
            })
            .workers((config.worker as u8).into())
            .keep_alive(Duration::from_secs(5))
            .listen_rustls_0_21(listener, load_rustls_config())?
            .run()
            .await
        }

        "NO_RATELIMIT_PROXY" => {

            let governor_auth_conf = GovernorConfigBuilder::default()
                .seconds_per_request(requests_per_second_auth_config)
                .burst_size(burst_auth_config)
                .use_headers()
                .period(std::time::Duration::from_millis(delay_block_auth_config))
                .finish()
                .unwrap();

            println!("\nlaunch ProxyAuth v{} \nratelimit On (Auth)\nstarting service: \"proxyauth-service\" worker: {} listening on {}", VERSION, config.worker, addr);
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
                    .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                    .default_service(web::to(global_proxy))
            })
            .workers((config.worker as u8).into())
            .keep_alive(Duration::from_secs(5))
            .listen_rustls_0_21(listener, load_rustls_config())?
            .run()
            .await
        }

        "RATELIMIT_GLOBAL_ON" => {

            let governor_auth_conf = GovernorConfigBuilder::default()
                .seconds_per_request(requests_per_second_auth_config)
                .burst_size(burst_auth_config)
                .use_headers()
                .period(std::time::Duration::from_millis(delay_block_auth_config))
                .finish()
                .unwrap();

            let governor_proxy_conf = GovernorConfigBuilder::default()
                .seconds_per_request(requests_per_second_proxy_config)
                .burst_size(burst_proxy_config)
                .key_extractor(UserToken)
                .period(std::time::Duration::from_millis(
                    delay_block_proxy_config,
                ))
                .finish()
                .unwrap();

            println!(
                "\nlaunch ProxyAuth v{} \nratelimit On, (Proxy, Auth)\nstarting service: \"proxyauth-service\" worker: {} listening on {}",
                 VERSION, config.worker, addr
            );
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
                    .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                    .default_service(web::to(global_proxy).wrap(Governor::new(&governor_proxy_conf)))
            })
            .workers((config.worker as u8).into())
            .keep_alive(Duration::from_secs(5))
            .listen_rustls_0_21(listener, load_rustls_config())?
            .run()
            .await
        }

        "RATELIMIT_GLOBAL_OFF" => {
            println!("\nlaunch ProxyAuth v{} \nratelimit Off\nstarting service: \"proxyauth-service\" worker: {} listening on {}", VERSION, config.worker, addr);
            HttpServer::new(move || {
                App::new()
                    .app_data(state.clone())
                    .service(web::resource("/auth").route(web::post().to(auth)))
                    .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                    .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                    .default_service(web::to(global_proxy))
            })
            .workers((config.worker as u8).into())
            .keep_alive(Duration::from_secs(5))
            .listen_rustls_0_21(listener, load_rustls_config())?
            .run()
            .await
        }

        _ => {
            println!(
                "\nlaunch ProxyAuth v{} \nratelimit Off (No config)\nstarting service: \"proxyauth-service\" worker: {} listening on {}",
                VERSION, config.worker, addr
            );
            HttpServer::new(move || {
                App::new()
                    .app_data(state.clone())
                    .service(web::resource("/auth").route(web::post().to(auth)))
                    .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                    .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                    .default_service(web::to(global_proxy))
            })
            .workers((config.worker as u8).into())
            .keep_alive(Duration::from_secs(5))
            .listen_rustls_0_21(listener, load_rustls_config())?
            .run()
            .await
        }
    }
}
