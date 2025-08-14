// Copyright 2025 Vladimir Souchet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod adm;
mod build;
mod cli;
mod config;
mod keystore;
mod logs;
mod network;
mod revoke;
mod start_actix;
mod stats;
mod tls;
mod token;

use crate::adm::registry_otp::{get_otpauth_uri, get_otpauth_uri_option};
use crate::adm::revoke::revoke_route;
use crate::build::build_info::update_build_info;
use crate::cli::prompt::prompt;
use crate::keystore::import::decrypt_keystore;
use crate::network::cors::CorsMiddleware;
use crate::revoke::db::{load_revoked_tokens, start_revoked_token_ttl};
use crate::tls::check_port;
use crate::network::proxy::init_routes;
use crate::network::config::init_loadbalancer;
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{App, http::Method, web};
use chrono::Local;
use config::config::{AppConfig, AppState, RouteConfig, load_config};
use config::def_config::{create_config, ensure_running_as_proxyauth, switch_to_user};
use dashmap::DashMap;
use futures_util::future::join_all;
use logs::{ChannelLogWriter, get_logs, log_collector};
use network::proxy::global_proxy;
use network::ratelimit::{RateLimitLogger, UserToken};
use network::shared_client::{
    ClientOptions, build_hyper_client_cert, build_hyper_client_normal, build_hyper_client_proxy,
};
use socket2::{Domain, Protocol, Socket, Type};
use start_actix::mode_actix_web;
use stats::stats::stats as metric_stats;
pub use stats::tokencount::CounterToken;
use std::net::TcpListener;
use std::{fs, process, sync::Arc, time::Duration};
use tls::bind_server;
use token::auth::{auth, auth_options};
use token::logout::{logout_options, logout_session};
use token::security::init_derived_key;
use tokio::sync::mpsc::unbounded_channel;
use tracing::{error, warn};
use tracing_loki::url::Url;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt::time::FormatTime;
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct LocalTime;

impl FormatTime for LocalTime {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        write!(w, "{}", Local::now().format("%Y-%m-%d %H:%M:%S %:z"))
    }
}

fn print_launcher(mode: &str, version: &str, worker: u8, addr: &str) {
    let msg = match mode {
        "NO_RATELIMIT_AUTH" => "ratelimit On (Proxy)",
        "NO_RATELIMIT_PROXY" => "ratelimit On (Auth)",
        "RATELIMIT_GLOBAL_ON" => "ratelimit On (Proxy, Auth)",
        "RATELIMIT_GLOBAL_OFF" => "ratelimit Off",
        _ => "ratelimit Off (No config)",
    };

    println!(
        "\nlaunch ProxyAuth v{} \n{}\nstarting service: \"proxyauth-service\" worker: {} listening on {}",
        version, msg, worker, addr
    );
}

async fn create_listener(
    addr: &str,
    send_buf_size: usize,
    recv_buf_size: usize,
    backlog: i32,
) -> std::io::Result<TcpListener> {
    let sock_addr: std::net::SocketAddr = addr.parse().unwrap();
    let domain = if sock_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.set_send_buffer_size(send_buf_size)?;
    socket.set_recv_buffer_size(recv_buf_size)?;
    socket.bind(&sock_addr.into())?;
    socket.listen(backlog)?;

    Ok(socket.into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    init_loadbalancer(&config);

    let mut routes: RouteConfig = serde_yaml::from_str(
        &fs::read_to_string("/etc/proxyauth/config/routes.yml").expect("cannot read routes"),
    )
    .expect("Failed to parse routes.yml");

    let counter_token = Arc::new(CounterToken::new());

    let revoked_tokens = match load_revoked_tokens() {
        Ok(tokens) => tokens,
        Err(e) => {
            error!(
                "Failed to load revoked token database: {}. Using empty token map.",
                e
            );
            Arc::new(DashMap::new())
        }
    };

    start_revoked_token_ttl(
        revoked_tokens.clone(),
        std::time::Duration::from_secs(15),
        config.redis.clone(),
    )
    .await;

    let client_normal = build_hyper_client_normal(&config);
    let client_with_cert = build_hyper_client_cert(
        ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: false,
            cert_path: None,
            key_path: None,
        },
        &config,
    );

    let client_with_proxy = build_hyper_client_proxy(
        ClientOptions {
            use_proxy: true,
            proxy_addr: Some("http://127.0.0.1:8888".to_string()),
            use_cert: false,
            cert_path: None,
            key_path: None,
        },
        &config,
    );

    init_routes(&mut routes.routes);

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::new(routes),
        counter: counter_token,
        client_normal,
        client_with_cert,
        client_with_proxy,
        revoked_tokens,
    });

    init_derived_key(&config.secret);

    // logs
    fn init_logging(config: &AppConfig) {
        let logs = config
            .log
            .get("type")
            .map(|v| v.trim_matches('"'))
            .unwrap_or("local");

        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("proxyauth=trace"))
            .add_directive("actix_web=warn".parse().unwrap())
            .add_directive("actix_server=warn".parse().unwrap());

        let base_registry = Registry::default().with(env_filter);

        match logs {
            "loki" => {
                let host = config.log.get("host").expect("Missing Loki host config");
                let url = Url::parse(host).expect("Invalid Loki URL");

                let (loki_layer, task) = tracing_loki::builder()
                    .label("app", "proxyauth")
                    .expect("builder failed")
                    .extra_field("pid", format!("{}", process::id()))
                    .expect("extra_field failed")
                    .build_url(url)
                    .expect("build_url failed");

                let loki_filter = tracing_subscriber::filter::filter_fn(|meta| {
                    meta.target().starts_with("proxyauth")
                });

                let fmt_layer = fmt::Layer::new()
                    .with_timer(LocalTime)
                    .with_filter(loki_filter);

                base_registry
                    .with(loki_layer.with_filter(LevelFilter::INFO))
                    .with(fmt_layer)
                    .init();

                tokio::spawn(task);
            }

            "http" => {
                let (tx, rx) = unbounded_channel::<String>();

                let max_logs = config
                    .log
                    .get("write_max_logs")
                    .and_then(|v| v.parse::<usize>().ok())
                    .expect("Invalid write_max_logs");

                if max_logs >= 100_000 {
                    eprintln!("write_max_logs must be < 100000");
                    process::exit(1);
                }

                let fmt_layer =
                    fmt::Layer::new()
                        .with_timer(LocalTime)
                        .with_writer(ChannelLogWriter {
                            sender: tx.clone().into(),
                        });

                base_registry.with(fmt_layer).init();

                tokio::spawn(log_collector(rx, max_logs));
            }

            "disabled" => {}

            _ => {
                let fmt_layer = fmt::Layer::new().with_timer(LocalTime);

                base_registry.with(fmt_layer).init();
            }
        }
    }

    init_logging(&config);

    // check keystore if exist
    match decrypt_keystore(None) {
        Ok(Some(message)) => {
            let _ = update_build_info(&message);
            println!("Load keystore successfull from /etc/proxyauth/import/data.gpg");
        }
        Ok(None) => {}
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

    let mode_actix = mode_actix_web(
        &requests_per_second_auth_config,
        &requests_per_second_proxy_config,
    );

    let addr = format!("{}:{}", config.host, config.port);

    if !check_port(&addr) {
        eprintln!("Port {} is already in use. Server startup aborted.", addr);
        std::process::exit(1);
    }

    let num_instances = config.num_instances;

    let mut server_futures = Vec::new();

    print_launcher(mode_actix, VERSION, config.worker, &addr.to_string());

    for _instance_id in 0..num_instances {
        let listener = create_listener(
            &format!("{}:{}", config.host, config.port),
            64 * 1024,
            64 * 1024,
            config.socket_listen.try_into().unwrap(),
        )
        .await?;

        let state_cloned = state.clone();

        match mode_actix.as_ref() {
            "NO_RATELIMIT_AUTH" => {
                let seconds_per_request =
                    Duration::from_secs_f64(1.0 / requests_per_second_proxy_config as f64);
                let governor_proxy_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_proxy_config)
                    .key_extractor(UserToken)
                    .period(seconds_per_request)
                    .finish()
                    .unwrap();

                let server = bind_server(
                    move || {
                        App::new()
                            .app_data(state_cloned.clone())
                            .wrap(RateLimitLogger)
                            .wrap(CorsMiddleware {
                                config: state_cloned.clone(),
                            })
                            .service(
                                web::resource("/auth")
                                    .route(web::post().to(auth))
                                    .route(web::method(Method::OPTIONS).to(auth_options)),
                            )
                            .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                            .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                            .service(
                                web::resource("/adm/revoke").route(web::post().to(revoke_route)),
                            )
                            .service(
                                web::resource("/logout")
                                    .route(web::get().to(logout_session))
                                    .route(web::method(Method::OPTIONS).to(logout_options)),
                            )
                            .service(
                                web::resource("/adm/auth/totp/get")
                                    .route(web::post().to(get_otpauth_uri))
                                    .route(web::method(Method::OPTIONS).to(get_otpauth_uri_option)),
                            )
                            .default_service(
                                web::to(global_proxy).wrap(Governor::new(&governor_proxy_conf)),
                            )
                    },
                    listener,
                    &config,
                )?;

                server_futures.push(tokio::spawn(server));
            }

            "NO_RATELIMIT_PROXY" => {
                let seconds_per_request =
                    Duration::from_secs_f64(1.0 / requests_per_second_auth_config as f64);
                let governor_auth_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_auth_config)
                    .use_headers()
                    .period(seconds_per_request)
                    .finish()
                    .unwrap();

                let server = bind_server(
                    move || {
                        App::new()
                            .app_data(state_cloned.clone())
                            .wrap(RateLimitLogger)
                            .wrap(CorsMiddleware {
                                config: state_cloned.clone(),
                            })
                            .service(
                                web::resource("/auth")
                                    .route(
                                        web::post()
                                            .to(auth)
                                            .wrap(Governor::new(&governor_auth_conf)),
                                    )
                                    .route(web::method(Method::OPTIONS).to(auth_options)),
                            )
                            .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                            .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                            .service(
                                web::resource("/adm/revoke").route(web::post().to(revoke_route)),
                            )
                            .service(
                                web::resource("/logout")
                                    .route(web::get().to(logout_session))
                                    .route(web::method(Method::OPTIONS).to(logout_options)),
                            )
                            .service(
                                web::resource("/adm/auth/totp/get")
                                    .route(web::post().to(get_otpauth_uri))
                                    .route(web::method(Method::OPTIONS).to(get_otpauth_uri_option)),
                            )
                            .default_service(web::to(global_proxy))
                    },
                    listener,
                    &config,
                )?;

                server_futures.push(tokio::spawn(server));
            }

            "RATELIMIT_GLOBAL_ON" => {
                let seconds_per_request_auth =
                    Duration::from_secs_f64(1.0 / requests_per_second_auth_config as f64);
                let governor_auth_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_auth_config)
                    .use_headers()
                    .period(seconds_per_request_auth)
                    .finish()
                    .unwrap();

                let seconds_per_request_proxy =
                    Duration::from_secs_f64(1.0 / requests_per_second_proxy_config as f64);
                let governor_proxy_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_proxy_config)
                    .key_extractor(UserToken)
                    .period(seconds_per_request_proxy)
                    .finish()
                    .unwrap();

                let server = bind_server(
                    move || {
                        App::new()
                            .app_data(state_cloned.clone())
                            .wrap(RateLimitLogger)
                            .wrap(CorsMiddleware {
                                config: state_cloned.clone(),
                            })
                            .service(
                                web::resource("/auth")
                                    .route(
                                        web::post()
                                            .to(auth)
                                            .wrap(Governor::new(&governor_auth_conf)),
                                    )
                                    .route(web::method(Method::OPTIONS).to(auth_options)),
                            )
                            .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                            .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                            .service(
                                web::resource("/adm/revoke").route(web::post().to(revoke_route)),
                            )
                            .service(
                                web::resource("/logout")
                                    .route(web::get().to(logout_session))
                                    .route(web::method(Method::OPTIONS).to(logout_options)),
                            )
                            .service(
                                web::resource("/adm/auth/totp/get")
                                    .route(web::post().to(get_otpauth_uri))
                                    .route(web::method(Method::OPTIONS).to(get_otpauth_uri_option)),
                            )
                            .default_service(
                                web::to(global_proxy).wrap(Governor::new(&governor_proxy_conf)),
                            )
                    },
                    listener,
                    &config,
                )?;

                server_futures.push(tokio::spawn(server));
            }

            "RATELIMIT_GLOBAL_OFF" => {
                let seconds_per_request_auth =
                    Duration::from_secs_f64(1.0 / requests_per_second_auth_config as f64);
                let governor_auth_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_auth_config)
                    .use_headers()
                    .period(seconds_per_request_auth)
                    .finish()
                    .unwrap();

                let seconds_per_request_proxy =
                    Duration::from_secs_f64(1.0 / requests_per_second_proxy_config as f64);
                let governor_proxy_conf = GovernorConfigBuilder::default()
                    .burst_size(burst_proxy_config)
                    .key_extractor(UserToken)
                    .period(seconds_per_request_proxy)
                    .finish()
                    .unwrap();

                let server = bind_server(
                    move || {
                        App::new()
                            .app_data(state_cloned.clone())
                            .wrap(RateLimitLogger)
                            .wrap(CorsMiddleware {
                                config: state_cloned.clone(),
                            })
                            .service(
                                web::resource("/auth")
                                    .route(
                                        web::post()
                                            .to(auth)
                                            .wrap(Governor::new(&governor_auth_conf)),
                                    )
                                    .route(web::method(Method::OPTIONS).to(auth_options)),
                            )
                            .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                            .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                            .service(
                                web::resource("/adm/revoke").route(web::post().to(revoke_route)),
                            )
                            .service(
                                web::resource("/logout")
                                    .route(web::get().to(logout_session))
                                    .route(web::method(Method::OPTIONS).to(logout_options)),
                            )
                            .service(
                                web::resource("/adm/auth/totp/get")
                                    .route(web::post().to(get_otpauth_uri))
                                    .route(web::method(Method::OPTIONS).to(get_otpauth_uri_option)),
                            )
                            .default_service(
                                web::to(global_proxy).wrap(Governor::new(&governor_proxy_conf)),
                            )
                    },
                    listener,
                    &config,
                )?;

                server_futures.push(tokio::spawn(server));
            }

            _ => {
                let server = bind_server(
                    move || {
                        App::new()
                            .app_data(state_cloned.clone())
                            .wrap(CorsMiddleware {
                                config: state_cloned.clone(),
                            })
                            .service(
                                web::resource("/auth")
                                    .route(web::post().to(auth))
                                    .route(web::method(Method::OPTIONS).to(auth_options)),
                            )
                            .service(web::resource("/adm/stats").route(web::get().to(metric_stats)))
                            .service(web::resource("/adm/logs").route(web::get().to(get_logs)))
                            .service(
                                web::resource("/adm/revoke").route(web::post().to(revoke_route)),
                            )
                            .service(
                                web::resource("/logout")
                                    .route(web::get().to(logout_session))
                                    .route(web::method(Method::OPTIONS).to(logout_options)),
                            )
                            .service(
                                web::resource("/adm/auth/totp/get")
                                    .route(web::post().to(get_otpauth_uri))
                                    .route(web::method(Method::OPTIONS).to(get_otpauth_uri_option)),
                            )
                            .default_service(web::to(global_proxy))
                    },
                    listener,
                    &config,
                )?;

                server_futures.push(tokio::spawn(server));
            }
        }
    }

    join_all(server_futures).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn print_launcher_variants_do_not_panic() {
        let modes = [
            "NO_RATELIMIT_AUTH",
            "NO_RATELIMIT_PROXY",
            "RATELIMIT_GLOBAL_ON",
            "RATELIMIT_GLOBAL_OFF",
            "UNKNOWN_MODE",
        ];
        for m in modes {
            print_launcher(m, "0.0.0-test", 4, "127.0.0.1:1234");
        }
    }

    #[tokio::test]
    async fn create_listener_ipv4_accepts_connection() {
        let listener = create_listener("127.0.0.1:0", 64 * 1024, 64 * 1024, 128)
        .await
        .expect("failed to create IPv4 listener");

        let addr = listener.local_addr().expect("no local addr");
        assert_ne!(addr.port(), 0, "port should be assigned");

        let t = thread::spawn(move || {
            let (_sock, _peer) = listener.accept().expect("accept failed");
        });

        thread::sleep(Duration::from_millis(50));

        let _stream = TcpStream::connect(addr).expect("connect failed");

        t.join().expect("accept thread panicked");
    }

    #[tokio::test]
    async fn create_listener_ipv6_accepts_connection_if_available() {
        match create_listener("[::1]:0", 64 * 1024, 64 * 1024, 128).await {
            Ok(listener) => {
                let addr = listener.local_addr().expect("no local addr (v6)");
                assert_ne!(addr.port(), 0, "port should be assigned (v6)");

                let t = thread::spawn(move || {
                    let _ = listener.accept();
                });

                // petit délai pour l'accept
                thread::sleep(Duration::from_millis(50));

                let _ = TcpStream::connect(addr);
                let _ = t.join();
            }
            Err(_e) => {
            }
        }
    }
}

