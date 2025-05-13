use actix_web::{App, HttpResponse, test, web};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use reqwest::Client;
use std::time::Duration;
use proxyauth::{AppConfig, AppState, CounterToken, RouteConfig, auth as auth_handler};

fn load_config<T: DeserializeOwned>(path: &str) -> T {
    let data = fs::read_to_string(path).expect("Failed to read config file");
    serde_json::from_str(&data).expect("Failed to parse config JSON")
}

async fn proxy_handler() -> HttpResponse {
    HttpResponse::Ok().body("proxy ok")
}

fn create_app_for_test() -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        Config = (),
        InitError = (),
    >,
> {
    let config: Arc<AppConfig> = Arc::new(load_config("config/config.json"));

    let routes: RouteConfig = serde_yaml::from_str(
        &fs::read_to_string("config/routes.yml").expect("Failed to read routes.yml"),
    )
    .expect("Failed to parse routes YAML");

    let counter_token = CounterToken::new();

    let client = Client::builder()
                .timeout(Duration::from_millis(100))
                .pool_idle_timeout(Some(Duration::from_secs(30)))
                .pool_max_idle_per_host(5000)
                .tcp_keepalive(Some(Duration::from_secs(30)))
                .danger_accept_invalid_certs(true)
                .build()
                .expect("Failed to build high-performance reqwest client");

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::new(routes),
        counter: Arc::new(counter_token.into()),
        client: client,
    });

    App::new()
        .app_data(state)
        .service(web::resource("/auth").route(web::post().to(auth_handler)))
        .default_service(web::to(proxy_handler))
}

#[actix_web::test]
async fn test_auth_route() {
    let app = test::init_service(create_app_for_test()).await;

    let req = test::TestRequest::post()
        .uri("/auth")
        .set_json(&json!({
            "username": "admin",
            "password": "admin123"
        }))
        .peer_addr(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            8080,
        ))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
