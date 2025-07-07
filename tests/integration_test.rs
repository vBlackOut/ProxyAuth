use actix_web::{App, HttpResponse, test, web};
use proxyauth::network::shared_client::{
    ClientOptions, build_hyper_client_cert, build_hyper_client_normal, build_hyper_client_proxy,
};
use proxyauth::{AppConfig, AppState, CounterToken, RouteConfig, auth as auth_handler};
use serde::de::DeserializeOwned;
use serde_json::json;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

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

    let counter_token = CounterToken::new();

    let state = web::Data::new(AppState {
        config: Arc::clone(&config),
        routes: Arc::new(routes),
        counter: Arc::new(counter_token.into()),
        client_normal,
        client_with_cert,
        client_with_proxy,
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
