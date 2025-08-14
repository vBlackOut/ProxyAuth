use crate::AppState;
use crate::network::ratelimit::governor::clock::DefaultClock;
use crate::token::security::extract_token_user;
use actix_governor::governor::clock::Clock;
use actix_governor::{KeyExtractor, SimpleKeyExtractionError, governor};
use actix_web::dev::ServiceRequest;
use actix_web::http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::web;
use actix_web::{
    Error,
    dev::{Service, ServiceResponse, Transform},
};
use actix_web::{HttpResponse, HttpResponseBuilder};
use futures_util::future::{LocalBoxFuture, Ready};
use std::task::{Context, Poll};
use tracing::warn;

use std::net::IpAddr;
//use tracing::{info, warn};

#[derive(Clone)]
pub struct UserToken;

fn client_ip(req: &ServiceRequest) -> Option<IpAddr> {
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(ip_str) = forwarded_str.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    req.peer_addr().map(|addr| addr.ip())
}

impl KeyExtractor for UserToken {
    type Key = String;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        let ip = client_ip(&req).expect("?").to_string();

        let app_data = req.app_data::<web::Data<AppState>>().ok_or_else(|| {
            Self::KeyExtractionError::new("Missing app state")
                .set_status_code(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

        // key ratelimite: user extract inside the token
        let user_or_ip = req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .and_then(|token| {
                //info!("Authorization header found: {}", token);
                extract_token_user(token, &app_data.config, ip.clone()).ok()
            })
            .or_else(|| {
                if app_data.config.session_cookie {
                    match req.cookie("session_token") {
                        Some(cookie) => {
                            let value = cookie.value();
                            //info!("Cookie 'session_token' found: {}", value);
                            match extract_token_user(value, &app_data.config, ip.clone()) {
                                Ok(user) => Some(user),
                                Err(_err) => {
                                    //warn!("Failed to extract user from cookie: {:?}", err);
                                    None
                                }
                            }
                        }
                        None => {
                            //warn!("No 'session_token' cookie found");
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .unwrap_or_else(|| {
                //warn!("Falling back to IP: {}", ip);
                ip.clone()
            });

        // key ratelimit: path request
        let path = req.path().to_string();
        Ok(format!("{}:{}", path, user_or_ip))
    }

    fn exceed_rate_limit_response(
        &self,
        negative: &governor::NotUntil<governor::clock::QuantaInstant>,
        mut response: HttpResponseBuilder,
    ) -> HttpResponse {
        let wait_time = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();

        response.content_type(ContentType::json())
        .insert_header(("Retry-After", wait_time.to_string()))

        .body(
            format!(
                r#"{{"code":429, "error": "TooManyRequests", "message": "Too Many Requests", "after": {wait_time}}}"#
            )
        )
    }
}

pub struct RateLimitLogger;

impl<S> Transform<S, ServiceRequest> for RateLimitLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitLoggerMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        futures_util::future::ready(Ok(RateLimitLoggerMiddleware { service }))
    }
}

pub struct RateLimitLoggerMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for RateLimitLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
{
    type Response = ServiceResponse;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<ServiceResponse, Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().clone();
        let path = req.path().to_string();
        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("-")
            .to_string();
        let ip = req
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or("-".to_string());

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            if res.status() == StatusCode::TOO_MANY_REQUESTS {
                warn!(
                    client_ip = %ip,
                    method = %method,
                    path = %path,
                    user_agent = %user_agent,
                    "Rate limit exceeded (429)"
                );
            }

            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};
    use actix_web::http::StatusCode;

    use std::sync::Arc;
    use dashmap::DashMap;
    use hyper::{Body, Client};
    use hyper::client::HttpConnector;
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};
    use hyper_rustls::HttpsConnectorBuilder;

    use crate::config::config::{AppConfig, AppState, RouteConfig};
    use crate::stats::tokencount::CounterToken;

    fn https_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        Client::builder().build::<_, Body>(https)
    }

    fn proxy_client() -> Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let pc = ProxyConnector::from_proxy(https, proxy).unwrap();
        Client::builder().build(pc)
    }

    fn base_config() -> AppConfig {
        AppConfig {
            token_expiry_seconds: 3600,
            secret: "unit-secret".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 8,
            timezone: "UTC".into(),
            login_via_otp: false,
            max_connections: 1024,
            pending_connections_limit: 1024,
            socket_listen: 128,
            client_timeout: 1000,
            keep_alive: 1,
            num_instances: 1,
            redis: None,
            cors_origins: None,
            session_cookie: false,
            max_age_session_cookie: 3600,
            login_redirect_url: None,
            logout_redirect_url: None,
            tls: false,
            csrf_token: false,
        }
    }

    fn make_state(cfg: AppConfig) -> web::Data<AppState> {
        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes: vec![] }),
            counter: Arc::new(CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        };
        web::Data::new(state)
    }

    // ---------------- UserToken.extract() ----------------

    #[actix_web::test]
    async fn user_token_extract_uses_x_forwarded_for() {
        let data = make_state(base_config());

        let app = test::init_service(
            App::new()
            .app_data(data.clone())
            .wrap_fn(|req, _srv| {
                // Interception: on renvoie directement la clé extraite
                let key = UserToken.extract(&req).expect("extraction de clé");
                let (head, _payload) = req.into_parts();
                let resp = HttpResponse::Ok().body(key);
                Box::pin(async move { Ok(ServiceResponse::new(head, resp)) })
            })
            .route("/api", web::get().to(|| async { HttpResponse::Ok() }))
        ).await;

        let req = test::TestRequest::get()
        .uri("/api")
        .insert_header(("x-forwarded-for", "203.0.113.7, 1.1.1.1"))
        .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        let key = String::from_utf8_lossy(&body);
        assert_eq!(key, "/api:203.0.113.7");
    }

    #[actix_web::test]
    async fn user_token_extract_uses_x_real_ip_when_no_forwarded_for() {
        let data = make_state(base_config());

        let app = test::init_service(
            App::new()
            .app_data(data.clone())
            .wrap_fn(|req, _srv| {
                let key = UserToken.extract(&req).expect("extraction de clé");
                let (head, _payload) = req.into_parts();
                let resp = HttpResponse::Ok().body(key);
                Box::pin(async move { Ok(ServiceResponse::new(head, resp)) })
            })
            .route("/x", web::get().to(|| async { HttpResponse::Ok() }))
        ).await;

        let req = test::TestRequest::get()
        .uri("/x")
        .insert_header(("x-real-ip", "198.51.100.42"))
        .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        let key = String::from_utf8_lossy(&body);
        assert_eq!(key, "/x:198.51.100.42");
    }

    #[actix_web::test]
    async fn user_token_extract_falls_back_to_peer_addr() {
        let data = make_state(base_config());

        let app = test::init_service(
            App::new()
            .app_data(data.clone())
            .wrap_fn(|req, _srv| {
                let key = UserToken.extract(&req).expect("extraction de clé");
                let (head, _payload) = req.into_parts();
                let resp = HttpResponse::Ok().body(key);
                Box::pin(async move { Ok(ServiceResponse::new(head, resp)) })
            })
            .route("/peer", web::get().to(|| async { HttpResponse::Ok() }))
        ).await;

        let req = test::TestRequest::get()
        .uri("/peer")
        .peer_addr("192.0.2.9:5555".parse().unwrap())
        .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = test::read_body(resp).await;
        let key = String::from_utf8_lossy(&body);
        assert_eq!(key, "/peer:192.0.2.9");
    }

    // ---------------- RateLimitLogger ----------------

    #[actix_web::test]
    async fn rate_limit_logger_passes_through_429() {
        let app = test::init_service(
            App::new()
            .wrap(RateLimitLogger)
            .route("/hit", web::get().to(|| async {
                HttpResponse::TooManyRequests().finish()
            }))
        ).await;

        let req = test::TestRequest::get().uri("/hit").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[actix_web::test]
    async fn rate_limit_logger_passes_through_200() {
        let app = test::init_service(
            App::new()
            .wrap(RateLimitLogger)
            .route("/ok", web::get().to(|| async { HttpResponse::Ok().finish() }))
        ).await;

        let req = test::TestRequest::get().uri("/ok").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
