use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue, SERVER};
use actix_web::{Error, web};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use std::task::{Context, Poll};

use crate::AppState;

pub struct CorsMiddleware {
    pub config: web::Data<AppState>,
}

impl<S, B> Transform<S, ServiceRequest> for CorsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CorsMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CorsMiddlewareService {
            service,
            config: self.config.clone(),
        })
    }
}

pub struct CorsMiddlewareService<S> {
    service: S,
    config: web::Data<AppState>,
}

impl<S, B> Service<ServiceRequest> for CorsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let config = self.config.clone();
        let origin = req
            .headers()
            .get("origin")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;

            if let Some(origin_str) = origin {
                if let Some(cors) = &config.config.cors_origins {
                    let origin_trimmed = origin_str.trim_end_matches('/').to_ascii_lowercase();
                    if cors.iter().any(|allowed| {
                        allowed.trim_end_matches('/').to_ascii_lowercase() == origin_trimmed
                    }) {
                        if let Ok(hval) = HeaderValue::from_str(&origin_str) {
                            res.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, hval);
                        }
                    }
                }
            }

            res.headers_mut()
                .insert(SERVER, HeaderValue::from_static("ProxyAuth"));
            res.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, HttpResponse, test, web};
    use actix_web::http::header::{
        ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_ORIGIN, SERVER,
    };
    use std::sync::Arc;

    use crate::config::config::{AppConfig, AppState, RouteConfig};
    use crate::stats::tokencount::CounterToken;
    use dashmap::DashMap;

    use hyper::{Body, Client};
    use hyper::client::HttpConnector;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};

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
            secret: "secret".into(),
            users: vec![],
            token_admin: String::new(),
            host: "127.0.0.1".into(),
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 16,
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
            config: Arc::new({
                cfg
            }),
            routes: Arc::new(RouteConfig { routes: vec![] }),
            counter: Arc::new(CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()),
        };
        web::Data::new(state)
    }

    #[actix_web::test]
    async fn cors_adds_headers_when_origin_allowed() {
        let mut cfg = base_config();
        cfg.cors_origins = Some(vec!["https://App.Example.com/".into()]);
        let data = make_state(cfg);

        let app = test::init_service(
            App::new()
            .app_data(data.clone())
            .wrap(CorsMiddleware { config: data.clone() })
            .route("/ping", web::get().to(|| async { HttpResponse::Ok().finish() }))
        ).await;

        let req = test::TestRequest::get()
        .uri("/ping")
        .insert_header((header::ORIGIN, "https://app.example.com"))
        .to_request();

        let resp = test::call_service(&app, req).await;

        let allow_origin = resp.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("ACAO devrait être présent")
        .to_str().unwrap();
        assert_eq!(allow_origin, "https://app.example.com");

        assert_eq!(
            resp.headers().get(SERVER).and_then(|v| v.to_str().ok()),
                   Some("ProxyAuth")
        );
        assert_eq!(
            resp.headers().get(ACCESS_CONTROL_ALLOW_CREDENTIALS).and_then(|v| v.to_str().ok()),
                   Some("true")
        );
    }

    #[actix_web::test]
    async fn cors_skips_acao_when_origin_missing_or_not_allowed_but_adds_other_headers() {
        let data = make_state(base_config());

        let app = test::init_service(
            App::new()
            .app_data(data.clone())
            .wrap(CorsMiddleware { config: data.clone() })
            .route("/ping", web::get().to(|| async { HttpResponse::Ok().finish() }))
        ).await;

        let req1 = test::TestRequest::get().uri("/ping").to_request();
        let resp1 = test::call_service(&app, req1).await;
        assert!(resp1.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        assert_eq!(
            resp1.headers().get(SERVER).and_then(|v| v.to_str().ok()),
                   Some("ProxyAuth")
        );
        assert_eq!(
            resp1.headers().get(ACCESS_CONTROL_ALLOW_CREDENTIALS).and_then(|v| v.to_str().ok()),
                   Some("true")
        );

        let req2 = test::TestRequest::get()
        .uri("/ping")
        .insert_header((header::ORIGIN, "https://not-allowed.example"))
        .to_request();
        let resp2 = test::call_service(&app, req2).await;
        assert!(resp2.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        assert_eq!(
            resp2.headers().get(SERVER).and_then(|v| v.to_str().ok()),
                   Some("ProxyAuth")
        );
        assert_eq!(
            resp2.headers().get(ACCESS_CONTROL_ALLOW_CREDENTIALS).and_then(|v| v.to_str().ok()),
                   Some("true")
        );
    }
}
