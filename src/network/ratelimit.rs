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
