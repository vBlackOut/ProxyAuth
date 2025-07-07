use crate::AppState;
use crate::network::ratelimit::governor::clock::DefaultClock;
use crate::token::security::extract_token_user;
use actix_governor::governor::clock::Clock;
use actix_governor::{KeyExtractor, SimpleKeyExtractionError, governor};
use actix_web::dev::ServiceRequest;
use actix_web::http::StatusCode;
use actix_web::http::header::ContentType;
use actix_web::web;
use actix_web::{HttpResponse, HttpResponseBuilder};
use std::net::IpAddr;

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
            .and_then(|token| extract_token_user(token, &app_data.config, ip.clone()).ok())
            .unwrap_or_else(|| ip.clone());

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
