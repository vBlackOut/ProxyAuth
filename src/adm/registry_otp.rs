use crate::AppState;
use crate::adm::method_otp::generate_otpauth_uri;
use crate::config::config::add_otpkey;
use crate::token::auth::{is_ip_allowed, verify_password};
use actix_web::{HttpRequest, HttpResponse, HttpResponseBuilder, http::header, Responder, web};
use serde::{Deserialize, Serialize};
use totp_rs::Algorithm;
use tracing::warn;

#[derive(Deserialize)]
pub struct OtpRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct OtpAuthUriResponse {
    pub otpauth_uri: String,
    pub otpkey: String,
}


pub async fn get_otpauth_uri_option(req: HttpRequest, data: web::Data<AppState>) -> impl actix_web::Responder {
    let origin_header = req.headers().get(header::ORIGIN);
    let origin = origin_header.and_then(|v| v.to_str().ok());

    let allowed = data.config.cors_origins.as_ref();

    let is_allowed = match (origin, allowed) {
        (Some(o), Some(list)) => {
            let origin_normalized = o.trim_end_matches('/');
            list.iter()
            .any(|allowed| allowed.trim_end_matches('/') == origin_normalized)
        }
        _ => false,
    };

    if let (Some(origin_str), true) = (origin, is_allowed) {
        HttpResponse::Ok()
        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str))
        .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS"))
        .insert_header((header::ACCESS_CONTROL_ALLOW_HEADERS, "Authorization, Content-Type, Accept"))
        .insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"))
        .finish()
    } else {
        HttpResponse::Forbidden().body("CORS origin not allowed")
    }
}

fn cors_response(mut resp: HttpResponseBuilder, req: &HttpRequest) -> HttpResponseBuilder {
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        if let Ok(origin_str) = origin.to_str() {
            if let Some(cors_origins) = &req.app_data::<web::Data<AppState>>()
                .and_then(|data| data.config.cors_origins.as_ref())
                {
                    let origin_clean = origin_str.trim_end_matches('/');
                    if cors_origins.iter().any(|o| o.trim_end_matches('/') == origin_clean) {
                        resp.append_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str));
                        resp.append_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
                        resp.append_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
                    }
                }
        }
    }
    resp
}

pub async fn get_otpauth_uri(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> impl Responder {
    let ip = req
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());

    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let auth: OtpRequest = if content_type.contains("application/json") {
        match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => return HttpResponse::BadRequest().body("Invalid JSON"),
        }
    } else if content_type.contains("x-www-form-urlencoded") {
        match serde_urlencoded::from_bytes(&body) {
            Ok(v) => v,
            Err(_) => return HttpResponse::BadRequest().body("Invalid form data"),
        }
    } else {
        return HttpResponse::UnsupportedMediaType().body("Unsupported content type");
    };

    let user = data
        .config
        .users
        .iter()
        .find(|u| u.username == auth.username && verify_password(&auth.password, &u.password));

    if user.is_none() {
        return HttpResponse::Unauthorized().body("Invalid username or password");
    }

    let user = user.unwrap();

    if !is_ip_allowed(&ip, user) {
        warn!(
            "[{}] Access denied: IP not allowed for user {}",
            ip, user.username
        );
        return HttpResponse::Forbidden()
            .append_header(("server", "ProxyAuth"))
            .body("Access denied");
    }

    if user.otpkey.is_none() {
        add_otpkey("/etc/proxyauth/config/config.json", &user.username);
    }

    let config_str = std::fs::read_to_string("/etc/proxyauth/config/config.json")
        .expect("Failed to reload updated config");

    let json: serde_json::Value =
        serde_json::from_str(&config_str).expect("Invalid JSON on reload");

    let otpkey = json
        .get("users")
        .and_then(|users| users.as_array())
        .and_then(|users| {
            users
                .iter()
                .find(|u| u.get("username").and_then(|n| n.as_str()) == Some(&auth.username))
        })
        .and_then(|u| u.get("otpkey").and_then(|v| v.as_str()))
        .map(|s| s.to_string());

    if let Some(ref secret) = otpkey {
        let uri = generate_otpauth_uri(
            &auth.username,
            "ProxyAuth",
            &secret,
            Algorithm::SHA512,
            6,
            30,
        );

        return cors_response(HttpResponse::Ok(), &req).json(OtpAuthUriResponse {
            otpauth_uri: uri,
            otpkey: otpkey.expect(""),
        });
    }

    HttpResponse::InternalServerError().body("OTP generation failed")
}
