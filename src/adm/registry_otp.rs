use crate::adm::method_otp::generate_otpauth_uri;
use crate::config::config::add_otpkey;
use crate::token::auth::verify_password;
use crate::AppState;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use totp_rs::Algorithm;

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

pub async fn get_otpauth_uri(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> impl Responder {
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

        return HttpResponse::Ok().json(OtpAuthUriResponse {
            otpauth_uri: uri,
            otpkey: otpkey.expect(""),
        });
    }

    HttpResponse::InternalServerError().body("OTP generation failed")
}
