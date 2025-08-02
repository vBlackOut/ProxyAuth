use actix_web::{HttpRequest, HttpResponse, web, http::header,  http::header::ContentType};
use time::{OffsetDateTime, format_description::well_known::Rfc2822};
use crate::AppState;

pub async fn logout_options(req: HttpRequest, data: web::Data<AppState>) -> impl actix_web::Responder {
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


pub async fn logout_session(
    req: HttpRequest,
    data: web::Data<AppState>,
) -> HttpResponse {
    let expires_str = OffsetDateTime::UNIX_EPOCH
    .format(&Rfc2822)
    .unwrap();

    let raw_cookie = format!(
        "session_token=; Expires={}; Path=/; HttpOnly; Secure; SameSite=Strict",
        expires_str
    );

    let mut resp = if let Some(url) = &data.config.logout_redirect_url {
        if !url.is_empty() {
            let mut r = HttpResponse::Found();
            r.insert_header((header::LOCATION, url.as_str()));
            r
        } else {
            HttpResponse::Ok()
        }
    } else {
        HttpResponse::Ok()
    };

    resp.insert_header((header::SET_COOKIE, raw_cookie));
    resp.insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));

    if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
    }

    if data.config.logout_redirect_url.as_ref().map_or(true, |s| s.is_empty()) {
        resp.insert_header(ContentType::plaintext());
        resp.body("Session cookie cleared")
    } else {
        resp.finish()
    }
}
