use actix_web::{cookie::{Cookie, SameSite}, HttpRequest, HttpResponse, Responder, web, http::header};
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

pub async fn logout_session(req: HttpRequest) -> impl Responder {
    let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok());

    let mut resp = HttpResponse::Ok();

    if let Some(origin_value) = origin {
        resp.append_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_value));
        resp.append_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
        resp.append_header((header::ACCESS_CONTROL_ALLOW_HEADERS, "Authorization, Content-Type"));
        resp.append_header((header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS"));
        resp.append_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
    }

    let expired_cookie = Cookie::build("session_token", "")
    .path("/")
    .secure(true)
    .http_only(true)
    .same_site(SameSite::Strict)
    .max_age(time::Duration::seconds(0))
    .finish();

    resp.cookie(expired_cookie);
    resp.body("Session cookie cleared")
}
