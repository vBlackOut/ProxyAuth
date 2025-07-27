use actix_web::{HttpRequest, HttpResponse, Responder, web};
use serde::Deserialize;

use crate::AppState;
use crate::revoke::load::revoke_token;

#[derive(Deserialize)]
pub struct RevokeRequest {
    pub token_id: String,
    pub exp: Option<u64>,
}

pub async fn revoke_route(
    req: HttpRequest,
    data: web::Data<AppState>,
    body: web::Json<RevokeRequest>,
) -> impl Responder {
    let expected_token = &data.config.token_admin;
    let auth_header = req.headers().get("X-Auth-Token");

    match auth_header {
        Some(token) if *token == *expected_token => {
            let token_id = &body.token_id;
            let exp = body.exp;

            match revoke_token(token_id, exp, &data.revoked_tokens).await {
                Ok(_) => {
                    if exp.is_some() {
                        HttpResponse::Ok().body("Token revoked with expiration.")
                    } else {
                        HttpResponse::Ok().body("Token permanently revoked.")
                    }
                }
                Err(e) => {
                    eprintln!("[revoke_route] Failed to revoke token: {}", e);
                    HttpResponse::InternalServerError().body("Failed to revoke token.")
                }
            }
        }
        _ => HttpResponse::Unauthorized().body("Invalid or missing token"),
    }
}
