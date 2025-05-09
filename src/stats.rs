use actix_web::{HttpRequest, HttpResponse, web, Responder};
use crate::AppState;


pub async fn stats(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {

    let expected_token = &data.config.token_admin;
    let auth_header = req.headers().get("X-Auth-Token");

    match auth_header {
        Some(token) if *token == *expected_token => {
            let stats = data.counter.lock().unwrap().get_all_tokens_json();
            let json = serde_json::to_string_pretty(&stats).unwrap();
            HttpResponse::Ok()
            .content_type("application/json")
            .body(json)
        }
        _ => HttpResponse::Unauthorized().body("Invalid or missing token"),
    }
}
