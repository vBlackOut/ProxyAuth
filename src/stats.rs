use actix_web::{web, HttpResponse, Responder};
use crate::AppState;

pub async fn stats(data: web::Data<AppState>) -> impl Responder {
    let stats = data.counter.lock().unwrap().get_all_tokens_json();
    let json = serde_json::to_string_pretty(&stats).unwrap();
    HttpResponse::Ok()
        .content_type("application/json")
        .body(json)
}
