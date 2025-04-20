use crate::crypto::{calcul_cipher, derive_key_from_secret, encrypt};
use crate::proxy::client_ip;
use crate::security::generate_token;
use crate::AppState;
use crate::AuthRequest;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::{Duration, Utc};
use chrono_tz::Europe::Paris;
use tracing::{info, warn};

pub async fn refresh_token(
    req: HttpRequest,
    auth: web::Json<AuthRequest>,
    data: web::Data<AppState>,
) -> impl Responder {

    let ip = client_ip(&req).expect("?").to_string();

    if let Some(index_user) = data
        .config
        .users
        .iter()
        .enumerate()
        .find(|(_, user)| user.username == auth.username && user.password == auth.password)
        .map(|(i, _)| i)
    {
        let user = &data.config.users[index_user];

        let now = Utc::now();
        let fr_time = now.with_timezone(&Paris);
        let expiry = fr_time + Duration::seconds(data.config.token_expiry_seconds);

        let token = generate_token(
            &auth.username,
            &data.config.secret,
            &expiry.timestamp().to_string(),
        );

        let key = derive_key_from_secret(&data.config.secret);

        let cipher_token = format!(
            "{}|{}|{}",
            calcul_cipher(token.clone()),
            expiry.timestamp(),
            index_user,
        );

        let token_encrypt = encrypt(&cipher_token, &key);
        let expires_at_str = expiry.format("%Y-%m-%d %H:%M:%S").to_string();

        info!(
            "[{}] new token generated for user {} expirated at {}",
            ip, user.username, expires_at_str
        );
        HttpResponse::Ok().json(serde_json::json!({
            "token": token_encrypt,
            "expires_at": expires_at_str,
        }))
    } else {
        warn!("Invalid credential for enter user {}.", auth.username);
        HttpResponse::Unauthorized().body("Invalid credentials")
    }
}
