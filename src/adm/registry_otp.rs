use actix_web::{post, web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use crate::token::auth::verify_password;
use data_encoding::BASE64;
use crate::adm::method_otp::generate_otpauth_uri;
use crate::token::crypto::decrypt_base64;
use totp_rs::Algorithm;
use crate::AppState;

#[derive(Deserialize)]
pub struct OtpRequest {
    pub username: String,
    pub password: String,
}


#[derive(Serialize)]
pub struct OtpAuthUriResponse {
    pub otpauth_uri: String,
}

#[post("/adm/auth/totp/get")]
async fn get_otpauth_uri(
    _req: HttpRequest,
    auth: web::Json<OtpRequest>,
    data: web::Data<AppState>,
) -> impl Responder {

    if let Some(user) = data
        .config
        .users
        .iter()
        .find(|u| u.username == auth.username && verify_password(&auth.password, &u.password))
        {
            if let Some(otpkey_enc) = &user.otpkey {
                let otpkey_b64 = BASE64.encode(otpkey_enc);
                let otp_secret = decrypt_base64(&otpkey_b64, &auth.password);

                let uri = generate_otpauth_uri(
                    &user.username,
                    "ProxyAuth",
                    &otp_secret,
                    Algorithm::SHA512,
                    6,
                    30,
                );

                return HttpResponse::Ok().json(OtpAuthUriResponse {
                    otpauth_uri: uri,
                });
            } else {
                return HttpResponse::BadRequest().body("OTP key not set");
            }
        }

        HttpResponse::Unauthorized().body("Invalid username or password")
}
