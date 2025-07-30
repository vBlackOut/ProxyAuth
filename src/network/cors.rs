use std::task::{Context, Poll};
use actix_service::{Service, Transform};
use actix_web::http::header;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, SERVER};
use actix_web::{web, Error};
use futures_util::future::{ok, Ready, LocalBoxFuture};

use crate::AppState;

pub struct CorsMiddleware {
    pub config: web::Data<AppState>,
}

impl<S, B> Transform<S, ServiceRequest> for CorsMiddleware
where
S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
S::Future: 'static,
B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CorsMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CorsMiddlewareService {
            service,
            config: self.config.clone(),
        })
    }
}

pub struct CorsMiddlewareService<S> {
    service: S,
    config: web::Data<AppState>,
}

impl<S, B> Service<ServiceRequest> for CorsMiddlewareService<S>
where
S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
S::Future: 'static,
B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let config = self.config.clone();
        let origin = req
        .headers()
        .get("origin")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;

            if let Some(origin_str) = origin {
                if let Some(cors) = &config.config.cors_origins {
                    let origin_trimmed = origin_str.trim_end_matches('/').to_ascii_lowercase();
                    if cors.iter().any(|allowed| {
                        allowed.trim_end_matches('/').to_ascii_lowercase() == origin_trimmed
                    }) {
                        if let Ok(hval) = HeaderValue::from_str(&origin_str) {
                            res.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, hval);
                        }
                    }
                }
            }

            res.headers_mut()
                .insert(SERVER, HeaderValue::from_static("ProxyAuth"));
            res.headers_mut()
                .insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
            Ok(res)
        })
    }
}
