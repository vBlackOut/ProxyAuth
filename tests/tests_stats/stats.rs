use proxyauth::stats::stats::stats;
use proxyauth::AppState;
use proxyauth::CounterToken;
use proxyauth::AppConfig;
use proxyauth::RouteConfig;

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, http::header, HttpResponse, Responder, web};
    use std::sync::Arc;
    use dashmap::DashMap;
    use hyper::{Body, Client, client::HttpConnector};
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_proxy::ProxyConnector;
    use hyper_proxy::Proxy;
    use hyper_proxy::Intercept;


    type RoutesWrapper = RouteConfig;

    fn dummy_https_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
        Client::builder().build::<_, Body>(https)
    }

    fn dummy_proxy_client(
    ) -> Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);

        let proxy = Proxy::new(Intercept::None, "http://127.0.0.1:8888".parse().unwrap());
        let px = ProxyConnector::from_proxy(https, proxy).expect("proxy connector");
        Client::builder().build(px)
    }


    fn make_state(stats_enabled: bool) -> web::Data<AppState> {
        let mut cfg = AppConfig::default();
        cfg.stats = stats_enabled;
        cfg.token_admin = "adm-token".to_string();

        let routes = Arc::new(RoutesWrapper { routes: vec![] });

        let counter = Arc::new(CounterToken::new());
        let revoked_tokens = Arc::new(DashMap::<String, u64>::new());

        let client_normal     = dummy_https_client();
        let client_with_cert  = dummy_https_client();
        let client_with_proxy = dummy_proxy_client();

        web::Data::new(AppState {
            config: Arc::new(cfg),
                       routes,
                       counter,
                       client_normal,
                       client_with_cert,
                       client_with_proxy,
                       revoked_tokens,
        })
    }

    #[actix_web::test]
    async fn stats_returns_200_json_when_enabled_and_token_ok() {
        let state = make_state(true);

        let req = test::TestRequest::default()
        .insert_header(("X-Auth-Token", "adm-token"))
        .to_http_request();

        let resp_impl = super::stats(req, state).await;
        let resp: HttpResponse = resp_impl
        .respond_to(&test::TestRequest::default().to_http_request())
        .map_into_boxed_body();

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
                   "application/json"
        );
    }

    #[actix_web::test]
    async fn stats_returns_401_on_missing_or_bad_token() {
        let state = make_state(true);

        let req_no_hdr = test::TestRequest::default().to_http_request();
        let resp_impl1 = super::stats(req_no_hdr, state.clone()).await;
        let resp1: HttpResponse = resp_impl1
        .respond_to(&test::TestRequest::default().to_http_request())
        .map_into_boxed_body();
        assert_eq!(resp1.status(), actix_web::http::StatusCode::UNAUTHORIZED);

        let req_bad = test::TestRequest::default()
        .insert_header(("X-Auth-Token", "wrong"))
        .to_http_request();
        let resp_impl2 = super::stats(req_bad, state).await;
        let resp2: HttpResponse = resp_impl2
        .respond_to(&test::TestRequest::default().to_http_request())
        .map_into_boxed_body();
        assert_eq!(resp2.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn stats_returns_message_when_feature_disabled() {
        let state = make_state(false);

        let req = test::TestRequest::default()
        .insert_header(("X-Auth-Token", "adm-token"))
        .to_http_request();

        let resp_impl = super::stats(req, state).await;
        let resp: HttpResponse = resp_impl
        .respond_to(&test::TestRequest::default().to_http_request())
        .map_into_boxed_body();

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body_bytes = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        assert!(body_str.contains("Stats is disabled"));
    }
}
