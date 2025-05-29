use dashmap::DashMap;
use fxhash::FxBuildHasher;
use once_cell::sync::Lazy;
use thiserror::Error;
use hyper::{Body, Client, Request, Response, Uri};
use hyper::body::to_bytes;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnectorBuilder;
use tokio::time::{timeout, Duration};

#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("503 Service Unavailable")]
    AllBackendsFailed,

    #[error(transparent)]
    Hyper(#[from] hyper::Error),
}



type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>>;
type FxDashMap<K, V> = DashMap<K, V, FxBuildHasher>;

static CLIENT_POOL: Lazy<FxDashMap<String, HttpsClient>> = Lazy::new(FxDashMap::default);


fn get_or_build_client(backend: &str) -> HttpsClient {
    if let Some(client) = CLIENT_POOL.get(backend) {
        return client.clone();
    }

    let https = HttpsConnectorBuilder::new()
    .with_native_roots()
    .https_or_http()
    .enable_http1()
    .build();

    let client = Client::builder()
    .pool_max_idle_per_host(64)
    .build::<_, Body>(https);

    CLIENT_POOL.insert(backend.to_string(), client.clone());
    client
}

pub async fn forward_failover(
    req: Request<Body>,
    backends: &[String],
) -> Result<Response<Body>, ForwardError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body_bytes = to_bytes(req.into_body()).await?;

    for backend in backends {
        let client = get_or_build_client(backend);
        let uri_backend: Uri = backend.parse().expect("Invalid backend URI");

        let mut parts = uri.clone().into_parts();
        parts.scheme = uri_backend.scheme().cloned();
        parts.authority = uri_backend.authority().cloned();
        parts.path_and_query = uri_backend.path_and_query().cloned();

        let full_uri = Uri::from_parts(parts).expect("Invalid full URI");

        let mut builder = Request::builder()
        .method(method.clone())
        .uri(full_uri);

        for (key, value) in headers.iter() {
            builder = builder.header(key, value);
        }

        let new_req = builder
        .body(Body::from(body_bytes.clone()))
        .expect("Error building request");

        let response_result = timeout(Duration::from_millis(10000), client.request(new_req)).await;

        match response_result {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(e)) => {
                tracing::warn!("Failover: backend {} failed: {}", backend, e);
                continue;
            }
            Err(_) => {
                tracing::warn!("Failover: backend {} timed out", backend);
                continue;
            }
        }
    }

    Err(ForwardError::AllBackendsFailed)
}
