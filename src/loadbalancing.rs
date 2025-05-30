use std::time::{Duration, Instant};

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use hyper::{Body, Client, Request, Response, Uri};
use hyper::body::to_bytes;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnectorBuilder;
use once_cell::sync::Lazy;
use thiserror::Error;
use tokio::time::timeout;

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
static LAST_GOOD_BACKEND: Lazy<DashMap<&'static str, (String, Instant)>> = Lazy::new(DashMap::new);

struct CooldownEntry {
    last_failed: Instant,
    failures: u32,
}

static BACKEND_COOLDOWN: Lazy<DashMap<String, CooldownEntry>> = Lazy::new(DashMap::new);

const BACKEND_CACHE_KEY: &str = "service";
const BACKEND_VALID_DURATION: Duration = Duration::from_secs(60);
const COOLDOWN_BASE: Duration = Duration::from_secs(30);
const COOLDOWN_MAX: Duration = Duration::from_secs(300);

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
    .pool_max_idle_per_host(200)
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

    if let Some((cached_backend, timestamp)) = LAST_GOOD_BACKEND.get(BACKEND_CACHE_KEY).map(|e| e.clone()) {
        if timestamp.elapsed() <= BACKEND_VALID_DURATION {
            if let Ok(resp) = try_forward_to_backend(&cached_backend, &body_bytes, &method, &uri, &headers).await {
                return Ok(resp);
            } else {
                tracing::warn!("Cached backend {} failed, falling back to full failover", cached_backend);
            }
        }
    }

    for backend in backends {
        if let Some(entry) = BACKEND_COOLDOWN.get(backend) {
            let delay = COOLDOWN_BASE * entry.failures.min(10);
            if delay > COOLDOWN_MAX {
                continue;
            }

            if entry.last_failed.elapsed() < delay {
                tracing::warn!(
                    "Skipping backend {} (cooldown active: {}s, failures: {})",
                               backend,
                               delay.as_secs(),
                               entry.failures
                );
                continue;
            }
        }

        if let Ok(resp) = try_forward_to_backend(backend, &body_bytes, &method, &uri, &headers).await {
            LAST_GOOD_BACKEND.insert(BACKEND_CACHE_KEY, (backend.clone(), Instant::now()));
            BACKEND_COOLDOWN.remove(backend);
            return Ok(resp);
        } else {
            BACKEND_COOLDOWN
            .entry(backend.clone())
            .and_modify(|e| {
                e.failures += 1;
                e.last_failed = Instant::now();
            })
            .or_insert(CooldownEntry {
                failures: 1,
                last_failed: Instant::now(),
            });
        }
    }

    Err(ForwardError::AllBackendsFailed)
}

async fn try_forward_to_backend(
    backend: &str,
    body_bytes: &[u8],
    method: &hyper::Method,
    uri: &Uri,
    headers: &hyper::HeaderMap,
) -> Result<Response<Body>, ForwardError> {
    let client = get_or_build_client(backend);
    let uri_backend: Uri = backend.parse().map_err(|_| ForwardError::AllBackendsFailed)?;

    let mut parts = uri.clone().into_parts();
    parts.scheme = uri_backend.scheme().cloned();
    parts.authority = uri_backend.authority().cloned();
    parts.path_and_query = uri_backend.path_and_query().cloned();

    let full_uri = Uri::from_parts(parts).map_err(|_| ForwardError::AllBackendsFailed)?;

    let mut builder = Request::builder()
    .method(method.clone())
    .uri(full_uri);

    for (key, value) in headers.iter() {
        builder = builder.header(key, value);
    }

    let new_req = builder
    .body(Body::from(body_bytes.to_vec()))
    .expect("Error building request");

    let response_result = timeout(Duration::from_secs(10), client.request(new_req)).await;

    match response_result {
        Ok(Ok(resp)) => Ok(resp),
        Ok(Err(e)) => {
            tracing::warn!("Failover: backend {} failed: {}", backend, e);
            Err(ForwardError::Hyper(e))
        }
        Err(_) => {
            tracing::warn!("Failover: backend {} timed out", backend);
            Err(ForwardError::AllBackendsFailed)
        }
    }
}
