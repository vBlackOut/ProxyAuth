use std::time::{Duration, Instant};

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use hyper::{Body, Client, Request, Response, Uri, Method};
use hyper::body::to_bytes;
use hyper_proxy::{Proxy, ProxyConnector, Intercept};
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

type FxDashMap<K, V> = DashMap<K, V, FxBuildHasher>;
type DefaultClient = Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>, Body>;
type ProxyClient = Client<ProxyConnector<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>, Body>;

static CLIENT_POOL: Lazy<FxDashMap<String, DefaultClient>> = Lazy::new(FxDashMap::default);
static PROXY_CLIENT_POOL: Lazy<FxDashMap<(String, String), ProxyClient>> = Lazy::new(FxDashMap::default);
static LAST_GOOD_BACKEND: Lazy<FxDashMap<&'static str, (String, Instant)>> = Lazy::new(FxDashMap::default);
static BACKEND_COOLDOWN: Lazy<FxDashMap<String, CooldownEntry>> = Lazy::new(FxDashMap::default);

struct CooldownEntry {
    last_failed: Instant,
    failures: u32,
}

const BACKEND_CACHE_KEY: &str = "service";
const BACKEND_VALID_DURATION: Duration = Duration::from_secs(60);
const COOLDOWN_BASE: Duration = Duration::from_secs(30);
const COOLDOWN_MAX: Duration = Duration::from_secs(300);

async fn get_or_build_client(backend: &str) -> DefaultClient {
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

async fn get_or_build_client_with_proxy(proxy_addr: &str, backend: &str) -> ProxyClient {
    let key = (proxy_addr.to_string(), backend.to_string());

    if let Some(client) = PROXY_CLIENT_POOL.get(&key) {
        return client.clone();
    }

    let proxy_uri: Uri = proxy_addr.parse().expect("Invalid proxy URI");
    let proxy = Proxy::new(Intercept::All, proxy_uri);

    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();

    let proxy_connector = ProxyConnector::from_proxy(https, proxy)
        .expect("Failed to create proxy connector");

    let client = Client::builder()
        .pool_max_idle_per_host(200)
        .build(proxy_connector);

    PROXY_CLIENT_POOL.insert(key, client.clone());
    client
}

pub async fn forward_failover(
    req: Request<Body>,
    backends: &[String],
    proxy_addr: Option<&str>,
) -> Result<Response<Body>, ForwardError> {

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body_bytes = to_bytes(req.into_body()).await?;

    if let Some((cached_backend, timestamp)) = LAST_GOOD_BACKEND.get(BACKEND_CACHE_KEY).map(|e| e.clone()) {
        if timestamp.elapsed() <= BACKEND_VALID_DURATION {
            if let Ok(resp) = try_forward_to_backend(&cached_backend, proxy_addr, &body_bytes, &method, &uri, &headers).await {
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

        if let Ok(resp) = try_forward_to_backend(backend, proxy_addr, &body_bytes, &method, &uri, &headers).await {
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
    proxy_addr: Option<&str>,
    body_bytes: &[u8],
    method: &hyper::Method,
    uri: &Uri,
    headers: &hyper::HeaderMap,
) -> Result<Response<Body>, ForwardError> {
    let uri_backend: Uri = backend.parse().map_err(|_| ForwardError::AllBackendsFailed)?;

    let mut parts = uri.clone().into_parts();
    parts.scheme = uri_backend.scheme().cloned();
    parts.authority = uri_backend.authority().cloned();
    parts.path_and_query = uri.path_and_query().cloned();

    let full_uri = Uri::from_parts(parts).map_err(|_| ForwardError::AllBackendsFailed)?;

    let mut builder = Request::builder()
    .method(method.clone())
    .uri(full_uri);

    for (key, value) in headers.iter() {
        if key.as_str().to_ascii_lowercase() != "host" {
            builder = builder.header(key, value);
        }
    }

    builder = builder.header("Host", uri_backend.authority().map(|a| a.as_str()).unwrap_or("127.0.0.1"));

    let new_req = if *method == Method::GET || *method == Method::HEAD {
        builder.body(Body::empty()).expect("Failed to build GET/HEAD request")
    } else {
        builder.body(Body::from(body_bytes.to_vec())).expect("Failed to build request with body")
    };

    let response_result = match proxy_addr {
        Some(proxy) => {
            let client = get_or_build_client_with_proxy(proxy, backend).await;
            timeout(Duration::from_secs(10), client.request(new_req)).await
        },
        None => {
            let client = get_or_build_client(backend).await;
            timeout(Duration::from_secs(10), client.request(new_req)).await
        }
    };

    match response_result {
        Ok(Ok(resp)) => {
            if resp.status().is_success() {
                Ok(resp)
            } else {
                tracing::warn!(
                    "Failover: backend {} returned non-success status {}",
                    backend,
                    resp.status()
                );
                Err(ForwardError::AllBackendsFailed) // Forcer le failover
            }
        }
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
