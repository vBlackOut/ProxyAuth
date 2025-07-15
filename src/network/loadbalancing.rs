use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::AppConfig;
use crate::config::config::BackendConfig;
use ahash::{AHashMap, AHashSet, RandomState};
use dashmap::DashMap;
use hyper::body::to_bytes;
use hyper::{Body, Client, Method, Request, Response, Uri};
use hyper_proxy::{Intercept, Proxy, ProxyConnector};
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

#[allow(dead_code)]
pub fn load_config(path: &str) -> AppConfig {
    let content = fs::read_to_string(path).expect("Cannot read config file");
    serde_yaml::from_str(&content).expect("Invalid YAML format")
}

type AHasherDashMap<K, V> = DashMap<K, V, RandomState>;
type DefaultClient = Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>, Body>;
type ProxyClient =
    Client<ProxyConnector<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>, Body>;

static CLIENT_POOL: Lazy<AHasherDashMap<String, DefaultClient>> = Lazy::new(Default::default);
static PROXY_CLIENT_POOL: Lazy<AHasherDashMap<(String, String), ProxyClient>> = Lazy::new(Default::default);
static LAST_GOOD_BACKEND: Lazy<AHasherDashMap<&'static str, (String, Instant)>> = Lazy::new(Default::default);
static BACKEND_COOLDOWN: Lazy<AHasherDashMap<String, CooldownEntry>> = Lazy::new(Default::default);
static ROUND_ROBIN_COUNTER: Lazy<AtomicUsize> = Lazy::new(|| AtomicUsize::new(0));

struct CooldownEntry {
    last_failed: Instant,
    failures: u32,
}

const BACKEND_CACHE_KEY: &str = "service";
#[allow(dead_code)]
const BACKEND_VALID_DURATION: Duration = Duration::from_secs(3);
const COOLDOWN_BASE: Duration = Duration::from_secs(5);
const COOLDOWN_MAX: Duration = Duration::from_secs(10);
const BACKEND_RESET_THRESHOLD: Duration = Duration::from_secs(5);

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

    let proxy_connector =
        ProxyConnector::from_proxy(https, proxy).expect("Failed to create proxy connector");

    let client = Client::builder()
        .pool_max_idle_per_host(200)
        .build(proxy_connector);

    PROXY_CLIENT_POOL.insert(key, client.clone());
    client
}

pub async fn forward_failover(
    req: Request<Body>,
    backends: &[BackendConfig],
    proxy_addr: Option<&str>,
) -> Result<Response<Body>, ForwardError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let body_bytes = to_bytes(req.into_body()).await?;

    let now = Instant::now();
    BACKEND_COOLDOWN
        .retain(|_, entry| now.duration_since(entry.last_failed) < BACKEND_RESET_THRESHOLD);

    let (active_backends, disabled_backends): (Vec<_>, Vec<_>) =
        backends.iter().partition(|b| b.weight != -1);

    let mut weighted_backends: Vec<&BackendConfig> = Vec::new();
    for backend in &active_backends {
        for _ in 0..backend.weight.max(1) {
            weighted_backends.push(backend);
        }
    }

    let start_index = ROUND_ROBIN_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut already_checked = AHashSet::with_capacity(backends.len());

    for i in 0..weighted_backends.len() {
        let index = (start_index + i) % weighted_backends.len();
        let backend = weighted_backends[index];
        let url = &backend.url;

        if !already_checked.insert(url.clone()) {
            continue;
        }

        if let Some(entry) = BACKEND_COOLDOWN.get(url) {
            let delay = COOLDOWN_BASE * entry.failures.min(10);
            if delay > COOLDOWN_MAX || entry.last_failed.elapsed() < delay {
                tracing::warn!(
                    "Skipping backend {} (cooldown: {}s, failures: {})",
                    url,
                    delay.as_secs(),
                    entry.failures
                );
                continue;
            }
        }

        if let Ok(resp) =
            try_forward_to_backend(url, proxy_addr, &body_bytes, &method, &uri, &headers).await
        {
            LAST_GOOD_BACKEND.insert(BACKEND_CACHE_KEY, (url.clone(), Instant::now()));
            BACKEND_COOLDOWN.remove(url);
            return Ok(resp);
        } else {
            BACKEND_COOLDOWN
                .entry(url.clone())
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

    for backend in &disabled_backends {
        let url = &backend.url;

        if !already_checked.insert(url.clone()) {
            continue;
        }

        if let Some(entry) = BACKEND_COOLDOWN.get(url) {
            let delay = COOLDOWN_BASE * entry.failures.min(10);
            if delay > COOLDOWN_MAX || entry.last_failed.elapsed() < delay {
                tracing::warn!(
                    "Skipping disabled fallback backend {} (cooldown: {}s, failures: {})",
                    url,
                    delay.as_secs(),
                    entry.failures
                );
                continue;
            }
        }

        if let Ok(resp) =
            try_forward_to_backend(url, proxy_addr, &body_bytes, &method, &uri, &headers).await
        {
            tracing::warn!("Using disabled backend {} as fallback", url);
            LAST_GOOD_BACKEND.insert(BACKEND_CACHE_KEY, (url.clone(), Instant::now()));
            BACKEND_COOLDOWN.remove(url);
            return Ok(resp);
        } else {
            BACKEND_COOLDOWN
                .entry(url.clone())
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
    let uri_backend: Uri = backend
        .parse()
        .map_err(|_| ForwardError::AllBackendsFailed)?;

    let mut parts = uri.clone().into_parts();
    parts.scheme = uri_backend.scheme().cloned();
    parts.authority = uri_backend.authority().cloned();
    parts.path_and_query = uri.path_and_query().cloned();

    let full_uri = Uri::from_parts(parts).map_err(|_| ForwardError::AllBackendsFailed)?;

    let mut builder = Request::builder().method(method.clone()).uri(full_uri);

    for (key, value) in headers.iter() {
        if key.as_str().to_ascii_lowercase() != "host" {
            builder = builder.header(key, value);
        }
    }

    builder = builder.header(
        "Host",
        uri_backend
            .authority()
            .map(|a| a.as_str())
            .unwrap_or("127.0.0.1"),
    );

    let new_req = if *method == Method::GET || *method == Method::HEAD {
        builder
            .body(Body::empty())
            .expect("Failed to build GET/HEAD request")
    } else {
        builder
            .body(Body::from(body_bytes.to_vec()))
            .expect("Failed to build request with body")
    };

    let response_result = match proxy_addr {
        Some(proxy) => {
            let client = get_or_build_client_with_proxy(proxy, backend).await;
            timeout(Duration::from_secs(10), client.request(new_req)).await
        }
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
                Err(ForwardError::AllBackendsFailed)
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
