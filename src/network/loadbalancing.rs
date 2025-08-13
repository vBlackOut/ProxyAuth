use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::config::config::BackendConfig;
use crate::network::config::{LB_TUNING, LbTuning};
use ahash::{AHashSet, RandomState};
use dashmap::DashMap;
use hyper::body::to_bytes;
use hyper::client::HttpConnector;
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

type AHasherDashMap<K, V> = DashMap<K, V, RandomState>;

type ArcClient = Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>>;
type ClientPool = DashMap<String, ArcClient, RandomState>;
static CLIENT_POOL: Lazy<ClientPool> = Lazy::new(ClientPool::default);

type ProxyArcClient = Arc<Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body>>;
type ProxyClientPool = DashMap<(String, String), ProxyArcClient, RandomState>;
static PROXY_CLIENT_POOL: Lazy<ProxyClientPool> = Lazy::new(ProxyClientPool::default);

static LAST_GOOD_BACKEND: Lazy<AHasherDashMap<&'static str, (String, Instant)>> =
Lazy::new(Default::default);
static BACKEND_COOLDOWN: Lazy<AHasherDashMap<String, CooldownEntry>> =
Lazy::new(Default::default);
static ROUND_ROBIN_COUNTER: Lazy<AtomicUsize> =
Lazy::new(|| AtomicUsize::new(0));

const BACKEND_CACHE_KEY: &str = "service";

struct CooldownEntry {
    last_failed: Instant,
    failures: u32,
}

fn lb() -> &'static LbTuning {
    LB_TUNING.get().unwrap_or(&LbTuning {
        request_timeout_ms: 1500,
        pool_max_idle_per_host: 1000,
        keep_alive_secs: 30,
        backend_valid_duration_secs: 10,
        cooldown_base_secs: 5,
        cooldown_max_secs: 10,
        backend_reset_threshold_secs: 5,
    })
}

fn backend_valid_duration() -> Duration {
    Duration::from_secs(lb().backend_valid_duration_secs)
}
fn cooldown_base() -> Duration {
    Duration::from_secs(lb().cooldown_base_secs)
}
fn cooldown_max() -> Duration {
    Duration::from_secs(lb().cooldown_max_secs)
}
fn backend_reset_threshold() -> Duration {
    Duration::from_secs(lb().backend_reset_threshold_secs)
}

// --------- Cooldown helper ---------
fn is_in_cooldown(url: &str) -> bool {
    if let Some(entry) = BACKEND_COOLDOWN.get(url) {
        let mut delay = cooldown_base() * entry.failures.min(10);
        if delay > cooldown_max() {
            delay = cooldown_max();
        }
        return entry.last_failed.elapsed() < delay;
    }
    false
}

#[derive(Clone, Copy, Debug)]
struct SwrrState {
    effective: i32,
    current: i32,
}

static SWRR_STATE: Lazy<DashMap<String, SwrrState, RandomState>> =
Lazy::new(Default::default);

fn build_swrr_order<'a>(cands: &[&'a BackendConfig]) -> Vec<&'a BackendConfig> {
    if cands.is_empty() {
        return Vec::new();
    }

    let mut unique = AHashSet::default();
    let mut total_weight: i32 = 0;
    for b in cands {
        let w = b.weight.max(1) as i32;
        total_weight += w;
        unique.insert(b.url.clone());
        SWRR_STATE
        .entry(b.url.clone())
        .and_modify(|st| st.effective = w)
        .or_insert(SwrrState { effective: w, current: 0 });
    }

    let mut order = Vec::with_capacity(unique.len());
    let mut picked = AHashSet::default();

    for _ in 0..unique.len() {
        let mut best_idx: Option<usize> = None;
        let mut best_val: i32 = i32::MIN;

        for (i, b) in cands.iter().enumerate() {
            if picked.contains(&b.url) {
                continue;
            }
            if let Some(mut st) = SWRR_STATE.get_mut(&b.url) {
                st.current += st.effective;
                if st.current > best_val {
                    best_val = st.current;
                    best_idx = Some(i);
                }
            }
        }

        if let Some(i) = best_idx {
            let chosen = cands[i];
            if let Some(mut st) = SWRR_STATE.get_mut(&chosen.url) {
                st.current -= total_weight;
            }
            picked.insert(chosen.url.clone());
            order.push(chosen);
        } else {
            break;
        }
    }

    let len = order.len();
    if len > 0 {
        let shift = ROUND_ROBIN_COUNTER.fetch_add(1, Ordering::Relaxed) % len;
        if shift != 0 {
            order.rotate_left(shift);
        }
    }

    order
}

async fn get_or_build_client(backend: &str) -> ArcClient {
    let key = backend.trim().to_lowercase();
    if let Some(client) = CLIENT_POOL.get(&key) {
        return Arc::clone(&client);
    }

    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_reuse_address(true);
    connector.set_keepalive(Some(Duration::from_secs(lb().keep_alive_secs)));

    let https = HttpsConnectorBuilder::new()
    .with_native_roots()
    .https_or_http()
    .enable_http1()
    .wrap_connector(connector);

    let client = Client::builder()
    .pool_max_idle_per_host(lb().pool_max_idle_per_host)
    .build::<_, Body>(https);

    let arc_client = Arc::new(client);
    CLIENT_POOL.insert(key, Arc::clone(&arc_client));
    arc_client
}

async fn get_or_build_client_with_proxy(proxy_addr: &str, backend: &str) -> ProxyArcClient {
    let key = (proxy_addr.to_string(), backend.to_string());
    if let Some(client) = PROXY_CLIENT_POOL.get(&key) {
        return Arc::clone(&client);
    }

    let proxy_uri: Uri = proxy_addr.parse().expect("Invalid proxy URI");
    let proxy = Proxy::new(Intercept::All, proxy_uri);

    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_reuse_address(true);
    connector.set_keepalive(Some(Duration::from_secs(lb().keep_alive_secs)));

    let https = HttpsConnectorBuilder::new()
    .with_native_roots()
    .https_or_http()
    .enable_http1()
    .wrap_connector(connector);

    let proxy_connector =
    ProxyConnector::from_proxy(https, proxy).expect("Failed to create proxy connector");

    let client = Client::builder()
    .pool_max_idle_per_host(lb().pool_max_idle_per_host)
    .build(proxy_connector);

    let arc_client = Arc::new(client);
    PROXY_CLIENT_POOL.insert(key, Arc::clone(&arc_client));
    arc_client
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

    // Purge soft des cooldowns
    let now = Instant::now();
    BACKEND_COOLDOWN.retain(|_, entry| now.duration_since(entry.last_failed) < backend_reset_threshold());

    if let Some((cached_url, when)) = LAST_GOOD_BACKEND.get(BACKEND_CACHE_KEY).map(|e| e.clone()) {
        if when.elapsed() <= backend_valid_duration() && !is_in_cooldown(&cached_url) {
            match try_forward_to_backend(&cached_url, proxy_addr, &body_bytes, &method, &uri, &headers).await {
                Ok(resp) => return Ok(resp),
                Err(_) => {
                    BACKEND_COOLDOWN
                    .entry(cached_url.clone())
                    .and_modify(|e| { e.failures += 1; e.last_failed = Instant::now(); })
                    .or_insert(CooldownEntry { failures: 1, last_failed: Instant::now() });
                }
            }
        }
    }

    let active: Vec<&BackendConfig> = backends.iter().filter(|b| b.weight != -1).collect();
    let disabled: Vec<&BackendConfig> = backends.iter().filter(|b| b.weight == -1).collect();

    let order_active = build_swrr_order(&active);

    let mut already_checked = AHashSet::default();

    if let Some(resp) = try_backends(
        &order_active,
        &mut already_checked,
        &body_bytes,
        &method,
        &uri,
        &headers,
        proxy_addr,
    ).await {
        return Ok(resp);
    }

    if let Some(resp) = try_backends(
        &disabled,
        &mut already_checked,
        &body_bytes,
        &method,
        &uri,
        &headers,
        proxy_addr,
    ).await {
        return Ok(resp);
    }

    Err(ForwardError::AllBackendsFailed)
}

async fn try_backends(
    backends: &[&BackendConfig],
    already_checked: &mut AHashSet<String>,
    body_bytes: &[u8],
    method: &Method,
    uri: &Uri,
    headers: &hyper::HeaderMap,
    proxy_addr: Option<&str>,
) -> Option<Response<Body>> {
    for backend in backends {
        let url = &backend.url;

        if !already_checked.insert(url.clone()) {
            continue;
        }

        if is_in_cooldown(url) {
            tracing::warn!("Skipping backend {} (cooldown active)", url);
            continue;
        }

        match try_forward_to_backend(url, proxy_addr, body_bytes, method, uri, headers).await {
            Ok(resp) => {
                LAST_GOOD_BACKEND.insert(BACKEND_CACHE_KEY, (url.clone(), Instant::now()));
                BACKEND_COOLDOWN.remove(url);
                return Some(resp);
            }
            Err(_) => {
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
    }
    None
}

async fn try_forward_to_backend(
    backend: &str,
    proxy_addr: Option<&str>,
    body_bytes: &[u8],
    method: &Method,
    uri: &Uri,
    headers: &hyper::HeaderMap,
) -> Result<Response<Body>, ForwardError> {
    let uri_backend: Uri = backend.parse().map_err(|_| ForwardError::AllBackendsFailed)?;

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
        builder.body(Body::empty()).expect("Failed to build GET/HEAD request")
    } else {
        builder.body(Body::from(body_bytes.to_vec())).expect("Failed to build request with body")
    };

    let response_result = match proxy_addr {
        Some(proxy) => {
            let client = get_or_build_client_with_proxy(proxy, backend).await;
            timeout(Duration::from_millis(lb().request_timeout_ms), client.request(new_req)).await
        }
        None => {
            let client = get_or_build_client(backend).await;
            timeout(Duration::from_millis(lb().request_timeout_ms), client.request(new_req)).await
        }
    };

    match response_result {
        Ok(Ok(resp)) if resp.status().is_success() => Ok(resp),
        Ok(Ok(resp)) => {
            tracing::warn!(
                "Failover: backend {} returned non-success status {}",
                backend,
                resp.status()
            );
            Err(ForwardError::AllBackendsFailed)
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
