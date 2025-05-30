use hyper::{Client, client::HttpConnector, Body};
use hyper_rustls::HttpsConnector;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{fs::File, io::BufReader};
use hyper_proxy::{Proxy, ProxyConnector, Intercept};
use dashmap::DashMap;
use crate::config::AppConfig;
use std::time::{Duration, Instant};
use std::str::FromStr;
use once_cell::sync::Lazy;
use fxhash::FxBuildHasher;

type FastDashMap<K, V> = DashMap<K, V, FxBuildHasher>;

fn cleanup_expired_clients() {
    let now = Instant::now();

    // Nettoyage CLIENT_CACHE
    let expired: Vec<_> = CLIENT_CACHE
    .iter()
    .filter_map(|entry| {
        if now.duration_since(entry.inserted) >= TTL {
            Some(entry.key().clone())
        } else {
            None
        }
    })
    .collect();

    for key in &expired {
        CLIENT_CACHE.remove(&key);
    }

    // Nettoyage CLIENT_CACHE_PROXY
    let expired_proxy: Vec<_> = CLIENT_CACHE_PROXY
    .iter()
    .filter_map(|entry| {
        if now.duration_since(entry.inserted) >= TTL {
            Some(entry.key().clone())
        } else {
            None
        }
    })
    .collect();

    for key in &expired_proxy {
        CLIENT_CACHE_PROXY.remove(&key);
    }

    tracing::debug!(
        "Cleaned expired clients: {} (normal) + {} (proxy)",
                    &expired.len(),
                    &expired_proxy.len()
    );
}

pub fn spawn_client_cache_cleanup_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_expired_clients();
        }
    });
}

#[allow(dead_code)]
type HttpsClient = Client<HttpsConnector<HttpConnector>>;
type ProxyClient = Client<ProxyConnector<HttpsConnector<HttpConnector>>>;

const MAX_CLIENTS: usize = 10000;
const TTL: Duration = Duration::from_secs(60); // 10 seconds per client

#[derive(Clone)]
struct TimedValue<T> {
    inserted: Instant,
    value: T,
}

static CLIENT_CACHE: Lazy<FastDashMap<ClientKey, TimedValue<HttpsClient>>> = Lazy::new(FastDashMap::default);
static CLIENT_CACHE_PROXY: Lazy<FastDashMap<ClientKey, TimedValue<ProxyClient>>> = Lazy::new(FastDashMap::default);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ClientOptions {
    pub use_proxy: bool,
    pub proxy_addr: Option<String>,
    pub use_cert: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug, Ord, PartialOrd)]
pub struct ClientKey {
    pub use_proxy: bool,
    pub proxy_addr: Option<String>,
    pub use_cert: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[allow(dead_code)]
impl ClientKey {
    pub fn from_options(opts: &ClientOptions) -> Self {
        ClientKey {
            use_proxy: opts.use_proxy,
            proxy_addr: opts.proxy_addr.clone().map(|s| s.to_string()),
            use_cert: opts.use_cert,
            cert_path: opts.cert_path.clone().map(|s| s.to_string()),
            key_path: opts.key_path.clone().map(|s| s.to_string()),
        }
    }
}

pub fn get_or_build_client(
    opts: ClientOptions,
    state: Arc<AppConfig>,
) -> HttpsClient {
    let key = ClientKey::from_options(&opts);

    if let Some(entry) = CLIENT_CACHE.get(&key) {
        if entry.inserted.elapsed() < TTL {
            return entry.value.clone();
        } else {
            CLIENT_CACHE.remove(&key);
        }
    }

    if CLIENT_CACHE.len() >= MAX_CLIENTS {
        for entry in CLIENT_CACHE.iter() {
            CLIENT_CACHE.remove(entry.key());
            break;
        }
    }

    let client = if opts.use_cert {
        build_hyper_client_cert(opts.clone(), &state)
    } else {
        build_hyper_client_normal(&state)
    };

    CLIENT_CACHE.insert(
        key,
        TimedValue {
            inserted: Instant::now(),
            value: client.clone(),
        },
    );

    client
}


pub fn get_or_build_client_proxy(
    opts: ClientOptions,
    state: Arc<AppConfig>,
) -> ProxyClient {
    let key = ClientKey::from_options(&opts);

    if let Some(entry) = CLIENT_CACHE_PROXY.get(&key) {
        if entry.inserted.elapsed() < TTL {
            return entry.value.clone();
        } else {
            CLIENT_CACHE_PROXY.remove(&key);
        }
    }

    if CLIENT_CACHE_PROXY.len() >= MAX_CLIENTS {
        for entry in CLIENT_CACHE_PROXY.iter() {
            CLIENT_CACHE_PROXY.remove(entry.key());
            break;
        }
    }

    let client = build_hyper_client_proxy(opts.clone(), &state);

    CLIENT_CACHE_PROXY.insert(
        key,
        TimedValue {
            inserted: Instant::now(),
            value: client.clone(),
        },
    );

    client
}

pub fn build_hyper_client_cert(opts: ClientOptions, state: &Arc<AppConfig>) -> Client<HttpsConnector<HttpConnector>> {
    let timeout_duration = Duration::from_millis(10000);

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = if opts.use_cert {
        let cert_path = opts.cert_path.expect("cert_path required");
        let key_path = opts.key_path.expect("key_path required");

        let cert_file = &mut BufReader::new(File::open(cert_path).expect("Failed to open cert file"));
        let key_file = &mut BufReader::new(File::open(&key_path).expect("Failed to open key file"));

        let cert_chain: Vec<Certificate> = certs(cert_file)
        .expect("Error reading cert file")
        .into_iter()
        .map(Certificate)
        .collect();

        let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .expect("Error reading key file")
        .into_iter()
        .map(PrivateKey)
        .collect();

        if keys.is_empty() {
            panic!("No key found in file: {:?}", key_path);
        }

        ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, keys.remove(0))
        .expect("Invalid cert/key pair")
    } else {
        ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth()
    };

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(timeout_duration));
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(Duration::from_secs(10)));

    let tls_config = Arc::new(config);
    let https_connector = HttpsConnector::from((http_connector, tls_config));

    Client::builder()
    .pool_idle_timeout(Some(timeout_duration))
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .http2_adaptive_window(true)
    .build::<_, Body>(https_connector)
}

pub fn build_hyper_client_proxy(opts: ClientOptions,  state: &Arc<AppConfig>) -> Client<ProxyConnector<HttpsConnector<HttpConnector>>> {
    let timeout_duration = Duration::from_millis(10000);

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = if opts.use_cert {
        let cert_path = opts.cert_path.expect("cert_path required");
        let key_path = opts.key_path.expect("key_path required");

        let cert_file = &mut BufReader::new(File::open(&cert_path).expect("Failed to open cert file"));
        let key_file = &mut BufReader::new(File::open(&key_path).expect("Failed to open key file"));

        let cert_chain: Vec<Certificate> = certs(cert_file)
        .expect("Error reading cert file")
        .into_iter()
        .map(Certificate)
        .collect();

        let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)
        .expect("Error reading key file")
        .into_iter()
        .map(PrivateKey)
        .collect();

        if keys.is_empty() {
            panic!("No key found in file: {:?}", key_path);
        }

        ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, keys.remove(0))
        .expect("Invalid cert/key pair")
    } else {
        ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth()
    };

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(timeout_duration));
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(Duration::from_secs(10)));

    let tls_config = Arc::new(config);
    let https_connector = HttpsConnector::from((http_connector, tls_config));

    let proxy_connector = if opts.use_proxy {
        let proxy_addr = opts.proxy_addr.clone().unwrap_or_else(|| "http://127.0.0.1:8888".to_string());
        let proxy_uri = hyper::Uri::from_str(&proxy_addr).expect("Invalid proxy address");

        ProxyConnector::from_proxy(https_connector, Proxy::new(Intercept::All, proxy_uri))
        .expect("Failed to create proxy connector")
    } else {
        ProxyConnector::from_proxy(https_connector, Proxy::new(Intercept::None, hyper::Uri::from_static("http://127.0.0.1:8888")))
        .expect("Failed to create dummy proxy connector")
    };

    Client::builder()
    .pool_idle_timeout(Some(timeout_duration))
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .http2_adaptive_window(true)
    .build::<_, Body>(proxy_connector)
}

pub fn build_hyper_client_normal(state: &Arc<AppConfig>) -> Client<HttpsConnector<HttpConnector>> {
    let timeout_duration = Duration::from_millis(10000);

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = ClientConfig::builder()
    .with_safe_defaults()
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let mut http_connector = HttpConnector::new();
    http_connector.set_connect_timeout(Some(timeout_duration));
    http_connector.enforce_http(false);
    http_connector.set_nodelay(true);
    http_connector.set_keepalive(Some(Duration::from_secs(30)));

    let tls_config = Arc::new(config);
    let https_connector = HttpsConnector::from((http_connector, tls_config));

    Client::builder()
    .pool_idle_timeout(Some(timeout_duration))
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .http2_adaptive_window(true)
    .build::<_, Body>(https_connector)
}
