use crate::config::config::AppConfig;
use ahash::{AHashMap, RandomState};
use dashmap::DashMap;
use hyper::{Body, Client, client::HttpConnector};
use hyper_proxy::{Intercept, Proxy, ProxyConnector};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use once_cell::sync::{Lazy, OnceCell};
use rustls::{Certificate, PrivateKey, ClientConfig, RootCertStore, OwnedTrustAnchor};
use rustls_native_certs::load_native_certs;
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::{cell::RefCell, fs::File, io::BufReader, str::FromStr, sync::Arc, time::Duration};
use webpki_roots::TLS_SERVER_ROOTS;


type AHashDashMap<K, V> = DashMap<K, V, RandomState>;
type HttpsClient = Client<HttpsConnector<HttpConnector>>;
type ThreadCache = AHashMap<ClientKey, HttpsClient>;

thread_local! {
    static THREAD_CLIENT_CACHE: RefCell<ThreadCache> = RefCell::new(AHashMap::with_capacity(8));
}

#[allow(dead_code)]
static CLIENT_CACHE:        Lazy<AHashDashMap<ClientKey, Client<HttpsConnector<HttpConnector>>>> =
Lazy::new(AHashDashMap::default);
static CLIENT_CACHE_PROXY:  Lazy<AHashDashMap<ClientKey, Client<ProxyConnector<HttpsConnector<HttpConnector>>>>> =
Lazy::new(AHashDashMap::default);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ClientOptions {
    pub use_proxy:  bool,
    pub proxy_addr: Option<String>,
    pub use_cert:   bool,
    pub cert_path:  Option<String>,
    pub key_path:   Option<String>,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct ClientKey {
    pub use_proxy:  bool,
    pub proxy_addr: Option<String>,
    pub use_cert:   bool,
    pub cert_path:  Option<String>,
    pub key_path:   Option<String>,
}

impl ClientKey {
    pub fn from_options(opts: &ClientOptions) -> Self {
        ClientKey {
            use_proxy:  opts.use_proxy,
            proxy_addr: opts.proxy_addr.clone(),
            use_cert:   opts.use_cert,
            cert_path:  opts.cert_path.clone(),
            key_path:   opts.key_path.clone(),
        }
    }
}


static ROOT_STORE: OnceCell<RootCertStore> = OnceCell::new();

fn global_root_store() -> &'static RootCertStore {
    ROOT_STORE.get_or_init(|| {
        let mut store = RootCertStore::empty();

        if let Ok(native) = load_native_certs() {
            for cert in native {
                let _ = store.add(&Certificate(cert.0));
            }
        }

        store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject, ta.spki, ta.name_constraints
            )
        }));
        store
    })
}


fn build_http_connector(keep: Duration) -> HttpConnector {
    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(Duration::from_secs(1)));
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_keepalive(Some(keep));
    http
}

fn with_alpn(cfg: ClientConfig) -> ClientConfig {
    //cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}


pub fn get_or_build_thread_client(opts: &ClientOptions, state: &Arc<AppConfig>) -> HttpsClient {
    let key = ClientKey::from_options(opts);

    THREAD_CLIENT_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(client) = cache.get(&key) {
            return client.clone();
        }

        let client = if opts.use_cert {
            build_hyper_client_cert(opts.clone(), state)
        } else {
            build_hyper_client_normal(state)
        };

        cache.insert(key, client.clone());
        client
    })
}

#[allow(dead_code)]
pub fn get_or_build_client(
    opts: ClientOptions,
    state: Arc<AppConfig>,
) -> Client<HttpsConnector<HttpConnector>> {
    let key = ClientKey::from_options(&opts);

    if let Some(client) = CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let client = if opts.use_cert {
        build_hyper_client_cert(opts.clone(), &state)
    } else {
        build_hyper_client_normal(&state)
    };

    CLIENT_CACHE.insert(key, client.clone());
    client
}

pub fn get_or_build_client_proxy(
    opts: ClientOptions,
    state: Arc<AppConfig>,
) -> Client<ProxyConnector<HttpsConnector<HttpConnector>>> {
    let key = ClientKey::from_options(&opts);

    if let Some(client) = CLIENT_CACHE_PROXY.get(&key) {
        return client.clone();
    }

    let client = build_hyper_client_proxy(opts.clone(), &state);

    CLIENT_CACHE_PROXY.insert(key, client.clone());
    client
}


pub fn build_hyper_client_cert(
    opts: ClientOptions,
    state: &Arc<AppConfig>,
) -> Client<HttpsConnector<HttpConnector>> {
    let keep = Duration::from_secs(state.keep_alive);

    let want_cert = opts.use_cert
    && opts.cert_path.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
    && opts.key_path.as_ref().map(|s| !s.is_empty()).unwrap_or(false);

    if !want_cert {
        return build_hyper_client_normal(state);
    }

    let cert_path = opts.cert_path.as_ref().unwrap();
    let key_path  = opts.key_path.as_ref().unwrap();

    let (Ok(cf), Ok(kf)) = (File::open(cert_path), File::open(key_path)) else {
        tracing::warn!("TLS: cannot open cert/key files ({:?} / {:?}), using no_client_auth", cert_path, key_path);
        return build_hyper_client_normal(state);
    };

    let mut cert_file = BufReader::new(cf);
    let mut key_file  = BufReader::new(kf);

    let cert_chain: Vec<Certificate> = match certs(&mut cert_file) {
        Ok(v) => v.into_iter().map(Certificate).collect(),
        Err(e) => {
            tracing::warn!("TLS: failed to read certs '{}': {}, using no_client_auth", cert_path, e);
            return build_hyper_client_normal(state);
        }
    };

    let mut keys: Vec<PrivateKey> = match pkcs8_private_keys(&mut key_file) {
        Ok(v) => v.into_iter().map(PrivateKey).collect(),
        Err(e) => {
            tracing::warn!("TLS: failed to read private key '{}': {}, using no_client_auth", key_path, e);
            return build_hyper_client_normal(state);
        }
    };

    if cert_chain.is_empty() || keys.is_empty() {
        tracing::warn!("TLS: empty cert or key, using no_client_auth");
        return build_hyper_client_normal(state);
    }

    let tls_cfg = with_alpn(
        ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(global_root_store().clone())
        .with_client_auth_cert(cert_chain, keys.remove(0))
        .expect("Invalid cert/key pair"),
    );

    let https = HttpsConnectorBuilder::new()
    .with_tls_config(tls_cfg)
    .https_or_http()
    .enable_http1()
    .wrap_connector(build_http_connector(keep));

    Client::builder()
    .pool_idle_timeout(Some(keep))
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .http2_adaptive_window(true)
    .http2_keep_alive_interval(Some(Duration::from_secs(15)))
    .build::<_, Body>(https)
}

pub fn build_hyper_client_proxy(
    opts: ClientOptions,
    state: &Arc<AppConfig>,
) -> Client<ProxyConnector<HttpsConnector<HttpConnector>>> {
    let keep = Duration::from_secs(state.keep_alive);

    let tls_cfg = with_alpn(
        ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(global_root_store().clone())
        .with_no_client_auth(),
    );

    let https = HttpsConnectorBuilder::new()
    .with_tls_config(tls_cfg)
    .https_or_http()
    .enable_http1()
    .wrap_connector(build_http_connector(keep));

    let proxy_addr = opts
    .proxy_addr
    .clone()
    .unwrap_or_else(|| "http://127.0.0.1:8888".to_string());
    let proxy_uri = hyper::Uri::from_str(&proxy_addr).expect("Invalid proxy address");

    let proxy = ProxyConnector::from_proxy(https, Proxy::new(Intercept::All, proxy_uri))
    .expect("Failed to create proxy connector");

    Client::builder()
    .pool_idle_timeout(Some(keep))
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .http2_adaptive_window(true)
    .http2_keep_alive_interval(Some(Duration::from_secs(15)))
    .build::<_, Body>(proxy)
}

pub fn build_hyper_client_normal(state: &Arc<AppConfig>) -> Client<HttpsConnector<HttpConnector>> {
    let keep = Duration::from_secs(state.keep_alive);

    let tls_cfg = with_alpn(
        ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(global_root_store().clone())
        .with_no_client_auth(),
    );

    let https = HttpsConnectorBuilder::new()
    .with_tls_config(tls_cfg)
    .https_or_http()
    .enable_http1()
    .wrap_connector(build_http_connector(keep));

    Client::builder()
    .pool_idle_timeout(Some(keep))
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .http2_adaptive_window(true)
    .http2_keep_alive_interval(Some(Duration::from_secs(15)))
    .build::<_, Body>(https)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn mk_state(keep: u64, max_idle: u16) -> Arc<AppConfig> {
        let mut cfg = AppConfig::default();
        cfg.keep_alive = keep;
        cfg.max_idle_per_host = max_idle;
        Arc::new(cfg)
    }

    #[test]
    fn clientkey_from_options_copies_all_fields() {
        let opts = ClientOptions {
            use_proxy: true,
            proxy_addr: Some("http://127.0.0.1:8888".into()),
            use_cert: true,
            cert_path: Some("/tmp/client.crt".into()),
            key_path: Some("/tmp/client.key".into()),
        };
        let key = ClientKey::from_options(&opts);
        assert_eq!(key.use_proxy, opts.use_proxy);
        assert_eq!(key.proxy_addr, opts.proxy_addr);
        assert_eq!(key.use_cert, opts.use_cert);
        assert_eq!(key.cert_path, opts.cert_path);
        assert_eq!(key.key_path, opts.key_path);
    }

    #[test]
    fn global_root_store_is_singleton() {
        let a = global_root_store() as *const RootCertStore;
        let b = global_root_store() as *const RootCertStore;
        assert_eq!(a, b, "RootCertStore doit être le même (OnceCell)");
    }

    #[test]
    fn build_http_connector_smoke() {
        let _c = build_http_connector(Duration::from_secs(5));
    }

    #[test]
    fn build_normal_client_works() {
        let state = mk_state(30, 128);
        let _cli = build_hyper_client_normal(&state);
    }

    #[test]
    fn get_or_build_thread_client_caches_by_key() {
        let state = mk_state(15, 64);
        let opts = ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: false,
            cert_path: None,
            key_path: None,
        };
        let c1 = get_or_build_thread_client(&opts, &state);
        let c2 = get_or_build_thread_client(&opts, &state);
        let _ = (c1, c2);
    }

    #[test]
    fn proxy_client_builds_with_default_addr() {
        let state = mk_state(20, 256);
        let opts = ClientOptions {
            use_proxy: true,
            proxy_addr: None,
            use_cert: false,
            cert_path: None,
            key_path: None,
        };
        let _cli = get_or_build_client_proxy(opts, state);
    }

    #[test]
    fn m_tls_falls_back_when_paths_missing() {
        let state = mk_state(25, 100);
        let opts = ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: true,
            cert_path: None,
            key_path: None,
        };
        let _cli = build_hyper_client_cert(opts, &state);
    }

    #[test]
    fn m_tls_falls_back_when_files_invalid() {
        let state = mk_state(25, 100);
        let opts = ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: true,
            cert_path: Some("/definitely/does/not/exist.crt".into()),
            key_path:  Some("/definitely/does/not/exist.key".into()),
        };
        let _cli = build_hyper_client_cert(opts, &state);
    }

    #[test]
    fn non_proxy_cached_client_ok() {
        let state = mk_state(10, 32);
        let opts = ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: false,
            cert_path: None,
            key_path: None,
        };
        let _c1 = super::get_or_build_client(opts.clone(), state.clone());
        let _c2 = super::get_or_build_client(opts, state);
    }
}

