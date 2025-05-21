use crate::auth::generate_random_string;
use crate::tokencount::CounterToken;
use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use hyper::Client;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use hyper_proxy::ProxyConnector;

#[derive(Debug, Deserialize)]
pub struct RouteRule {
    pub prefix: String,
    pub target: String,

    #[serde(default = "default_username")]
    pub username: Vec<String>,

    #[serde(default = "default_secure")]
    pub secure: bool,

    #[serde(default = "default_proxy")]
    pub proxy: bool,

    #[serde(default = "default_proxy_config")]
    pub proxy_config: String,

    #[serde(default = "default_cert")]
    pub cert: HashMap<String, String>,
}

#[derive(Default, Debug, Deserialize)]
pub struct RouteConfig {
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
}

impl Serialize for User {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("User", 2)?;
        state.serialize_field("username", &self.username)?;
        state.serialize_field("password", &self.password)?;
        state.end()
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct AppConfig {
    pub token_expiry_seconds: i64,
    pub secret: String,
    pub users: Vec<User>,

    #[serde(default)]
    pub token_admin: String,

    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_worker")]
    pub worker: u8,

    #[serde(default = "default_ratelimit_proxy")]
    pub ratelimit_proxy: HashMap<String, u64>,

    #[serde(default = "default_ratelimit_auth")]
    pub ratelimit_auth: HashMap<String, u64>,

    #[serde(default = "default_log")]
    pub log: HashMap<String, String>,

    #[serde(default = "default_stats")]
    pub stats: bool,

    #[serde(default = "default_max_idle_per_host")]
    pub max_idle_per_host: u16,
}

impl Serialize for AppConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AppConfig", 7)?;
        state.serialize_field("token_expiry_seconds", &self.token_expiry_seconds)?;
        state.serialize_field("secret", &self.secret)?;
        state.serialize_field("token_admin", &self.token_admin)?;
        state.serialize_field("host", &self.host)?;
        state.serialize_field("port", &self.port)?;
        state.serialize_field("worker", &self.worker)?;
        state.serialize_field("ratelimit_auth", &self.ratelimit_auth)?;
        state.serialize_field("ratelimit_proxy", &self.ratelimit_proxy)?;
        state.serialize_field("users", &self.users)?; // en dernier
        state.end()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub routes: Arc<RouteConfig>,
    pub counter: Arc<CounterToken>,
    #[allow(dead_code)]
    pub client_normal: Client<HttpsConnector<HttpConnector>>,
    #[allow(dead_code)]
    pub client_with_cert: Client<HttpsConnector<HttpConnector>>,
    #[allow(dead_code)]
    pub client_with_proxy: Client<ProxyConnector<HttpsConnector<HttpConnector>>>,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_username() -> Vec<String> {
    [].to_vec()
}

fn default_secure() -> bool {
    true
}

fn default_worker() -> u8 {
    4
}

fn default_proxy() -> bool {
    false
}

fn default_stats() -> bool {
    false
}

fn default_proxy_config() -> String {
    "".to_string()
}

fn default_max_idle_per_host() -> u16 {
    50
}

fn default_log() -> HashMap<String, String> {
    let mut log = HashMap::new();
    log.insert("type".to_string(), "local".to_string());
    log
}

fn default_ratelimit_proxy() -> HashMap<String, u64> {
    let mut ratelimit = HashMap::new();
    ratelimit.insert("requests_per_second".to_string(), 0);
    ratelimit.insert("burst".to_string(), 1);
    ratelimit.insert("block_delay".to_string(), 500);
    ratelimit
}

fn default_ratelimit_auth() -> HashMap<String, u64> {
    let mut ratelimit = HashMap::new();
    ratelimit.insert("requests_per_second".to_string(), 0);
    ratelimit.insert("burst".to_string(), 1);
    ratelimit.insert("block_delay".to_string(), 500);
    ratelimit
}

fn default_cert() -> HashMap<String, String> {
    let cert = HashMap::new();
    cert
}

pub fn load_config(path: &str) -> Arc<AppConfig> {
    let config_str = fs::read_to_string(path).expect("Could not read config.json file");
    let mut config: AppConfig =
        serde_json::from_str(&config_str).expect("Invalid config format config.json");

    let mut updated = false;
    for user in &mut config.users {
        if !user.password.starts_with("$argon2") {
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(user.password.as_bytes(), &salt)
                .expect(&format!(
                    "Password hashing failed for user {}",
                    user.username
                ))
                .to_string();

            user.password = hash;
            updated = true;
        }
    }

    if config.token_admin.trim().is_empty() {
        let token: String = generate_random_string(64);
        config.token_admin = token;
        updated = true;
    }

    if updated {
        let updated_str = serde_json::to_string_pretty(&config).expect("Serialization failed");
        fs::write(path, updated_str).expect("Failed to write updated config");
    }

    Arc::new(config)
}
