use crate::token::auth::generate_random_string;
use crate::stats::tokencount::CounterToken;
use crate::adm::method_otp::generate_base32_secret;
use argon2::password_hash::{SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHasher};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use hyper::Client;
use hyper::client::HttpConnector;
use hyper_rustls::HttpsConnector;
use hyper_proxy::ProxyConnector;
use serde::Deserializer;
use std::fmt;
use serde::de::MapAccess;
use serde::de::Visitor;

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

    #[serde(default = "default_backends")]
    pub backends: Vec<BackendInput>,
}


#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub url: String,
    #[serde(default = "default_weight")]
    pub weight: i16,
}

fn default_weight() -> i16 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BackendInput {
    Simple(String),
    Detailed(BackendConfig),
}

#[derive(Default, Debug, Deserialize)]
pub struct RouteConfig {
    pub routes: Vec<RouteRule>,
}

#[derive(Debug, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub otpkey: Option<String> // Option<Vec<u8>>
}

impl Serialize for User {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("User", 2)?;
        state.serialize_field("username", &self.username)?;
        state.serialize_field("password", &self.password)?;
        state.serialize_field("otpkey", &self.otpkey)?;
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

    #[serde(deserialize_with = "deserialize_log_map")]
    pub log: HashMap<String, String>,

    #[serde(default = "default_stats")]
    pub stats: bool,

    #[serde(default = "default_max_idle_per_host")]
    pub max_idle_per_host: u16,

    #[serde(default = "default_timezone")]
    pub timezone: String,

    #[serde(default = "default_login_via_otp")]
    pub login_via_otp: bool,
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
        state.serialize_field("log", &self.log)?;
        state.serialize_field("login_via_otp", &self.login_via_otp)?;
        state.serialize_field("worker", &self.worker)?;
        state.serialize_field("ratelimit_auth", &self.ratelimit_auth)?;
        state.serialize_field("ratelimit_proxy", &self.ratelimit_proxy)?;
        state.serialize_field("users", &self.users)?;
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
    pub totp_code: Option<String>,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_timezone() -> String {
    "Europe/Paris".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_username() -> Vec<String> {
    [].to_vec()
}

fn default_backends() -> Vec<BackendInput> {
    Vec::new()
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

fn default_login_via_otp() -> bool {
    false
}

fn default_log() -> HashMap<String, String> {
    let mut log = HashMap::new();
    log.insert("type".to_string(), "local".to_string());
    log.insert("write_max_logs".to_string(), "1000".into());
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

#[allow(dead_code)]
pub fn add_otpkey(config_path: &str, username: &str) {
    if !Path::new(config_path).exists() {
        eprintln!("Config file not found: {}", config_path);
        return;
    }

    let config_str = fs::read_to_string(config_path)
    .expect("Failed to read the configuration file.");
    let mut json: Value = serde_json::from_str(&config_str)
    .expect("Invalid JSON format in configuration file.");

    let users = json.get_mut("users")
    .and_then(|u| u.as_array_mut())
    .expect("Missing 'users' field in configuration file.");

    let mut updated = false;

    for user in users.iter_mut() {
        let name = user.get("username").and_then(|u| u.as_str());
        if name == Some(username) {
            if user.get("otpkey").is_some() {
                println!("User '{}' already has an OTP key.", username);
            } else {
                let otpkey = generate_base32_secret(32);
                user.as_object_mut()
                .unwrap()
                .insert("otpkey".to_string(), Value::String(otpkey.clone()));
                println!("OTP key successfully generated for '{}': {}", username, otpkey);
                updated = true;
            }
            break;
        }
    }

    if updated {
        let updated_str = serde_json::to_string_pretty(&json)
        .expect("Failed to serialize the updated configuration.");
        fs::write(config_path, updated_str)
        .expect("Failed to write the updated configuration file.");
        println!("Configuration file has been updated.");
    } else if !users.iter().any(|u| u.get("username").and_then(|n| n.as_str()) == Some(username)) {
        eprintln!("User '{}' not found in the configuration file.", username);
    }
}

fn deserialize_log_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, String>, D::Error>
where
D: Deserializer<'de>,
{
    struct LogMapVisitor;

    impl<'de> Visitor<'de> for LogMapVisitor {
        type Value = HashMap<String, String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a map with string keys and string/int/bool values")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
        M: MapAccess<'de>,
        {
            let mut map = HashMap::new();
            while let Some((k, v)) = access.next_entry::<String, serde_json::Value>()? {
                let stringified = match v {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Bool(b) => b.to_string(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => continue,
                };
                map.insert(k, stringified);
            }
            Ok(map)
        }
    }

    let value = deserializer.deserialize_map(LogMapVisitor);
    match value {
        Ok(v) => Ok(v),
        Err(_) => Ok(default_log()),
    }
}
