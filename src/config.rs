use std::fs;
use serde::{Serialize, Serializer, ser::SerializeStruct, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::{SaltString, rand_core::OsRng};

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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub token_expiry_seconds: i64,
    pub secret: String,
    pub users: Vec<User>,

    #[serde(default = "default_host")]
    pub host: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default = "default_worker")]
    pub worker: u8,

    #[serde(default = "default_ratelimit")]
    pub ratelimit: HashMap<String, u64>,
}

impl Serialize for AppConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AppConfig", 7)?;
        state.serialize_field("token_expiry_seconds", &self.token_expiry_seconds)?;
        state.serialize_field("secret", &self.secret)?;
        state.serialize_field("host", &self.host)?;
        state.serialize_field("port", &self.port)?;
        state.serialize_field("worker", &self.worker)?;
        state.serialize_field("ratelimit", &self.ratelimit)?;
        state.serialize_field("users", &self.users)?; // en dernier
        state.end()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub routes: Arc<RouteConfig>,
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

fn default_proxy_config() -> String {
    "".to_string()
}

fn default_ratelimit() -> HashMap<String, u64> {
    let mut ratelimit = HashMap::new();
    ratelimit.insert("requests_per_second".to_string(), 1000);
    ratelimit.insert("burst".to_string(), 10);
    ratelimit.insert("block_delay".to_string(), 500);
    ratelimit.insert("auth".to_string(), 5);
    ratelimit.insert("block_delay_auth".to_string(), 10000);
    ratelimit
}

fn default_cert() -> HashMap<String, String> {
    let mut cert = HashMap::new();
    cert.insert("file".to_string(), "".to_string());
    cert.insert("password".to_string(), "".to_string());
    cert
}

pub fn load_config(path: &str) -> Arc<AppConfig> {
    let config_str = fs::read_to_string(path).expect("Could not read config.json file");
    let mut config: AppConfig = serde_json::from_str(&config_str).expect("Invalid config format config.json");

    let mut updated = false;
    for user in &mut config.users {
        if !user.password.starts_with("$argon2") {
            let salt = SaltString::generate(&mut OsRng);
            let hash = Argon2::default()
                .hash_password(user.password.as_bytes(), &salt)
                .expect(&format!("Password hashing failed for user {}", user.username))
                .to_string();

            user.password = hash;
            updated = true;
        }
    }

    if updated {
        let updated_str = serde_json::to_string_pretty(&config).expect("Serialization failed");
        fs::write(path, updated_str).expect("Failed to write updated config");
    }

    Arc::new(config)
}
