use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct RouteRule {
    pub prefix: String,
    pub target: String,

    #[serde(default = "default_username")]
    pub username: Vec<String>,

    #[serde(default = "default_secure")]
    pub secure: bool,
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

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub routes: Arc<RouteConfig>,
    pub client: Client,
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

fn default_ratelimit() -> HashMap<String, u64> {
    let mut ratelimit = HashMap::new();
    ratelimit.insert("per_second".to_string(), 100);
    ratelimit.insert("burst".to_string(), 10);
    ratelimit.insert("block_delay".to_string(), 10);
    ratelimit
}
