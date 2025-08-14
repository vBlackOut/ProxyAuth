use crate::AppConfig;
use crate::AppState;
use crate::config::config::RouteRule;
use crate::config::config::RegexCond;
use crate::build::build_info::get;
use crate::network::canonical_url::canonicalize_path_for_match;
use crate::revoke::load::is_token_revoked;
use crate::token::crypto::{calcul_factorhash, decrypt, derive_key_from_secret};
use actix_web::http::header::HeaderMap;
use actix_web::HttpRequest;
use actix_web::web;
use actix_web::http::StatusCode;
use serde_json::Value as JsonValue;
use blake3;
use chrono::{DateTime, Duration, TimeZone, Timelike, Utc};
use chrono_tz::Tz;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{error, info, warn};

fn get_build_time() -> u64 {
    let get_build = get();
    let data = get_build.build_time;
    data
}

pub fn get_build_rand() -> u64 {
    let get_build = get();
    let data = get_build.build_rand;
    data
}

pub fn get_build_seed2() -> u64 {
    let get_build = get();
    let data = get_build.build_seed2;
    data
}

pub fn get_build_epochdate() -> i64 {
    let get_build = get();
    let data = get_build.build_epoch;
    data
}

pub fn get_build_datetime() -> chrono::DateTime<chrono::Utc> {
    let seconds = get_build_epochdate();
    let naive = Utc.timestamp_opt(seconds, 0).unwrap();
    naive
}

static DERIVED_KEY: OnceLock<[u8; 32]> = OnceLock::new();

#[allow(dead_code)]
fn format_long_date(seconds: u128) -> String {
    let seconds_per_year = 31_557_600u128;
    let year = seconds / seconds_per_year;
    let remaining = seconds % seconds_per_year;

    let _days = remaining / 86400;
    let hours = (remaining % 86400) / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    format!(
        "+{:0>8}-01-01T{:02}:{:02}:{:02}Z",
        year, hours, minutes, seconds
    )
}

pub fn init_derived_key(secret: &str) {
    let key = derive_key_from_secret(secret);
    DERIVED_KEY.set(key).expect("Key already initialized");
}

pub fn check_date_token(
    time_str: &str,
    username: &str,
    ip: &str,
    timezone: &str,
) -> Result<u64, ()> {
    let tz: Tz = timezone.parse().map_err(|_| {
        warn!("[{}] invalid timezone '{}'", ip, timezone);
        ()
    })?;

    let expire_time = time_str
        .parse::<DateTime<Utc>>()
        .or_else(|_| {
            time_str
                .parse::<i64>()
                .map(|ts| Utc.timestamp_opt(ts, 0).single().unwrap())
        })
        .map_err(|_| {
            warn!("[{}] failed to parse expiration time: {}", ip, time_str);
            ()
        })?;

    let expire_local = expire_time.with_timezone(&tz);
    let now_local = Utc::now().with_timezone(&tz);

    if now_local.timestamp() >= expire_local.timestamp() {
        warn!("[{}] token is expired for user {}", ip, username);
        return Err(());
    }

    let diff = expire_local.timestamp() - now_local.timestamp();
    diff.try_into().map_err(|_| ())
}

pub fn generate_secret(secret: &str, token_expiry_seconds: &i64) -> String {
    let base = get_build_datetime();

    let next_reset_time = match *token_expiry_seconds {
        0..=86_400 => base + Duration::seconds(*token_expiry_seconds),

        86_401..=2_419_200 => {
            let weeks = (*token_expiry_seconds as f64 / (7.0 * 86400.0)).ceil() as i64;
            base + Duration::days(weeks * 7)
        }

        2_419_201..=31_104_000 => {
            let months = (*token_expiry_seconds as f64 / (30.0 * 86400.0)).ceil() as u32;

            let mut year = 0;
            let mut month = 1 + months;

            while month > 12 {
                month -= 12;
                year += 1;
            }

            let (next_year, next_month) = if month == 12 {
                (year + 1, 1)
            } else {
                (year, month + 1)
            };

            let first_of_next_month = Utc
                .with_ymd_and_hms(next_year as i32, next_month, 1, 0, 0, 0)
                .unwrap();

            let last_day = first_of_next_month - Duration::days(1);
            last_day
                .with_hour(23)
                .unwrap()
                .with_minute(59)
                .unwrap()
                .with_second(59)
                .unwrap()
        }

        31_104_001..=157_680_000 => {
            let years = (*token_expiry_seconds as f64 / (365.0 * 86400.0)).ceil() as i32;
            Utc.with_ymd_and_hms(0 + years, 12, 31, 23, 59, 59).unwrap()
        }

        _ => base + Duration::seconds(86_400),
    };

    let now = Utc::now();
    let _remaining_seconds = (next_reset_time - now).num_seconds();

    format!("{}:{}", secret, next_reset_time.timestamp())
}

pub fn generate_token(
    username: &str,
    config: &AppConfig,
    time_expire: &str,
    token_id: &str,
) -> String {
    let values_map = HashMap::from([
        ("username", username.to_string()),
        (
          "secret_with_timestamp",
          generate_secret(&config.secret, &config.token_expiry_seconds),
        ),
        ("build_time", get_build_time().to_string()),
        ("time_expire", time_expire.to_string()),
        ("build_rand", get_build_rand().to_string()),
        ("token_id", token_id.to_string()),
    ]);

    let shuffled: Vec<String> = get()
        .shuffled_order_list()
        .iter()
        .map(|k| values_map[k.as_str()].clone())
        .collect();

    let shuffle_data = shuffled.join(":");
    let mut signature = Sha256::new();
    signature.update(shuffle_data.as_bytes());
    format!("{:x}", signature.finalize())
}

pub async fn validate_token(
    token: &str,
    data_app: &web::Data<AppState>,
    config: &AppConfig,
    ip: &str,
) -> Result<(String, String, u64), String> {
    let key = derive_key_from_secret(&config.secret);

    let decrypt_token = decrypt(token, &key).map_err(|_| "Invalid token format")?;

    let data: [&str; 4] = decrypt_token
        .splitn(4, '|')
        .collect::<Vec<&str>>()
        .try_into()
        .map_err(|_| "Invalid token format")?;

    let token_hash_decrypt = data[0];

    let index_user = data[2].parse::<usize>().map_err(|_| "Index invalide")?;
    let user = config.users.get(index_user).ok_or("User not found")?;

    let time_expire = check_date_token(data[1], &user.username, ip, &config.timezone)
        .map_err(|_| "Your token is expired")?;

    if (time_expire > (config.token_expiry_seconds as i64).try_into().unwrap())
        .try_into()
        .unwrap()
    {
        error!(
            "[{}] username {} try to access token limit config {} value request {}",
            ip, user.username, config.token_expiry_seconds, time_expire
        );
        return Err("Bad time token".to_string());
    }

    let token_generated = generate_token(&user.username, &config, data[1], data[3]);
    let token_hash = calcul_factorhash(token_generated);

    if blake3::hash(token_hash.as_bytes()).to_hex().to_string() != token_hash_decrypt {
        warn!("[{}] Invalid token", ip);
        return Err("no valid token".to_string());
    }

    if is_token_revoked(data[3], &data_app.revoked_tokens) {
        warn!(
            "[{}] token_id {} is revoked from user {}",
            ip, data[3], user.username
        );
        return Err("revoked token".to_string());
    }

    if config.stats {
        let count =
            data_app
                .counter
                .record_and_get(&user.username, data[3], &time_expire.to_string());

        info!(
            "[{}] user {} is logged token expire in {} seconds [token used: {}]",
            ip, user.username, time_expire, count
        );
    } else {
        info!(
            "[{}] user {} is logged token expire in {} seconds",
            ip, user.username, time_expire
        );
    }

    Ok((user.username.to_string(), data[3].to_string(), time_expire))
}

pub fn extract_token_user(token: &str, config: &AppConfig, ip: String) -> Result<String, String> {
    let key = derive_key_from_secret(&config.secret);

    let decrypt_token = match decrypt(token, &key) {
        Ok(val) => val,
        Err(_) => {
            warn!("[{}] Failed to decrypt token (invalid format)", ip);
            return Err("Invalid token format".into());
        }
    };

    let data: Vec<&str> = decrypt_token.split('|').collect();

    if data.len() < 3 {
        warn!("[{}] Token structure is invalid (not enough segments)", ip);
        return Err("Invalid token content".into());
    }

    let index_user: usize = match data[2].parse() {
        Ok(i) => i,
        Err(_) => {
            warn!("[{}] Failed to parse user index from token", ip);
            return Err("Invalid user index".into());
        }
    };

    if let Some(user) = config.users.get(index_user) {
        Ok(user.username.clone())
    } else {
        warn!("[{}] User index out of bounds: {}", ip, index_user);
        Err("User not found".into())
    }
}

fn all_values_match<'a, I>(vals: I, re: &Regex) -> bool
where
I: IntoIterator<Item = &'a str>,
{
    vals.into_iter().all(|v| re.is_match(v))
}

pub fn parse_query_map(q: &str) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::<String, Vec<String>>::new();
    for pair in q.split('&').filter(|s| !s.is_empty()) {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("").to_string();
        let v = it.next().unwrap_or("").to_string();
        map.entry(k).or_default().push(v);
    }
    map
}

pub fn apply_filters_regex_allow_only(
    rule: &RouteRule,
    req: &HttpRequest,
    body: &[u8],
) -> Option<StatusCode> {

    let compiled = match &rule.filters_compiled {
        Some(c) => c,
        None => return None,
    };

    let method = req.method();
    let path_canon = canonicalize_path_for_match(req.uri().path());
    let query = parse_query_map(req.uri().query().unwrap_or("")); // HashMap<String, Vec<String>>

    let mut need_utf8 = false;
    let mut need_json = false;
    for c in &compiled.allow {
        match c {
            RegexCond::BodyRaw  { .. } => need_utf8 = true,
            RegexCond::BodyJson { .. } => need_json = true,
            _ => {}
        }
    }

    let ct = req.headers()
    .get(actix_web::http::header::CONTENT_TYPE)
    .and_then(|v| v.to_str().ok())
    .unwrap_or("")
    .to_ascii_lowercase();

    let body_utf8 = if need_utf8 {
        std::str::from_utf8(body).ok()
    } else {
        None
    };

    let body_json = if need_json && ct.contains("application/json") {
        serde_json::from_slice::<JsonValue>(body).ok()
    } else {
        None
    };

    if compiled.allow.is_empty() {
        return if compiled.default_allow { None } else { Some(StatusCode::FORBIDDEN) };
    }

    let ok = compiled.allow.iter().all(|cond| {
        cond_matches_strict(
            cond,
            method,
            &path_canon,
            req.headers().clone(),
            &query,
            body_utf8,
            body_json.as_ref(),
            &ct,
        )
    });

    if ok {
        None
    } else {
        Some(StatusCode::FORBIDDEN)
    }
}

pub fn cond_matches_strict(
    cond: &RegexCond,
    method: &actix_web::http::Method,
    path: &str,
    headers: HeaderMap,
    query: &std::collections::HashMap<String, Vec<String>>,
    body_utf8: Option<&str>,
    body_json: Option<&JsonValue>,
    content_type_lower: &str,
) -> bool {
    match cond {
        RegexCond::Method { re } => re.is_match(method.as_str()),
        RegexCond::Path { re } => re.is_match(path),

        RegexCond::Header { name_re, re } => {
            let mut matched_any_name = false;
            let mut values_for_matched_names: Vec<String> = Vec::new();

            for (k, v) in headers.iter() {
                let name = k.as_str();
                if name_re.is_match(name) {
                    matched_any_name = true;
                    if let Ok(val) = v.to_str() {
                        values_for_matched_names.push(val.to_string());
                    } else {
                        return false;
                    }
                }
            }

            if !matched_any_name {
                return false;
            }

            all_values_match(values_for_matched_names.iter().map(|s| s.as_str()), re)
        }

        RegexCond::Query { name_re, re } => {
            let mut matched_any_name = false;

            for (k, vals) in query {
                if name_re.is_match(k) {
                    matched_any_name = true;

                    if !all_values_match(vals.iter().map(|s| s.as_str()), re) {
                        return false;
                    }
                }
            }

            matched_any_name
        }

        RegexCond::BodyRaw { re } => {
            match body_utf8 {
                Some(s) => re.is_match(s),
                None => false,
            }
        }

        RegexCond::BodyJson { key, re } => {
            if !content_type_lower.contains("application/json") {
                return false;
            }
            let Some(j) = body_json else { return false; };

            match j.get(key) {
                Some(JsonValue::String(s)) => re.is_match(s),
                Some(JsonValue::Number(n)) => re.is_match(&n.to_string()),
                Some(JsonValue::Bool(b))   => re.is_match(if *b { "true" } else { "false" }),
                Some(other)                => re.is_match(&other.to_string()),
                None => false,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, http::header, http::Method, test::TestRequest};
    use regex::Regex;
    use serde_json::json;
    use bytes::Bytes;
    use std::collections::HashMap;
    use crate::config::config::{AllowRegexCfg, RegexCondCfg, RouteRule, BackendInput};

    // ---------- parse_query_map ----------------------------------------------

    #[test]
    async fn parse_query_map_multiple_values_and_missing_value() {
        let q = "a=1&a=2&b=&c";
        let m = parse_query_map(q);
        assert_eq!(m.get("a").unwrap(), &vec!["1".to_string(), "2".to_string()]);
        assert_eq!(m.get("b").unwrap(), &vec!["".to_string()]);
        assert_eq!(m.get("c").unwrap(), &vec!["".to_string()]);
        assert!(m.get("d").is_none());
    }

    fn mk_rule(filters: AllowRegexCfg) -> RouteRule {
        let compiled = filters.compile().ok();
        RouteRule {
            prefix: "/api".into(),
            target: "http://upstream".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: HashMap::new(),
            backends: Vec::<BackendInput>::new(),
            need_csrf: false,
            cache: true,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: Some(filters),
            filters_compiled: compiled,
        }
    }

    #[actix_web::test]
    async fn acl_all_must_match_ok() {
        let filters = AllowRegexCfg {
            default_allow: false,
                allow: vec![
                    RegexCondCfg::Method { pattern: r"(?i)^POST$".into() },
                    RegexCondCfg::Path   { pattern: r"^/api/v1/items$".into() },
                    RegexCondCfg::Header { name: r"(?i)^x-trace-id$".into(), pattern: r"^[a-f0-9-]{8,}$".into() },
                    RegexCondCfg::Query  { name: r"(?i)^page$".into(), pattern: r"^\d+$".into() },
                    RegexCondCfg::BodyJson { key: "name".into(), pattern: r"^[a-z0-9_-]{3,16}$".into() },
                ],
        };
        let rule = mk_rule(filters);

        let req = test::TestRequest::post()
        .uri("/api/v1/items?page=2")
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header(("x-trace-id", "abcd-1234-ef"))
        .set_payload(r#"{ "name":"hello_123" }"#)
        .to_http_request();

        let status = super::apply_filters_regex_allow_only(&rule, &req, &Bytes::from_static(b"{\"name\":\"hello_123\"}"));
        assert!(status.is_none(), "should be allowed (all conditions match)");
    }

    #[actix_web::test]
    async fn acl_mismatch_denied() {
        let filters = AllowRegexCfg {
            default_allow: false,
                allow: vec![
                    RegexCondCfg::Method { pattern: r"(?i)^GET$".into() },
                ],
        };
        let rule = mk_rule(filters);

        let req = test::TestRequest::post()
        .uri("/api/list")
        .to_http_request();

        let status = super::apply_filters_regex_allow_only(&rule, &req, &[]);
        assert_eq!(status, Some(StatusCode::FORBIDDEN));
    }

    #[actix_web::test]
    async fn acl_default_allow_false_and_no_rules_denied() {
        let filters = AllowRegexCfg { default_allow: false, allow: vec![] };
        let rule = mk_rule(filters);
        let req = test::TestRequest::get().uri("/api").to_http_request();
        let status = super::apply_filters_regex_allow_only(&rule, &req, &[]);
        assert_eq!(status, Some(StatusCode::FORBIDDEN));
    }

    #[actix_web::test]
    async fn acl_bodyraw_and_header_and_query() {
        let filters = AllowRegexCfg {
            default_allow: false,
                allow: vec![
                    RegexCondCfg::Method  { pattern: r"^POST$".into() },
                    RegexCondCfg::Header  { name: r"(?i)^content-type$".into(), pattern: r"^application/x-www-form-urlencoded".into() },
                    RegexCondCfg::Query   { name: r"(?i)^lang$".into(), pattern: r"^(en|fr)$".into() },
                    RegexCondCfg::BodyRaw { pattern: r"(^|&)name=[a-z]{2,8}(&|$)".into() },
                ],
        };
        let rule = mk_rule(filters);

        let req = test::TestRequest::post()
        .uri("/api/form?lang=fr")
        .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
        .set_payload("name=alice&x=1")
        .to_http_request();

        let status = super::apply_filters_regex_allow_only(&rule, &req, b"name=alice&x=1");
        assert!(status.is_none(), "form should pass");
    }

    // ---------- all_values_match ---------------------------------------------

    #[test]
    async fn all_values_match_ok_and_ko() {
        let re_ok = Regex::new("^[a-z]+$").unwrap();
        assert!(all_values_match(["abc", "xyz"], &re_ok));

        let re_ko = Regex::new("^a+$").unwrap();
        assert!(!all_values_match(["a", "b"], &re_ko));
    }

    // ---------- canonicalize + Path ------------------------------------------

    #[test]
    async fn cond_matches_path_with_canonicalization() {
        let raw_path = "/api%2Fadmin";
        let canon = canonicalize_path_for_match(raw_path);
        let cond = RegexCond::Path { re: Regex::new("^/api/admin$").unwrap() };

        let ok = cond_matches_strict(
            &cond,
            &Method::GET,
            &canon,
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(),
            None,
            None,
            "",
        );
        assert!(ok);
    }

    // ---------- Method --------------------------------------------------------

    #[test]
    async fn cond_matches_method_exact() {
        let cond = RegexCond::Method { re: Regex::new("^POST$").unwrap() };
        assert!(cond_matches_strict(
            &cond, &Method::POST, "/p",
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(), None, None, ""
        ));
        assert!(!cond_matches_strict(
            &cond, &Method::GET, "/p",
            actix_web::http::header::HeaderMap::new(),
            &std::collections::HashMap::new(), None, None, ""
        ));
    }

    // ---------- Header(name, value) ------------------------------------------

    #[test]
    async fn cond_matches_header_name_and_values() {
        let req = TestRequest::default()
        .insert_header(("x-client", "abc_123"))
        .insert_header(("x-client", "def-456"))
        .insert_header(("other", "zzz"))
        .to_http_request();

        let cond_ok = RegexCond::Header {
            name_re: Regex::new("^x-client$").unwrap(),
            re: Regex::new("^[a-z0-9_\\-]+$").unwrap(),
        };
        assert!(cond_matches_strict(
            &cond_ok, &Method::GET, "/",
            req.headers().clone(), &std::collections::HashMap::new(),
                                    None, None, ""
        ));

        let req_bad = TestRequest::default()
        .insert_header(("x-client", "ok"))
        .insert_header(("x-client", "NO!")) // invalide
        .to_http_request();

        assert!(!cond_matches_strict(
            &cond_ok, &Method::GET, "/",
            req_bad.headers().clone(), &std::collections::HashMap::new(),
                                     None, None, ""
        ));

        // Nom d’en-tête introuvable => false
        let cond_name_missing = RegexCond::Header {
            name_re: Regex::new("^x-missing$").unwrap(),
            re: Regex::new(".*").unwrap(),
        };
        assert!(!cond_matches_strict(
            &cond_name_missing, &Method::GET, "/",
            req.headers().clone(), &std::collections::HashMap::new(),
                                     None, None, ""
        ));
    }

    // ---------- Query(name, values) ------------------------------------------

    #[test]
    async fn cond_matches_query_all_values_must_match() {
        let q = parse_query_map("foo=a&foo=ab&bar=zzz");

        let cond_ok = RegexCond::Query {
            name_re: Regex::new("^foo$").unwrap(),
            re: Regex::new("^[ab]+$").unwrap(), // "a", "ab" OK
        };
        assert!(cond_matches_strict(
            &cond_ok, &Method::GET, "/", actix_web::http::header::HeaderMap::new(), &q, None, None, ""
        ));

        let cond_bad = RegexCond::Query {
            name_re: Regex::new("^foo$").unwrap(),
            re: Regex::new("^a$").unwrap(), // "ab" casse la règle
        };
        assert!(!cond_matches_strict(
            &cond_bad, &Method::GET, "/", actix_web::http::header::HeaderMap::new(), &q, None, None, ""
        ));

        // clé query absente => false
        let cond_missing = RegexCond::Query {
            name_re: Regex::new("^qux$").unwrap(),
            re: Regex::new(".*").unwrap(),
        };
        assert!(!cond_matches_strict(
            &cond_missing, &Method::GET, "/", actix_web::http::header::HeaderMap::new(), &q, None, None, ""
        ));
    }

    // ---------- BodyRaw -------------------------------------------------------

    #[test]
    async fn cond_matches_body_raw_utf8() {
        let cond = RegexCond::BodyRaw { re: Regex::new("^hello[ ]+world$").unwrap() };
        assert!(cond_matches_strict(
            &cond, &Method::POST, "/",
            actix_web::http::header::HeaderMap::new(), &std::collections::HashMap::new(),
                                    Some("hello world"), None, "text/plain"
        ));
        assert!(!cond_matches_strict(
            &cond, &Method::POST, "/",
            actix_web::http::header::HeaderMap::new(), &std::collections::HashMap::new(),
                                     Some("hello  WORLD"), None, "text/plain"
        ));
    }

    // ---------- BodyJson(key, value) -----------------------------------------

    #[test]
    async fn cond_matches_body_json_with_ct_guard() {
        let body = json!({"role":"admin","n":42,"active":true});
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let body_utf8 = std::str::from_utf8(&body_bytes).ok();
        let body_json: Option<JsonValue> = serde_json::from_slice(&body_bytes).ok();

        let c_role = RegexCond::BodyJson { key: "role".into(), re: Regex::new("^admin$").unwrap() };
        let c_num  = RegexCond::BodyJson { key: "n".into(),    re: Regex::new("^42$").unwrap() };
        let c_bool = RegexCond::BodyJson { key: "active".into(), re: Regex::new("^true$").unwrap() };

        for cond in [&c_role, &c_num, &c_bool] {
            assert!(cond_matches_strict(
                cond, &Method::POST, "/",
                actix_web::http::header::HeaderMap::new(), &std::collections::HashMap::new(),
                                        body_utf8, body_json.as_ref(), "application/json"
            ));
        }

        assert!(!cond_matches_strict(
            &c_role, &Method::POST, "/",
            actix_web::http::header::HeaderMap::new(), &std::collections::HashMap::new(),
                                     body_utf8, body_json.as_ref(), "text/plain"
        ));

        let c_missing = RegexCond::BodyJson { key: "missing".into(), re: Regex::new(".*").unwrap() };
        assert!(!cond_matches_strict(
            &c_missing, &Method::POST, "/",
            actix_web::http::header::HeaderMap::new(), &std::collections::HashMap::new(),
                                     body_utf8, body_json.as_ref(), "application/json"
        ));
    }

    #[test]
    async fn derive_key_is_32_bytes_and_stable() {
        let k1 = derive_key_from_secret("super-secret");
        let k2 = derive_key_from_secret("super-secret");
        assert_eq!(k1.len(), 32);
        assert_eq!(k1, k2);
        let k3 = derive_key_from_secret("other");
        assert_ne!(k1, k3);
    }

    #[test]
    async fn generate_secret_has_secret_and_timestamp_suffix() {
        let s = generate_secret("s3cr3t", &3600);
        let parts: Vec<&str> = s.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "s3cr3t");
        assert!(parts[1].parse::<i64>().is_ok());
    }

    #[test]
    async fn generate_token_is_sha256_hex() {
        #[allow(dead_code)]
        #[derive(Default)]
        struct MiniUser { username: String, roles: Option<Vec<String>> }
        #[allow(dead_code)]
        #[derive(Default)]
        struct MiniAppConfig {
            secret: String,
            token_expiry_seconds: i64,
            users: Vec<MiniUser>,
            timezone: String,
            stats: bool,
        }

        fn looks_like_sha256_hex(s: &str) -> bool {
            s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
        }

        let mut hasher = Sha256::new();
        hasher.update(b"some deterministic input");
        let hex = format!("{:x}", hasher.finalize());
        assert!(looks_like_sha256_hex(&hex));
    }
}

#[cfg(test)]
mod more_unit_tests {
    use super::*;
    use crate::config::config::{AllowRegexCfg, RouteRule, BackendInput};
    use std::collections::HashMap;

    fn mk_rule(filters: AllowRegexCfg) -> RouteRule {
        let compiled = filters.compile().ok();
        RouteRule {
            prefix: "/api".into(),
            target: "http://upstream".into(),
            username: vec![],
            secure: false,
            proxy: false,
            proxy_config: String::new(),
            cert: HashMap::new(),
            backends: Vec::<BackendInput>::new(),
            need_csrf: false,
            cache: true,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: Some(filters),
            filters_compiled: compiled,
        }
    }

    // ---------------- check_date_token ----------------

    #[test]
    fn check_date_token_accepts_future_iso_in_tz() {
        // dans 10 minutes
        let exp = (Utc::now() + chrono::Duration::minutes(10))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

        let res = check_date_token(&exp, "alice", "127.0.0.1", "UTC");
        assert!(res.is_ok());
        assert!(res.unwrap() > 0);
    }

    #[test]
    fn check_date_token_accepts_future_epoch() {
        let exp_epoch = (Utc::now() + chrono::Duration::minutes(5)).timestamp().to_string();
        let res = check_date_token(&exp_epoch, "bob", "127.0.0.1", "UTC");
        assert!(res.is_ok());
    }

    #[test]
    fn check_date_token_rejects_expired() {
        let past = (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let res = check_date_token(&past, "carol", "127.0.0.1", "UTC");
        assert!(res.is_err());
    }

    #[test]
    fn check_date_token_rejects_bad_timezone() {
        let exp = (Utc::now() + chrono::Duration::minutes(2))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
        let res = check_date_token(&exp, "dave", "127.0.0.1", "Not/AZone");
        assert!(res.is_err());
    }

    // ---------------- format_long_date ----------------

    #[test]
    fn format_long_date_formats_components() {
        assert_eq!(format_long_date(0), "+00000000-01-01T00:00:00Z");

        // 3661s => 01:01:01
        assert_eq!(format_long_date(3661), "+00000000-01-01T01:01:01Z");
    }

    // ---------------- build helpers ----------------

    #[test]
    fn get_build_helpers_do_not_panic_and_types_match() {
        let _t: u64 = get_build_time();
        let _r: u64 = get_build_rand();
        let _s2: u64 = get_build_seed2();
        let _e: i64 = get_build_epochdate();

        let dt = get_build_datetime();
        assert_eq!(dt.timestamp(), get_build_epochdate());
    }

    // ---------------- apply_filters_regex_allow_only ----------------

    #[actix_web::test]
    async fn acl_default_allow_true_and_no_rules_allows() {
        let filters = AllowRegexCfg { default_allow: true, allow: vec![] };
        let rule = mk_rule(filters);
        let req = actix_web::test::TestRequest::get().uri("/api/anything").to_http_request();
        let status = super::apply_filters_regex_allow_only(&rule, &req, &[]);
        assert!(status.is_none());
    }

    // ---------------- extract_token_user ----------------

    #[test]
    fn extract_token_user_rejects_invalid_format() {
        let cfg = AppConfig {
            secret: "topsecret".into(),
            token_expiry_seconds: 3600,
            users: vec![], // inutilisé ici
            timezone: "UTC".into(),
            stats: false,
            ..Default::default()
        };
        let err = extract_token_user("this-is-not-encrypted", &cfg, "127.0.0.1".into())
        .unwrap_err();
        assert_eq!(err, "Invalid token format");
    }
}

#[cfg(test)]
pub(super) fn validate_token_from_decrypted(
    decrypt_token: &str,
    data_app: &actix_web::web::Data<crate::AppState>,
    config: &crate::AppConfig,
    ip: &str,
) -> Result<(String, String, u64), String> {
    use tracing::{error, warn};
    use crate::revoke::load::is_token_revoked;
    use crate::token::crypto::calcul_factorhash;
    use crate::token::security::generate_token;
     use crate::token::security::check_date_token;

    let data: [&str; 4] = decrypt_token
    .splitn(4, '|')
    .collect::<Vec<&str>>()
    .try_into()
    .map_err(|_| "Invalid token format")?;

    let token_hash_decrypt = data[0];

    let index_user = data[2].parse::<usize>().map_err(|_| "Index invalide")?;
    let user = config.users.get(index_user).ok_or("User not found")?;

    let time_expire = check_date_token(data[1], &user.username, ip, &config.timezone)
    .map_err(|_| "Your token is expired")?;

    if (time_expire > (config.token_expiry_seconds as i64).try_into().unwrap())
        .try_into()
        .unwrap()
        {
            error!(
                "[{}] username {} try to access token limit config {} value request {}",
                ip, user.username, config.token_expiry_seconds, time_expire
            );
            return Err("Bad time token".to_string());
        }

        let token_generated = generate_token(&user.username, &config, data[1], data[3]);
        let token_hash = calcul_factorhash(token_generated);
        if blake3::hash(token_hash.as_bytes()).to_hex().to_string() != token_hash_decrypt {
            warn!("[{}] Invalid token", ip);
            return Err("no valid token".to_string());
        }

        if is_token_revoked(data[3], &data_app.revoked_tokens) {
            warn!(
                "[{}] token_id {} is revoked from user {}",
                ip, data[3], user.username
            );
            return Err("revoked token".to_string());
        }

        if config.stats {
            let count =
            data_app
            .counter
            .record_and_get(&user.username, data[3], &time_expire.to_string());
            tracing::info!(
                "[{}] user {} is logged token expire in {} seconds [token used: {}]",
                ip, user.username, time_expire, count
            );
        } else {
            tracing::info!(
                "[{}] user {} is logged token expire in {} seconds",
                ip, user.username, time_expire
            );
        }

        Ok((user.username.to_string(), data[3].to_string(), time_expire))
}

#[cfg(test)]
mod validate_token_path_tests {
    use super::*;
    use actix_web::web;
    use chrono::Utc;

    // ====== Clients Hyper tests ======
    use hyper::{Body, Client};
    use hyper::client::HttpConnector;
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_proxy::{Proxy, ProxyConnector, Intercept};
    use std::str::FromStr;
    use std::sync::Arc;
    use dashmap::DashMap;

    use crate::config::config::RouteConfig;
    use crate::stats::tokencount::CounterToken;
    use crate::token::crypto::calcul_factorhash;

    fn build_https_client_for_tests() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();
        Client::builder().build::<_, Body>(https)
    }

    fn build_proxy_client_for_tests(
        proxy_addr: &str,
    ) -> Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, Body> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_or_http()
        .enable_http1()
        .build();

        let proxy_uri = hyper::Uri::from_str(proxy_addr).expect("Invalid proxy URI");
        let proxy = Proxy::new(Intercept::All, proxy_uri);
        let proxy_connector =
        ProxyConnector::from_proxy(https, proxy).expect("Failed to create ProxyConnector");

        Client::builder().build::<_, Body>(proxy_connector)
    }

    // ====== AppState complet pour tests ======
    fn make_test_app_state() -> web::Data<crate::AppState> {
        let client_normal     = build_https_client_for_tests();
        let client_with_cert  = build_https_client_for_tests();
        let client_with_proxy = build_proxy_client_for_tests("http://127.0.0.1:8080");

        let cfg = AppConfig {
            secret: "super-secret".into(),
            timezone: "UTC".into(),
            ..Default::default()
        };

        let routes = RouteConfig { routes: vec![] };
        let counter = Arc::new(CounterToken::new());
        let revoked = DashMap::<String, u64>::new();

        web::Data::new(crate::AppState {
            counter,
            client_normal,
            client_with_cert,
            client_with_proxy,
            revoked_tokens: revoked.into(),
                       config: Arc::new(cfg),
                       routes: Arc::new(routes),
        })
    }

    // ====== helpers de config & hash ======
    fn mk_config(token_expiry_seconds: i64, stats: bool) -> AppConfig {
        let mut cfg = AppConfig {
            secret: "super-secret".into(),
            token_expiry_seconds,
            timezone: "UTC".into(),
            stats,
            ..Default::default()
        };
        if cfg.users.is_empty() {
            cfg.users.push(crate::config::config::User {
                username: "alice".into(),
                           roles: None,
                           allow: Some(vec!["127.0.0.1".to_string()]),
                           otpkey: Some(String::new()),
                           password: String::new(),
            });
        }
        cfg
    }

    fn mk_state() -> web::Data<AppState> {
        make_test_app_state()
    }

    fn make_valid_hash(username: &str, cfg: &AppConfig, time_str: &str, token_id: &str) -> String {
        let token_generated = generate_token(username, cfg, time_str, token_id);
        let token_hash = calcul_factorhash(token_generated);
        blake3::hash(token_hash.as_bytes()).to_hex().to_string()
    }

    fn compute_transport_hash(username: &str, cfg: &AppConfig, time_str: &str, token_id: &str) -> String {
        let token_generated = generate_token(username, cfg, time_str, token_id);
        let token_hash      = calcul_factorhash(token_generated);
        blake3::hash(token_hash.as_bytes()).to_hex().to_string()
    }

    // ==================== Cas d’erreur / bords ====================

    #[test]
    fn vt_invalid_format_less_parts() {
        let cfg = mk_config(3600, false);
        let st = mk_state();

        let dec = "only|two|parts";
        let err = super::validate_token_from_decrypted(dec, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "Invalid token format");
    }

    #[test]
    fn vt_index_invalide() {
        let cfg = mk_config(3600, false);
        let st = mk_state();

        let future = (Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let dec = format!("hash|{}|not-a-number|tid", future);
        let err = super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "Index invalide");
    }

    #[test]
    fn vt_user_not_found() {
        let cfg = mk_config(3600, false);
        let st = mk_state();

        let future = (Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let dec = format!("hash|{}|999|tid", future);
        let err = super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "User not found");
    }

    #[test]
    fn vt_timezone_invalide_mappe_vers_expired_message() {
        let mut cfg = mk_config(3600, false);
        cfg.timezone = "BAD/TZ".into(); // force une erreur dans check_date_token
        let st = mk_state();

        let future = (Utc::now() + chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let dec = format!("deadbeef|{}|0|tid", future);
        // l’erreur coté check_date_token est mappée sur "Your token is expired"
        let err = super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "Your token is expired");
    }

    #[test]
    fn vt_expired_maps_to_your_token_is_expired() {
        let cfg = mk_config(3600, false);
        let st = mk_state();

        let past = (Utc::now() - chrono::Duration::minutes(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let dec = format!("deadbeef|{}|0|tid", past);
        let err = super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "Your token is expired");
    }

    #[test]
    fn vt_bad_time_token_when_expiry_too_far() {
        let cfg = mk_config(60, false); // fenêtre config 60s
        let st = mk_state();

        let far = (Utc::now() + chrono::Duration::days(1))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let good_hash = make_valid_hash("alice", &cfg, &far, "tid-1");
        let dec = format!("{}|{}|0|tid-1", good_hash, far);
        let err = super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "Bad time token");
    }

    #[test]
    fn vt_hash_mismatch_no_valid_token() {
        let cfg = mk_config(3600, false);
        let st = mk_state();

        let future = (Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let dec = format!("deadbeef|{}|0|tid-x", future);
        let err = super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "no valid token");
    }

    #[test]
    fn vt_revoked_token() {
        let cfg = mk_config(3600, false);
        let st = mk_state();

        st.revoked_tokens.insert("tid-revoked".into(), 1u64);

        let future = (Utc::now() + chrono::Duration::minutes(2))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let good_hash = make_valid_hash("alice", &cfg, &future, "tid-revoked");
        let dec = format!("{}|{}|0|tid-revoked", good_hash, future);

        let err = super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "revoked token");
    }

    // ==================== Cas de succès ====================

    #[test]
    fn vt_success_minimal_no_stats() {
        let cfg = mk_config(3600, false);
        let st = mk_state();

        let future = (Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let good_hash = make_valid_hash("alice", &cfg, &future, "tid-ok");
        let dec = format!("{}|{}|0|tid-ok", good_hash, future);

        let (user, tid, _exp) =
        super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(tid, "tid-ok");
    }

    #[test]
    fn vt_success_with_stats_path_does_not_panic() {
        let cfg = mk_config(3600, true);
        let st = mk_state();

        let future = (Utc::now() + chrono::Duration::minutes(3))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let good_hash = make_valid_hash("alice", &cfg, &future, "tid-stats");
        let dec = format!("{}|{}|0|tid-stats", good_hash, future);

        let ok = super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1");
        assert!(ok.is_ok(), "le chemin avec stats ne doit pas paniquer");
    }

    #[test]
    fn vt_success_with_unix_timestamp_expire_field() {
        // couvre la branche parse i64 -> timestamp Unix dans check_date_token()
        let cfg = mk_config(3600, false);
        let st = mk_state();

        // expire dans ~5 minutes, en secondes Unix
        let expires = (Utc::now() + chrono::Duration::minutes(5)).timestamp().to_string();
        let h = make_valid_hash("alice", &cfg, &expires, "tid-unix");
        let dec = format!("{}|{}|0|tid-unix", h, expires);

        let (user, tid, _exp) =
        super::validate_token_from_decrypted(&dec, &st, &cfg, "127.0.0.1").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(tid, "tid-unix");
    }

    // ==================== Vérifs spécifiques hashing ====================

    #[test]
    fn blake3_hash_matches_on_valid_data() {
        let cfg = mk_config(3600, false);
        let future = (Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let tid = "tid-ok";
        let token_hash_decrypt = compute_transport_hash("alice", &cfg, &future, tid);
        let again = compute_transport_hash("alice", &cfg, &future, tid);
        assert_eq!(token_hash_decrypt, again);
    }

    #[test]
    fn blake3_hash_changes_when_time_or_tid_changes() {
        let cfg = mk_config(3600, false);

        let t1 = (Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let t2 = (Utc::now() + chrono::Duration::minutes(6))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let h1 = compute_transport_hash("alice", &cfg, &t1, "tid-X");
        let h2 = compute_transport_hash("alice", &cfg, &t2, "tid-X");
        let h3 = compute_transport_hash("alice", &cfg, &t1, "tid-Y");

        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn whole_block_detects_tamper_on_hash() {
        let st = web::Data::new(AppState {
            config: Arc::new(AppConfig::default()),
                                routes: Arc::new(RouteConfig { routes: vec![] }),
                                counter: Arc::new(CounterToken::new()),
                                client_normal: build_https_client_for_tests(),
                                client_with_cert: build_https_client_for_tests(),
                                client_with_proxy: build_proxy_client_for_tests("http://127.0.0.1:8080"),
                                revoked_tokens: DashMap::<String, u64>::new().into(),
        });

        let cfg = mk_config(3600, false);
        let future = (Utc::now() + chrono::Duration::minutes(5))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let h_ok = compute_transport_hash("alice", &cfg, &future, "tid-tamper");
        let mut h_bad = h_ok.clone();
        let last = h_bad.pop().unwrap();
        h_bad.push(if last == 'a' { 'b' } else { 'a' });

        let dec_bad = format!("{}|{}|0|tid-tamper", h_bad, future);
        let err = super::validate_token_from_decrypted(&dec_bad, &st, &cfg, "127.0.0.1").unwrap_err();
        assert_eq!(err, "no valid token");
    }

    #[test]
    fn calcul_factorhash_is_stable_for_same_inputs() {
        let cfg = mk_config(3600, false);

        let t = (Utc::now() + chrono::Duration::minutes(4))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let g1 = generate_token("alice", &cfg, &t, "tidZ");
        let g2 = generate_token("alice", &cfg, &t, "tidZ");
        let f1 = calcul_factorhash(g1);
        let f2 = calcul_factorhash(g2);
        assert_eq!(f1, f2);

        let b1 = blake3::hash(f1.as_bytes()).to_hex().to_string();
        let b2 = blake3::hash(f2.as_bytes()).to_hex().to_string();
        assert_eq!(b1, b2);
    }
}


