use nix::unistd::Group;
use nix::unistd::{Uid, User, setuid};
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub fn ensure_running_as_proxyauth() {
    let uid = Uid::effective();

    if let Some(user) = User::from_uid(uid).expect("Failed to get current user") {
        if user.name == "proxyauth" {
        } else {
            eprintln!(
                "This program must be run as 'proxyauth'. Current user is '{}'",
                user.name
            );
            std::process::exit(1);
        }
    } else {
        eprintln!("Unable to find current user info.");
        std::process::exit(1);
    }
}

pub fn ensure_running_as_root() {
    let uid = Uid::effective();

    if let Some(user) = User::from_uid(uid).expect("Failed to get current user") {
        if user.name == "root" {
        } else {
            eprintln!(
                "This program must be run as 'root'. Current user is '{}'",
                user.name
            );
            std::process::exit(1);
        }
    } else {
        eprintln!("Unable to find current user info.");
        std::process::exit(1);
    }
}

fn is_alpine() -> bool {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        content.to_lowercase().contains("alpine")
    } else {
        false
    }
}

pub fn ensure_user_proxyauth_exists() -> io::Result<()> {
    let alpine = is_alpine();

    println!(
        "Detected OS: {}",
        if alpine { "Alpine" } else { "Debian/Ubuntu" }
    );

    if Group::from_name("proxyauth")?.is_none() {
        println!("Group 'proxyauth' not found. Creating group...");

        let group_cmd = if alpine { "addgroup" } else { "groupadd" };

        let status_group = Command::new(group_cmd).arg("proxyauth").status()?;

        if !status_group.success() {
            eprintln!("Failed to create group 'proxyauth'.");
            std::process::exit(1);
        }
        println!("Group 'proxyauth' created.");
    } else {
        println!("Group 'proxyauth' already exists.");
    }

    if User::from_name("proxyauth")?.is_none() {
        println!("User 'proxyauth' not found. Creating user...");

        let status_user = if alpine {
            Command::new("adduser")
                .args([
                    "-S", // small/system account
                    "-G",
                    "proxyauth", // associate group
                    "proxyauth",
                ])
                .status()?
        } else {
            Command::new("useradd")
                .args([
                    "--system",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "--gid",
                    "proxyauth",
                    "proxyauth",
                ])
                .status()?
        };

        if !status_user.success() {
            eprintln!("Failed to create user 'proxyauth'.");
            std::process::exit(1);
        }

        println!("User 'proxyauth' created.");
        println!("Waiting for system to register new user...");
        thread::sleep(Duration::from_millis(500));
    } else {
        println!("User 'proxyauth' already exists.");
    }

    Ok(())
}

pub fn setup_proxyauth_directory() -> io::Result<()> {
    let path = Path::new("/etc/proxyauth");

    // verify path exist
    if !path.exists() {
        println!("Creating /etc/proxyauth directory...");

        // Create directory if no exist
        fs::create_dir_all(path)?;
    } else {
        println!("Directory /etc/proxyauth already exists.");
    }

    // Change owner
    let status_chown = Command::new("chown")
        .args(["-R", "proxyauth:proxyauth", "/etc/proxyauth"])
        .status()?;

    if !status_chown.success() {
        eprintln!("Failed to change owner of /etc/proxyauth.");
        std::process::exit(1);
    }

    // Change permission directory
    let status_chmod = Command::new("chmod")
        .args(["750", "/etc/proxyauth"])
        .status()?;

    if !status_chmod.success() {
        eprintln!("Failed to set permissions on /etc/proxyauth.");
        std::process::exit(1);
    }

    println!("Directory /etc/proxyauth is ready and secured.");
    Ok(())
}

pub fn setup_proxyauth_db_directory(insecure: bool) -> io::Result<()> {
    let path = Path::new("/opt/proxyauth/db");

    if !path.exists() {
        println!("Creating /opt/proxyauth/db directory...");
        fs::create_dir_all(path)?;
    } else {
        println!("Directory /opt/proxyauth/db already exists.");
    }

    let status_chown = Command::new("chown")
        .args(["-R", "proxyauth:proxyauth", "/opt/proxyauth"])
        .status()?;

    if !status_chown.success() {
        eprintln!("Failed to change owner of /opt/proxyauth.");
        std::process::exit(1);
    }

    let chmod_mode = if insecure { "777" } else { "700" };

    let status_chmod = Command::new("chmod")
        .args([chmod_mode, "/opt/proxyauth"])
        .status()?;

    if !status_chmod.success() {
        eprintln!("Failed to set permissions on /opt/proxyauth.");
        std::process::exit(1);
    }

    if insecure {
        println!("WARN ! Directory /opt/proxyauth/db is set to insecure mode.");
    } else {
        println!("Directory /opt/proxyauth/db is secured.");
    }

    Ok(())
}

pub fn switch_to_user(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    let user = User::from_name(username)?.ok_or("User not found")?;
    setuid(user.uid)?;
    Ok(())
}

pub async fn create_config(url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(path).exists() {
        return Ok(());
    }

    println!("Config file {} not found. Downloading from {}", path, url);

    let response = reqwest::get(url).await?;
    if !response.status().is_success() {
        return Err(format!("Failed to download config: HTTP {}", response.status()).into());
    }

    let content = response.bytes().await?;

    if let Some(parent) = Path::new(path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = fs::File::create(path)?;
    file.write_all(&content)?;

    println!("Config downloaded and saved to {}", path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::create_config;
    use std::{fs, net::SocketAddr, path::PathBuf};
    use tokio::task::JoinHandle;

    use hyper::{Body, Request, Response, Server, StatusCode};
    use hyper::service::{make_service_fn, service_fn};

    // --- Helpers -------------------------------------------------------------

    async fn start_test_server(status: StatusCode, body: &'static [u8]) -> (SocketAddr, JoinHandle<()>) {
        let make_svc = make_service_fn(move |_| {
            let body = body.to_vec();
            let status = status;
            async move {
                Ok::<_, hyper::Error>(service_fn(move |_req: Request<Body>| {
                    let body = body.clone();
                    async move {
                        let mut resp = Response::new(Body::from(body));
                        *resp.status_mut() = status;
                        Ok::<_, hyper::Error>(resp)
                    }
                }))
            }
        });

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        listener.set_nonblocking(true).unwrap();
        let local_addr = listener.local_addr().unwrap();

        let server = Server::from_tcp(listener).unwrap().serve(make_svc);
        let handle = tokio::spawn(async move {
            let _ = server.await;
        });

        (local_addr, handle)
    }

    fn tmp_path(name: &str) -> PathBuf {
        let suffix = format!(
            "{}_{}",
            std::process::id(),
                             std::time::SystemTime::now()
                             .duration_since(std::time::UNIX_EPOCH)
                             .unwrap()
                             .as_nanos()
        );
        std::env::temp_dir().join(format!("proxyauth_test_{}_{}", name, suffix))
    }

    // --- Tests ---------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn create_config_downloads_when_missing() {
        let expected = b"CONFIG_CONTENT";
        let (addr, _h) = start_test_server(StatusCode::OK, expected).await;
        let url = format!("http://{}/config.json", addr);

        let path = tmp_path("dl_ok").join("cfg/config.json");
        let _ = fs::remove_file(&path);

        // Appel
        create_config(&url, path.to_str().unwrap())
        .await
        .expect("download OK");

        // Vérif : fichier créé avec le bon contenu
        let got = fs::read(&path).expect("file exists");
        assert_eq!(got, expected);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn create_config_is_noop_when_file_exists() {
        let server_body = b"SHOULD_NOT_OVERWRITE";
        let (addr, _h) = start_test_server(StatusCode::OK, server_body).await;
        let url = format!("http://{}/conf.json", addr);

        let path = tmp_path("noop").join("already/exists/config.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = b"LOCAL_PRESENT";
        fs::write(&path, original).unwrap();

        create_config(&url, path.to_str().unwrap())
        .await
        .expect("noop OK");

        let got = fs::read(&path).unwrap();
        assert_eq!(&got, original, "existing file must not be overwritten");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn create_config_returns_error_on_non_200() {
        let (addr, _h) = start_test_server(StatusCode::NOT_FOUND, b"nope").await;
        let url = format!("http://{}/missing.json", addr);

        let path = tmp_path("err").join("cfg/config.json");
        let _ = fs::remove_file(&path);

        let err = create_config(&url, path.to_str().unwrap()).await.err();
        assert!(err.is_some(), "non-200 must yield an error");
    }
}
