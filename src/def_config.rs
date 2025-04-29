use std::fs;
use std::path::Path;
use std::io::Write;
use reqwest;
use std::process::Command;
use std::io;
use nix::unistd::{Uid, User, setuid};

pub fn ensure_running_as_proxyauth() {
    let uid = Uid::effective();

    if let Some(user) = User::from_uid(uid).expect("Failed to get current user") {
        if user.name == "proxyauth" {
        } else {
            eprintln!("This program must be run as 'proxyauth'. Current user is '{}'", user.name);
            std::process::exit(1);
        }
    } else {
        eprintln!("Unable to find current user info.");
        std::process::exit(1);
    }
}

pub fn ensure_user_proxyauth_exists() -> io::Result<()> {
    if let Ok(Some(_)) = User::from_name("proxyauth") {
        println!("User 'proxyauth' already exists.");
        return Ok(());
    }

    println!("User 'proxyauth' not found. Creating user...");

    let status = Command::new("useradd")
        .args([
            "--system",
            "--no-create-home",
            "--shell", "/usr/sbin/nologin",
            "proxyauth",
        ])
        .status()?;

    thread::sleep(Duration::from_millis(500));

    if status.success() {
        println!("User 'proxyauth' created successfully.");
        Ok(())
    } else {
        eprintln!("Failed to create user 'proxyauth'. Are you running as root?");
        std::process::exit(1);
    }
}

pub fn setup_proxyauth_directory() -> io::Result<()> {
    let path = Path::new("/etc/proxyauth");

    // Vérifie si le dossier existe
    if !path.exists() {
        println!("Creating /etc/proxyauth directory...");

        // Crée le dossier avec tous les parents si besoin
        fs::create_dir_all(path)?;
    } else {
        println!("Directory /etc/proxyauth already exists.");
    }

    // Changer le propriétaire
    let status_chown = Command::new("chown")
        .args(["-R", "proxyauth:proxyauth", "/etc/proxyauth"])
        .status()?;

    if !status_chown.success() {
        eprintln!("Failed to change owner of /etc/proxyauth.");
        std::process::exit(1);
    }

    // Changer les permissions
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

pub fn switch_to_user(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    let user = User::from_name(username)?.ok_or("User not found")?;
    setuid(user.uid)?;
    println!("Switched to user '{}'", username);
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
