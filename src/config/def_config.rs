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
