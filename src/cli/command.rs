use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "proxyauth")]
#[command(about = "Manage proxyauth system", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Prepare {
        #[arg(long)]
        insecure: bool,
    },
    Stats,
    Sync {
        target: Option<String>,
    },
}
