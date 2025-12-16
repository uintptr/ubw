use clap::{Args, Parser, Subcommand};

#[derive(Args)]
pub struct SessionArgs {
    /// email address
    #[arg(short, long)]
    pub email: Option<String>,

    /// server url
    #[arg(short, long)]
    pub server_url: Option<String>,
}

#[derive(Args)]
pub struct CiphersArgs {}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new session
    Session(SessionArgs),
    /// List ciphers
    Ciphers(CiphersArgs),
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct UserArgs {
    /// verbose
    #[arg(short, long)]
    pub verbose: bool,

    /// Comamnd
    #[command(subcommand)]
    pub command: Commands,
}
