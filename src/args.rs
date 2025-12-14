use clap::{Args, Parser, Subcommand};

#[derive(Args)]
pub struct SessionArgs {
    /// email address
    #[arg(short, long)]
    pub email: String,

    /// server url
    #[arg(short, long)]
    pub server_url: String,
}

#[derive(Args)]
pub struct CiphersArgs {}

#[derive(Subcommand)]
pub enum Commands {
    Session(SessionArgs),
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
