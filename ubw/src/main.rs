use clap::{Args, Parser, Subcommand};

use anyhow::Result;
use log::LevelFilter;
use rstaples::logging::StaplesLogger;

use ubw::commands::{
    ciphers::{command_cipher, command_ciphers},
    login::{LoginArgs, command_login},
    password::command_password,
    server::{CacheArgs, command_cache},
    totp::command_totp,
};

#[derive(Args)]
pub struct IdArgs {
    /// cipher id
    #[arg(short, long)]
    id: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Cache Server
    Cache(CacheArgs),
    /// Create a new session
    Login(LoginArgs),
    /// List ciphers
    Ciphers,
    /// Pull cipher
    Cipher(IdArgs),
    /// Pull the TOTP for the specified id
    Totp(IdArgs),
    /// Pull the password for the specified id
    Password(IdArgs),
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = UserArgs::parse();

    let log_level = if args.verbose {
        LevelFilter::Info
    } else {
        LevelFilter::Error
    };

    StaplesLogger::new().with_colors().with_log_level(log_level).start();

    match args.command {
        Commands::Login(login) => command_login(login).await?,
        Commands::Cache(a) => command_cache(a).await?,
        Commands::Ciphers => command_ciphers().await?,
        Commands::Cipher(cipher) => command_cipher(cipher.id).await?,
        Commands::Totp(totp) => command_totp(totp.id).await?,
        Commands::Password(pass) => command_password(pass.id).await?,
    }

    Ok(())
}
