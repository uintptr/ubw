use clap::{Args, Parser, Subcommand};

use anyhow::Result;
use log::LevelFilter;
use rstaples::logging::StaplesLogger;

use ubw::commands::{
    agent::server::{AgentArgs, command_agent},
    ciphers::{command_cipher, command_ciphers},
    login::{LoginArgs, command_login, command_logins},
    password::command_password,
    ssh::command_ssh_keys,
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
    Agent(AgentArgs),
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
    /// List SSH keys
    SshKeys,
    /// List Loginms
    Logins,
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
        Commands::Login(login) => command_login(login).await,
        Commands::Agent(a) => command_agent(a).await,
        Commands::Ciphers => command_ciphers().await,
        Commands::Cipher(cipher) => command_cipher(cipher.id).await,
        Commands::Totp(totp) => command_totp(totp.id).await,
        Commands::Password(pass) => command_password(pass.id).await,
        Commands::SshKeys => command_ssh_keys().await,
        Commands::Logins => command_logins().await,
    }
}
