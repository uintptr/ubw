use std::{fs, os::unix::fs::OpenOptionsExt};

use clap::{Args, Parser, Subcommand};

use anyhow::{Result, anyhow};
use daemonize::Daemonize;
use log::{LevelFilter, error};
use rstaples::logging::StaplesLogger;

use ubw::{
    commands::{
        agent::server::{AgentArgs, command_agent},
        auth::{AuthArgs, command_auth, command_logins, command_logout},
        ciphers::{command_cipher, command_ciphers},
        login::{command_password, command_totp},
        ssh::command_ssh_keys,
    },
    common_const::UBW_DATA_DIR,
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
    Auth(AuthArgs),
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
    /// Logout
    Logout,
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

//#[tokio::main]
#[tokio::main(flavor = "current_thread")]
async fn tokio_entry(args: UserArgs) -> Result<()> {
    match args.command {
        Commands::Auth(auth) => command_auth(auth).await,
        Commands::Agent(a) => command_agent(a).await,
        Commands::Ciphers => command_ciphers().await,
        Commands::Cipher(cipher) => command_cipher(cipher.id).await,
        Commands::Totp(totp) => command_totp(totp.id).await,
        Commands::Password(pass) => command_password(pass.id).await,
        Commands::SshKeys => command_ssh_keys().await,
        Commands::Logins => command_logins().await,
        Commands::Logout => command_logout().await,
    }
}

fn daemonize() -> Result<()> {
    let home_dir = dirs::home_dir().ok_or(anyhow!("unable to find home dir"))?;

    let data_dir = dirs::data_dir().ok_or(anyhow!("unable to find data-dir"))?;
    let data_dir = data_dir.join(UBW_DATA_DIR);

    //
    // create it if it doesn't already exist
    //
    if !data_dir.exists()
        && let Err(e) = fs::create_dir_all(&data_dir)
    {
        error!("unable to create {} ({e})", data_dir.display());
    }

    //
    // Using a pid file will protect us from spawning multiple servers
    //
    let pid_file = data_dir.join("agent.pid");
    let stdout_file = data_dir.join("agent.stdout");
    let stderr_file = data_dir.join("agent.stderr");

    let stdout = fs::OpenOptions::new().append(true).create(true).mode(0o600).open(stdout_file)?;

    let stderr = fs::OpenOptions::new().append(true).create(true).mode(0o600).open(stderr_file)?;

    Daemonize::new()
        .pid_file(pid_file)
        .chown_pid_file(true)
        .working_directory(home_dir)
        .umask(0o077)
        .stdout(stdout)
        .stderr(stderr)
        .start()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = UserArgs::parse();

    let log_level = if args.verbose {
        LevelFilter::Info
    } else {
        LevelFilter::Error
    };

    StaplesLogger::new().with_colors().with_log_level(log_level).start();

    if let Commands::Agent(a) = &args.command
        && !a.foreground
        && !a.stop
    {
        //
        // Not stoping and not in the foreground
        //
        daemonize()?;
    }

    tokio_entry(args)
}
