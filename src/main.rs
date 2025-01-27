mod client;
mod encryption;
mod logger;
mod scan2;
mod server;
mod types;
mod utils;
use argh::FromArgs;
use logger::{log_error, log_info};

/// Redit file sharing
#[derive(FromArgs)]
struct Cli {
    /// verbose output
    #[argh(switch, short = 'V')]
    #[allow(dead_code)]
    verbose: bool,

    /// subcommand
    #[argh(subcommand)]
    command: Option<Commands>,
}

/// Subcommands
#[derive(FromArgs)]
#[argh(subcommand)]
enum Commands {
    Scan(ScanCommand),
    Host(HostCommand),
}

/// Scan network for Redit distributors
#[derive(FromArgs)]
#[argh(subcommand, name = "scan")]
struct ScanCommand {}

/// Host file on local network via Redit
#[derive(FromArgs)]
#[argh(subcommand, name = "host")]
struct HostCommand {
    #[argh(positional)]
    path: std::path::PathBuf,

    #[argh(positional)]
    name: String,

    /// make the content available to everyone
    #[argh(switch)]
    no_passphrase: bool,

    /// use a custom passphrase forcibly
    #[argh(option)]
    passphrase: Option<String>,
}

fn main() {
    log_info("Starting Redit");

    let cli: Cli = argh::from_env();
    if cli.command.is_none() {
        log_error("No command line arguments provided! Try `redit help`");
        return;
    }

    // Match the provided command line argument

    let command = cli.command.unwrap();
    match command {
        Commands::Scan(_command) => client::scan(),
        Commands::Host(command) => server::host(
            command.no_passphrase,
            command.path,
            command.name,
            command.passphrase,
        ),
    }
}
