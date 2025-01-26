mod client;
mod encryption;
mod logger;
mod scan;
mod scan2;
mod server;
mod types;
mod utils;
mod words;
use argh::FromArgs;
use logger::log_info;

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
    let cli: Cli = argh::from_env();
    log_info("Starting Redit");

    if let Some(command) = cli.command {
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
}
