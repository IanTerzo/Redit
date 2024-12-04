mod scan;

mod upload;
use upload::{host};
mod types;
mod words;
mod encryption;

use argh::FromArgs;

/// Redit file sharing
#[derive(FromArgs)]
struct Cli {
    /// verbose output
    #[argh(switch, short = 'V')]
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
struct ScanCommand {
}

/// Host file on local network via Redit
#[derive(FromArgs)]
#[argh(subcommand, name = "host")]
struct HostCommand {
    #[argh(positional)]
    path: std::path::PathBuf,

    /// make the content available to everyone
    #[argh(switch)]
    no_passphrase: bool,

    /// use a custom passphrase forcibly
    #[argh(option)]
    passphrase: Option<String>,
}

fn main() {
    println!("Getting hosts...");
    let hosts = scan::scan_network(6969, 1000);

    println!("Hosts: {:?}", hosts);
}

