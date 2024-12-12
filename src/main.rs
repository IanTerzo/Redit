mod connect;
mod encryption;
mod scan;
mod types;
mod upload;
mod utils;
mod words;
use argh::FromArgs;
use std::io;
use types::UploaderInfo;

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
struct ScanCommand {}

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
    let cli: Cli = argh::from_env();

    if let Some(command) = cli.command {
        match command {
            // Nils fixar detta -
            Commands::Scan(_command) => {
                let availible_hosts = scan::scan_network(1000);
                println!("{:#?}", availible_hosts); // Visa upp de fint.
                println!("Choose a host to connect to 0 - 10: ");

                let mut input = String::new();

                io::stdin()
                    .read_line(&mut input)
                    .expect("Failed to read line");

                let index: usize = input.trim().parse().unwrap();
                let selected = availible_hosts[index].clone();
                if selected.0.public == false {
                    // password sharing
                    connect::connect_to_host(selected.1, "pass".to_string());
                } else {
                    //idk
                }
            }
            Commands::Host(_command) => {
                println!("Password");
                // Todo: Ask if it needs to be private or public, it assumes private now

                let mut password = String::new();

                io::stdin()
                    .read_line(&mut password)
                    .expect("Failed to read line");

                let password = password.trim().to_string();

                let info = UploaderInfo {
                    public: false,
                    name: "Ian".to_string(),
                    files_size: 3,
                    public_key: Some("testpublickey".to_string()),
                };

                upload::host(info, Some(password))
            }
        }
    }
}