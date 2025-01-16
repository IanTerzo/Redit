# Redit File Sharing CLI

Redit is a file-sharing application that allows you to host and scan for files on a local network. This CLI provides commands to host files and scan the network for available hosts.

```

## Usage

The Redit CLI has two main commands: `scan` and `host`.

### Scan Command

The `scan` command scans the local network for available Redit distributors.

#### Usage

```sh
cargo run -- scan
```

#### Example

```sh
cargo run -- scan
```

This will output a list of available hosts. You will be prompted to choose a host to connect to and provide a password if required.

### Host Command

The `host` command allows you to host a file on the local network via Redit.

#### Usage

```sh
cargo run -- host <path> <name> [--no-passphrase] [--passphrase <passphrase>]
```

- `<path>`: The path to the file you want to host.
- `<name>`: The name of the file.
- `--no-passphrase`: Make the content available to everyone without a passphrase.
- `--passphrase <passphrase>`: Use a custom passphrase forcibly.

#### Example

```sh
cargo run -- host /path/to/file "My File" --no-passphrase
```

or

```sh
cargo run -- host /path/to/file "My File" --passphrase "mysecretpassphrase"
```