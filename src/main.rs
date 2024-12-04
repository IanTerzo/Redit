mod scan;

mod upload;
use upload::host;
mod types;
use types::UploaderInfo;
mod connect;
mod utils;

fn main() {
    println!("Getting hosts...");
    let hosts = scan::scan_network(6969, 1000);

    // Simulate user selecting a host
    let selected_host = &hosts[0];
    // let result = connect::connect_to_host(selected_host.clone(), Some("123".to_string()));
    let res = connect::wait_for_client_connection(Some(String::from("123")));

    println!("Hosts: {:?}", hosts);
}
