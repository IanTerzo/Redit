mod scan;

fn main() {
    println!("Getting hosts...");
    let hosts = scan::scan_network(6969, 1000);

    println!("Hosts: {:?}", hosts);
}