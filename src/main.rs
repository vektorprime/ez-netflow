use std::net::{UdpSocket, SocketAddr};
use std::net::Ipv4Addr;
use std::convert::TryInto;

mod ez_netflow;

use crate::ez_netflow::check_packet_size;


fn main() {

    let mut netflow_server = ez_netflow::NetflowServer::new("10.0.0.40:2055");
    netflow_server.wait_for_initial_template();

    let (byte_count, source_address) = netflow_server.start_receiving();
    println!("Received data");

    check_packet_size(byte_count);

    
}
