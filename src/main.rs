use std::net::{UdpSocket, SocketAddr};
use std::net::Ipv4Addr;
use std::convert::TryInto;


mod server;
mod fields;
mod templates;
mod senders;
mod utils;


use server::NetflowServer;

fn main() {

    let mut netflow_server = NetflowServer::new("10.0.0.40:2055");
    netflow_server.run();
    
    
}
