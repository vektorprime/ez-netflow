use std::net::{UdpSocket, SocketAddr};
use std::net::Ipv4Addr;
use std::convert::TryInto;


mod ez_nf;

use ez_nf::server::NetflowServer;

fn main() {

    let mut netflow_server = NetflowServer::new("10.0.0.40:2055");
    netflow_server.run();
    
    
}
