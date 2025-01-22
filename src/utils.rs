use std::net::{Ipv4Addr, IpAddr};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::str::FromStr;

pub fn check_packet_size(byte_count: usize) -> Result<()> {
    println!("checking packet size");
    let min_pkt_size: usize = 20;
    if byte_count < min_pkt_size {
        Err(Error::new(ErrorKind::InvalidData, "Packet is too small"))
    }
    else {
        Ok(())
    }

}

pub fn convert_socket_to_ipv4(source_address: SocketAddr) -> Ipv4Addr {
    let new_sender_ip_general: IpAddr = source_address.ip();
    let new_sender_str  = new_sender_ip_general.to_string();
    Ipv4Addr::from_str(new_sender_str.as_str())
        .expect("Unable to convert string to ipv4")
}
