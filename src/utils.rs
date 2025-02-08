use std::net::{AddrParseError, IpAddr, Ipv4Addr};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::str::FromStr;

use crate::fields::TrafficType;

pub fn check_packet_size(byte_count: usize) -> Result<()> {
    //println!("checking packet size");
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

pub fn convert_string_to_ipv4(ip_string: &String) -> std::result::Result<Ipv4Addr, AddrParseError> {
     Ipv4Addr::from_str(ip_string.as_str().trim())
}

pub fn convert_ipv4_to_string(ip: Ipv4Addr) -> String {
    ip.to_string()
}


pub fn get_ip_cast_type(ip: Ipv4Addr) -> TrafficType {

    if ip.is_broadcast() { 
        TrafficType::Broadcast
    }
    else if ip.is_multicast() { 
        TrafficType::Multicast
    }
    else {
        TrafficType::Unicast
    }

}