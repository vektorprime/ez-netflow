use std::net::{AddrParseError, IpAddr, Ipv4Addr};
use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;
use std::str::FromStr;

use crate::templates::*;
use crate::fields::*;

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

// pub fn is_flow_match(flow_ip: (Ipv4Addr, Ipv4Addr), pkt_ip: (Ipv4Addr, Ipv4Addr), flow_port: (u16, u16), pkt_port: (u16, u16)) -> bool {
//     // Matches IPs bidirectionally
//    let ip_match = (flow.src_ip == pkt_src_ip && flow.dst_ip == pkt_dst_ip) || 
//    (flow.src_ip == pkt_dst_ip && flow.dst_ip == pkt_src_ip);

//    // Matches Ports bidirectionally
//    let port_match = (flow_port.0 == pkt_port.0 && flow_port.1 == pkt_port.1) || 
//        (flow_port.0 == pkt_port.1 && flow_port.1 == pkt_port.0);

//    ip_match && port_match
// }

pub fn is_flow_match(flow_src_ip: Ipv4Addr, flow_dst_ip: Ipv4Addr, pkt_src_ip: Ipv4Addr, pkt_dst_ip: Ipv4Addr, 
    flow_src_port: u16, flow_dst_port: u16, pkt_src_port: u16, pkt_dst_port: u16) -> bool {
        // Matches IPs bidirectionally
        let ip_match = (flow_src_ip == pkt_src_ip && flow_dst_ip == pkt_dst_ip) || 
        (flow_src_ip == pkt_dst_ip && flow_dst_ip == pkt_src_ip);

        // Matches Ports bidirectionally
        let port_match = (flow_src_port == pkt_src_port && flow_dst_port == pkt_dst_port) || 
            (flow_src_port == pkt_dst_port && flow_dst_port == pkt_src_port);

        ip_match && port_match
}


pub fn handle_icmp_code(protocol: i32, src_port:i32, dst_port:i32) -> (String, i32, i32) {
    //returning tuple in case I want to actually return type and code later
    if protocol == 1 {
        if src_port == 0 && dst_port == 0 {
            ("ECHO_REPLY".to_string(), 0, 0)
        }
        else if src_port == 2048 || dst_port == 2048 {
            ("ECHO_REQ".to_string(), 0, 0)
        }
        else if src_port == 768 || dst_port == 768 {
            ("NET_UNRCH".to_string(), 0, 0)
        }
        else if src_port == 769 || dst_port == 769 {
            ("HOST_UNRCH".to_string(), 0, 0)
        }
        else if src_port == 770 || dst_port == 770 {
            ("PROTO_UNRCH".to_string(), 0, 0)
        }
        else if src_port == 771 || dst_port == 771 {
            ("PORT_UNRCH".to_string(), 0, 0)
        }
        else {
            ("NOT_SURE".to_string(), src_port, dst_port)
        }
    }
    else {
    ("NONE".to_string(), src_port, dst_port)
    }

}

pub fn handle_traffic_type(flow: &NetFlow) -> String {
    //returning tuple in case I want to actually return type and code later

    //This only partially works because we don't know the mask for some broadcast traffic 
    //e.g. 10.0.0.255 could be valid unicast in a /16.

    let src_ip_cast = get_ip_cast_type(flow.src_ip);
    let dst_ip_cast = get_ip_cast_type(flow.dst_ip);

    //let dst_mac = flow.

    if src_ip_cast == TrafficType::Multicast || dst_ip_cast == TrafficType::Multicast {
        "Multicast".to_string()
    }
    else if src_ip_cast == TrafficType::Broadcast || dst_ip_cast == TrafficType::Broadcast {
        "Broadcast".to_string()
    }
    // else if src_ip_cast == TrafficType::Broadcast || dst_ip_cast == TrafficType::Broadcast {
    //     "Broadcast".to_string()
    // }
    else 
    {
        "Unicast".to_string()
    }

}

pub fn handle_traffic_type_in_flow(src_addr: Ipv4Addr, dst_addr: Ipv4Addr) -> TrafficType {

    let src_ip_cast = get_ip_cast_type(src_addr);
    let dst_ip_cast = get_ip_cast_type(dst_addr);


    if src_ip_cast == TrafficType::Multicast || dst_ip_cast == TrafficType::Multicast {
        TrafficType::Multicast
    }
    else if src_ip_cast == TrafficType::Broadcast || dst_ip_cast == TrafficType::Broadcast {
        TrafficType::Broadcast
    }
    else 
    {
        TrafficType::Unicast
    }

}
