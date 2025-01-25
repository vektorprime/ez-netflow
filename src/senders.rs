use std::net::Ipv4Addr;
use crate::templates::*;
use crate::fields::*;



#[derive(Clone)]
pub struct NetflowSender {
    pub ip_addr: Ipv4Addr,
    pub active_template: NetflowTemplate,
    pub flow_packets: Vec<NetflowTemplate>,
    pub flow_stats:  Vec<NetFlow>,
}


impl NetflowSender {
    // pub fn new(new_sender_ip: Ipv4Addr, template: NetflowTemplate) -> Self {
    //     NetflowSender {
    //         ip_addr: new_sender_ip,
    //         active_template: template,
    //         flow_packets: Vec::new(),
    //         flow_stats: Vec::new(),
    //     }
    // }

    pub fn report_flow_stats(&self) {

          //look for existing flow and update
          for flow in &self.flow_stats {
            println!("Start flow data...");
            println!("Src IP is {} and Dst IP is {}", flow.src_and_dst_ip.0, flow.src_and_dst_ip.1 );
            println!("Protocol is {}", flow.protocol);
            println!("Bytes/octets are {}", flow.in_octets );
            println!("Packets are {}", flow.in_packets);
            println!("End flow data");

        }
    }
    
    pub fn parse_packet_to_flow(&mut self) {
        let packet_result = self.flow_packets.pop();
        match packet_result {
            Some(pkt) => {
                //println!("parsing packet to flow");

                //get tuple
                //Need to handle optional variants
                let proto: u8 = match pkt.protocol {
                    Some(U8Field::Value(v)) => { v },
                    _ => 0,
                };
                
                let oct: u32 = match pkt.in_octets {
                    Some(U32Field::Value(v)) => { v },
                    _ => 0,
                };

                let pk: u32 = match pkt.in_packets {
                    Some(U32Field::Value(v)) => { v },
                    _ => 0,
                };

                let s_and_d_ip: (Ipv4Addr, Ipv4Addr) = (
                    match pkt.src_addr {
                        Some(Ipv4Field::Value(v)) => { v },
                        _ => Ipv4Addr::UNSPECIFIED,
                    },
                    match pkt.dst_addr {
                        Some(Ipv4Field::Value(v)) => { v },
                        _ => Ipv4Addr::UNSPECIFIED,
                    }
                );

                let s_and_d_port: (u16, u16) = (
                    match pkt.src_port {
                        Some(U16Field::Value(v)) => { v },
                        _ => 0,
                    },
                    match pkt.dst_port {
                        Some(U16Field::Value(v)) => { v },
                        _ => 0,
                    }
                );

                let mut updated_flow = false;
                //look for existing flow and update
                for flow in &mut self.flow_stats {
                    if flow.src_and_dst_ip == s_and_d_ip && 
                        flow.src_and_dst_port == s_and_d_port &&
                        flow.protocol == proto {

                        //println!("updating existing flow");
                        flow.in_octets += oct;
                        flow.in_packets += pk;
                        updated_flow = true;
                    
                    }
                }

                //no flows
                //create new flow
                if !updated_flow {
                    //println!("flow_stats is empty, creating new flow");
                    let new_flow = NetFlow {
                        src_and_dst_ip: s_and_d_ip,
                        src_and_dst_port: s_and_d_port,
                        protocol: proto,
                        //Need to handle optional variants
                        in_octets: oct,
                        in_packets: pk,
                    };
                    self.flow_stats.push(new_flow)
                }

            },
            None => {
                //println!("Can't parse empty packet in parse_stats_on_packet, skipping");
                return;
            }
        };
    }
}


pub fn merge_senders(received_senders: Vec<NetflowSender>, global_senders: &mut Vec<NetflowSender>) {
    if global_senders.is_empty() {
        for s in received_senders {
            global_senders.push(s.clone());
        }
    }
    else {
        let mut temp_senders: Vec<NetflowSender> = Vec::new();

        for s in &received_senders {
            let mut found = false;
            for g in &mut *global_senders {
                if s.ip_addr == g.ip_addr {
                    found = true;
                    //copy all flows into g.flow_stats vec
                    for flow in &s.flow_stats {
                        g.flow_stats.push(flow.clone());
                    }
                    // no longer need to look at global_senders
                    break;
                }
            }
            if !found {
                temp_senders.push(s.clone());
            }
        }

        global_senders.append(&mut temp_senders);
    }

}