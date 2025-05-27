use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;
use chrono::prelude::*;

use crate::templates::*;
use crate::fields::*;
use crate::sql::*;
use crate::utils::*;



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
            println!("Src IP is {} and Dst IP is {}", flow.src_ip, flow.dst_ip );
            println!("Src Port is {} and Dst Port is {}", flow.src_ip, flow.dst_ip);
            println!("Protocol is {}", flow.protocol);
            println!("Bytes/octets are {}", flow.in_octets );
            println!("Packets are {}", flow.in_packets);
            println!("End flow data");

        }
    }
  


    pub fn parse_packet_to_flow(&mut self) {
        while let Some(pkt) = self.flow_packets.pop() {
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

                    // let s_and_d_ip: (Ipv4Addr, Ipv4Addr) = (
                    //     match pkt.src_addr {
                    //         Some(Ipv4Field::Value(v)) => { v },
                    //         _ => Ipv4Addr::UNSPECIFIED,
                    //     },
                    //     match pkt.dst_addr {
                    //         Some(Ipv4Field::Value(v)) => { v },
                    //         _ => Ipv4Addr::UNSPECIFIED,
                    //     }
                    // );

                    let src_ip: Ipv4Addr = match pkt.src_addr {
                        Some(Ipv4Field::Value(v)) => { v },
                        _ => Ipv4Addr::UNSPECIFIED,
                    };

                    let dst_ip: Ipv4Addr = match pkt.dst_addr {
                        Some(Ipv4Field::Value(v)) => { v },
                        _ => Ipv4Addr::UNSPECIFIED,
                    };

                    let src_port: u16 = match pkt.src_port {
                        Some(U16Field::Value(v)) => { v },
                        _ => 0,
                    };

                    let dst_port: u16 = match pkt.dst_port {
                        Some(U16Field::Value(v)) => { v },
                        _ => 0,
                    };

                    // let s_and_d_port: (u16, u16) = (
                    //     match pkt.src_port {
                    //         Some(U16Field::Value(v)) => { v },
                    //         _ => 0,
                    //     },
                    //     match pkt.dst_port {
                    //         Some(U16Field::Value(v)) => { v },
                    //         _ => 0,
                    //     }
                    // );

                    let cast: TrafficType = match pkt.in_dst_mac {
                        Some(U64Field::Value(v)) => { 
                            let field_array: [u8; 8] = v.to_be_bytes();
                            //let field_array: [u8; 6] = field_array_64[..6];
                            let pkt_cast = handle_traffic_type_in_flow(src_ip, dst_ip);
                            if pkt_cast == TrafficType::Unicast && field_array[0] == 0xFF && field_array[1] == 0xFF
                            && field_array[2] == 0xFF && field_array[3] == 0xFF && field_array[4] == 0xFF && field_array[5] == 0xFF {
                                TrafficType::Broadcast
                            }
                            else {
                                pkt_cast
                            }
                        },
                        _ =>  {
                            handle_traffic_type_in_flow(src_ip, dst_ip)
                        },
                    };

                    let current_time = Local::now();
                    let mut updated_flow = false;
                    //look for existing flow and update
                    for flow in &mut self.flow_stats {
                        if is_flow_match(flow.src_ip, flow.dst_ip, src_ip, dst_ip,
                             flow.src_port, flow.dst_port, src_port, dst_port) {
                                //println!("updating existing flow");
                                //first update the delta vec for the flow so we can have the correct value when we update db later
                                //this separation is required to have both gui and cli displays
                                
                                let new_delta = NetFlowDelta {
                                  updated_time: current_time,
                                  in_octets: oct as i64,
                                  in_pkts: pk as i64,
                                  ..Default::default()
                                };
                                
                                flow.deltas.push(new_delta);
                                //add the delta here so we can display it in cli if required
                                flow.update_throughput();
                                flow.in_octets += oct;
                                flow.in_packets += pk;
                                updated_flow = true;
                                flow.needs_db_update = true;
                                break;
                        }
                    }

                    //no flow exists, create new
                    if !updated_flow {
                        //println!("flow_stats is empty, creating new flow");
                        let new_flow = NetFlow {
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            protocol: proto,
                            //Need to handle optional variants
                            in_octets: oct,
                            in_packets: pk,
                            in_db: false,
                            needs_db_update: true,
                            traffic_type: cast,
                            created_time: current_time,
                            //delta starts empty if the flow is new, it grows when flow is updated in for loop above
                            deltas: Vec::new(),
                        };
                        self.flow_stats.push(new_flow)
                    }

                
                // None => {
                //     //println!("Can't parse empty packet in parse_stats_on_packet, skipping");
                //     return;
                // }
            
        }
    }

 

    pub fn prepare_and_update_flow_in_db(&mut self, db_conn: &mut Arc<Mutex<Connection>>) {
        let sender_ip: String = String::from(&self.ip_addr.to_string());
        let mut db_conn_unlocked: MutexGuard<Connection> = db_conn.lock().unwrap();
        for flow in &mut self.flow_stats {
            // needs_db_update is required because this func and parse_packet_to_flow share overlap
            // upstream to this call we are iterating over senders, which would dup flow stats and create dup updated_times in db
            if flow.needs_db_update {
                flow.in_db = check_if_flow_exists_in_db(&mut db_conn_unlocked, flow);
                let current_time = Local::now();
                if !flow.in_db {
                    create_flow_in_db(&mut db_conn_unlocked, flow, &sender_ip, &current_time);
                    flow.in_db = true;
                    flow.needs_db_update = false;
                }
                else {
                    update_flow_in_db(&mut db_conn_unlocked, flow, &sender_ip, &current_time);
                    flow.needs_db_update = false;
                }
            }
            
        }
    }
}


pub fn merge_senders(received_senders: &Vec<NetflowSender>, global_senders: &mut Vec<NetflowSender>) {
    if global_senders.is_empty() {
        for s in received_senders {
            global_senders.push(s.clone());
        }
    }
    else {
        let mut temp_senders: Vec<NetflowSender> = Vec::new();

        for s in received_senders {
            let mut found = false;
            for g in &mut *global_senders {
                if s.ip_addr == g.ip_addr {
                    found = true;
                    //copy all flow packets into g.flow_packets vec to parse later
                    for pkt in &s.flow_packets {
                        g.flow_packets.push(pkt.clone());
                    }
                    // no longer need to look at global_senders
                    break;
                }
            }
            if !found {
                temp_senders.push(s.clone());
            }
        }

        if !temp_senders.is_empty() {
            global_senders.append(&mut temp_senders);
        }
        
    }

}