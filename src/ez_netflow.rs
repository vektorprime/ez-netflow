

use std::net::{UdpSocket, SocketAddr};
use std::net::{Ipv4Addr, IpAddr};
use std::convert::TryInto;
use std::io::{Error,ErrorKind, Result};
use std::str::FromStr;

#[derive(Copy, Clone)]
pub enum NetflowVersion {
    V5(u16),
    V9(u16)
}

//enabled is the order
//value is actual payload
#[derive(Copy, Clone)]
pub enum U8Field {
    Disabled,
    Enabled(u16),
    Value(u8),
}

#[derive(Copy, Clone)]
pub enum U16Field {
    Disabled,
    Enabled(u16),
    Value(u16),
}

#[derive(Copy, Clone)]
pub enum U32Field {
    Disabled,
    Enabled(u16),
    Value(u32),
}

#[derive(Copy, Clone)]
pub enum Ipv4Field {
    Disabled,
    Enabled(u16),
    Value(Ipv4Addr),
}


#[derive(Copy, Clone, Default)]
pub struct NetflowTemplate {
    //no mpls, mpls, or application
    pub id: Option<u16>,
    pub count: Option<u16>,
    pub in_octets: Option<U32Field>, /// Can be higher
    pub in_packets: Option<U32Field>, /// Can be higher
    pub flows: Option<U32Field>, /// Can be higher   
    pub protocol: Option<U8Field>,
    pub src_tos: Option<U8Field>,
    pub tcp_flags: Option<U8Field>,
    pub src_port: Option<U16Field>,
    pub src_addr: Option<Ipv4Field>,
    pub src_mask: Option<U8Field>,
    pub input_snmp: Option<U16Field>, /// Can be higher
    pub dst_port: Option<U16Field>,
    pub dst_addr: Option<Ipv4Field>,
    pub dst_mask: Option<U8Field>, /// Can be higher 
    pub output_snmp: Option<U16Field>,
    pub ipv4_next_hop: Option<Ipv4Field>,  
    // src_as: Option<U32Field>, //can be higher         
    // dst_as: Option<U32Field>, //can be higher    
    // bgp_next_hop: Ipv4Field,
    pub mul_dst_pkts: Option<U32Field>, /// Can be higher
    pub mul_dst_bytes: Option<U32Field>, /// Can be higher
    pub last_switched: Option<U32Field>, 
    pub first_switched: Option<U32Field>,
    pub out_bytes: Option<U32Field>, /// Can be higher
    pub out_pkts: Option<U32Field>,  /// Can be higher
    pub min_pkt_lngth: Option<U16Field>, 
    pub max_pkt_lngth: Option<U16Field>,
    pub icmp_type: Option<U16Field>,
    pub mul_igmp_type: Option<U8Field>,
    // total_bytes_exp: U32Field,
    // total_pkts_exp: U32Field,
    // total_flows_exp: U32Field, 
    // ipv4_src_prefix: U32Field,
    // ipv4_dst_prefix: U32Field,
    // mpls_top_label_type: u8,
    // mpls_top_label_ip_addr: U32Field,
    pub min_ttl: Option<U8Field>,
    pub max_ttl: Option<U8Field>,
    pub ipv4_ident: Option<U16Field>,
    pub dst_tos: Option<U8Field>,
    pub in_src_mac: Option<[U8Field; 6]>,
    pub out_dst_mac: Option<[U8Field; 6]>,
    pub src_vlan: Option<U16Field>,
    pub dst_vlan: Option<U16Field>,
    pub ip_version: Option<U8Field>,
    pub direction: Option<U8Field>,
    pub in_dst_mac: Option<[U8Field; 6]>,
    pub out_src_mac: Option<[U8Field; 6]>,
    //if_name: u64, //not sure since it's specified in the template
    //if_desc: u64, //not sure since it's specified in the template
    in_permanent_bytes: Option<U32Field>, /// Can be higher
    in_permanent_pkts: Option<U32Field>, /// Can be higher
    fragment_offset: Option<U16Field>,
    forwarding_status: Option<U8Field>,
    replication_factor: Option<U32Field>,
    //nothing for l2_packet section yet
}

#[derive(Copy, Clone)]
pub struct NetflowPacket {
    pub version: NetflowVersion,
    pub count: u16,
    pub sys_uptime: u32,
    pub timestamp: u32,
    pub flow_sequence: u32,
    pub source_id: u32,
    //flowsetid when using options its zero, when has flows its greater than 255
    pub flowset_id: u16,
    pub flow_length: u16,
    pub flow_template: Option<NetflowTemplate>,

}

#[derive(Copy, Clone)]
pub struct NetflowSender {
    pub ip_addr: Ipv4Addr,
    pub active_template: NetflowTemplate,
}

pub struct NetflowServer {
    pub initial_template_received: bool,
    pub socket: UdpSocket,
    pub receive_buffer: [u8; 2500],
    // //may need to move these around as a tuple for multiple netflow senders
    // pub byte_count: usize,
    // pub source_address: SocketAddr,
    pub senders: Vec<NetflowSender>,
}

pub fn convert_socket_to_ipv4(source_address: SocketAddr) -> Ipv4Addr {
    let new_sender_ip_general: IpAddr = source_address.ip();
    let new_sender_str  = new_sender_ip_general.to_string();
    Ipv4Addr::from_str(new_sender_str.as_str())
        .expect("Unable to convert string to ipv4")
}

impl NetflowServer {
    pub fn new(addr_and_port: &str) -> Self {
        NetflowServer {
            initial_template_received: false,
            socket: UdpSocket::bind(addr_and_port)
                .expect("Unable to bind socket"),
            receive_buffer: [0; 2500],
            senders: Vec::new(),
        }
    }

    pub fn run(&mut self) {
            //todo
            //parse_flow_template
            //build netflow packet
            //update sender
            //receive and parse data

        let (byte_count, source_address) =  self.wait_for_initial_template();
        let template: NetflowTemplate = self.parse_flow_template(byte_count);
        self.update_or_create_sender(source_address, template);

        loop {
            //only account for 1 sender atm
            let (byte_count, source_address) = self.wait_for_netflow_data();
            let sender_result =  self.match_sender(byte_count, source_address);
            let sender: NetflowSender = match sender_result {
                Ok(ok) => {
                    ok
                },
                Err(e) => {
                    println!("ERROR {e}");
                    continue;
                }
            };
            self.parse_flow_data(byte_count, sender);
            //netflow_packet = self.build_netflow_packet();

        }


    }

    pub fn update_or_create_sender(&mut self, source_address: SocketAddr, template: NetflowTemplate) {
        //check if sender exists
        //create sender and add to vec
        let mut found_sender = false;
        let new_sender_ip = convert_socket_to_ipv4(source_address);
        let vec_len = self.senders.len();
        for x in 0..vec_len {
            if self.senders[x] .ip_addr == new_sender_ip {
                println!("Found the source in the senders vector");
                found_sender = true;
                break;
            }
        }
        if (!found_sender) {
            
            let new_sender = NetflowSender {
                ip_addr: new_sender_ip,
                active_template: template,
            };
            self.senders.push(new_sender);
        }
    }

    fn decode_and_enable_field(&self, field_id: u16,order: u16, received_template: &mut NetflowTemplate) {
        match field_id {
            1 => {
                println!("Field id 1 is IN_BYTES");
                received_template.in_octets = Some(U32Field::Enabled(order));
            },
            2 => {
                println!("Field id 2 is IN_PKTS");
                received_template.in_packets = Some(U32Field::Enabled(order));
            },
            3 => {
                println!("Field id 3 is FLOWS");
                received_template.flows = Some(U32Field::Enabled(order));
            },
            4 => {
                println!("Field id 4 is PROTOCOL");
                received_template.protocol = Some(U8Field::Enabled(order));
            },
            5 => {
                println!("Field id 5 is SRC_TOS");
                received_template.src_tos = Some(U8Field::Enabled(order));
            },
            6 => {
                println!("Field id 6 is TCP_FLAGS");
                received_template.tcp_flags = Some(U8Field::Enabled(order));
            },
            7 => {
                println!("Field id 7 is SRC_PORT");
                received_template.src_port = Some(U16Field::Enabled(order));
            },
            8 => {
                println!("Field id 8 is SRC_ADDR");
                received_template.src_addr = Some(Ipv4Field::Enabled(order));
            },
            9 => {
                println!("Field id 9 is SRC_MASK");
                received_template.src_mask = Some(U8Field::Enabled(order));
            },
            10 => {
                println!("Field id 10 is INPUT_SNMP");
                received_template.input_snmp = Some(U16Field::Enabled(order));
            },
            11 => {
                println!("Field id 11 is DST_PORT");
                received_template.dst_port = Some(U16Field::Enabled(order));
            },
            12 => {
                println!("Field id 12 is DST_ADDR");
                received_template.dst_addr = Some(Ipv4Field::Enabled(order));
            },
            13 => {
                println!("Field id 13 is DST_MASK");
                received_template.dst_mask = Some(U8Field::Enabled(order));
            },
            14 => {
                println!("Field id 14 is OUTPUT_SNMP");
                received_template.output_snmp = Some(U16Field::Enabled(order));
            },
            15 => {
                println!("Field id 15 is NEXT_HOP");
                received_template.ipv4_next_hop = Some(Ipv4Field::Enabled(order));
            },
            _ => {
                println!("Unsure of the field id {field_id}");
            },
        }
    }
    
    pub fn start_receiving(&mut self) -> (usize, SocketAddr) {
        self.socket.recv_from(&mut self.receive_buffer)
            .expect("Error receiving from the socket")
    }


    // pub fn build_netflow_packet(&self, byte_count: usize) -> NetflowPacket {
    //     netflow_packet = self.parse_packet_header();
    // }

    // pub fn parse_packet_header(&mut self, byte_count: usize) -> NetflowPacket {
    //     //todo
    // }


    pub fn parse_flow_template(&mut self, byte_count: usize) -> NetflowTemplate {
        //if flowset id == 0, it's a template
        //the udp receive func starts us at byte 30 because that's the udp payload
        //byte 20 and 21 in the payload are the flowset ID,
        //thus, if the u16 at byte 20 and 21 is 0 it's a template, else it's data
    
        let message: &[u8]  = &self.receive_buffer[..byte_count];
        println!("Parsing...");

        let mut received_template = NetflowTemplate {
            ..Default::default()
        };
        //flowset length
        let data_len_slice: &[u8]  = &message[22..24];
        let data_len_array: [u8; 2] = data_len_slice.try_into().expect("Unable to convert data_len_slice to array");
        let data_len: u16 = u16::from_be_bytes(data_len_array);
        println!("The payload data_len is {data_len}");
    

        //template id
        let template_id_slice: &[u8]  = &message[24..26];
        let template_id_array: [u8; 2] = template_id_slice.try_into().expect("Unable to convert template_id_slice to array");
        let template_id: u16 = u16::from_be_bytes(template_id_array);
        println!("The payload template_id is {template_id}");
        received_template.id = Some(template_id);
    
        //field count
        let field_count_slice: &[u8]  = &message[26..28];
        let field_count_array: [u8; 2] = field_count_slice.try_into().expect("Unable to convert field_count_slice to array");
        let field_count: u16 = u16::from_be_bytes(field_count_array);
        println!("The payload field_count is {field_count}");
        //save the field count so we can easily iterate later
        received_template.count = Some(field_count);

        let mut start_slice: usize = 28;
        let mut end_slice: usize = 30;
        let mut inc_size: usize = 4;
        for x in 0..field_count  {
            let field_slice: &[u8]  = &message[start_slice..end_slice];
            let field_array: [u8; 2] = field_slice.try_into().expect("Unable to convert field_slice to array");
            let field_data: u16 = u16::from_be_bytes(field_array);
            println!("The payload field_slice for field {x} is {field_data}");
            //leaving 0 open because that means no order
            let order = x+1;
            self.decode_and_enable_field(field_data, order, &mut received_template);
            start_slice += inc_size;
            end_slice += inc_size;
        }

        self.initial_template_received = true;

        received_template

    }


    pub fn parse_flow_data(&self, byte_count: usize, sender: NetflowSender) {
        let message: &[u8]  = &self.receive_buffer[..byte_count];
        println!("Parsing...");

         //flowset length
         let data_len_slice: &[u8]  = &message[22..24];
         let data_len_array: [u8; 2] = data_len_slice.try_into().expect("Unable to convert data_len_slice to array");
         let data_len: u16 = u16::from_be_bytes(data_len_array);
         println!("The payload data_len is {data_len}");
     
 
         //template id
         let template_id_slice: &[u8]  = &message[24..26];
         let template_id_array: [u8; 2] = template_id_slice.try_into().expect("Unable to convert template_id_slice to array");
         let template_id: u16 = u16::from_be_bytes(template_id_array);
         println!("The payload template_id is {template_id}");

       
         //field count
         let field_count_slice: &[u8]  = &message[26..28];
         let field_count_array: [u8; 2] = field_count_slice.try_into().expect("Unable to convert field_count_slice to array");
         let field_count: u16 = u16::from_be_bytes(field_count_array);
         println!("The payload field_count is {field_count}");

    }

    // pub fn wait_for_initial_template(&mut self) -> NetflowTemplate {

    //     //need initial template data
    //     loop {
    //         let (byte_count, source_address) = self.start_receiving();
    //         match check_packet_size(byte_count) {
    //             Ok(x) => {
    //                 println!("The packet size is valid");
    //             },
    //             Err(e) => {
    //                 println!("The packet size too small, skipping this packet");
    //                 continue;
    //             }
    //         }
            
    //         let received_message: &[u8]  = &self.receive_buffer[..byte_count];
    //         if received_message[20] == 0 && received_message[21] == 0 {
    //             println!("Received data is a flow template");
    //             println!("Parsing...");
    //             let test_netflow_template = self.parse_flow_template(received_message, byte_count);
    //             self.initial_template_received = true;
    //             return test_netflow_template;
    //         }
    //         else {
    //             println!("Received data is not a flow template, waiting for template");
    //         }
    //     }
      
    //     //account for template changing
    // }

    pub fn wait_for_initial_template(&mut self) -> (usize, SocketAddr)  {

        //need initial template data
        loop {
            let (byte_count, source_address) = self.start_receiving();
            match check_packet_size(byte_count) {
                Ok(x) => {
                    println!("The packet size is valid");
                },
                Err(e) => {
                    println!("The packet size too small, skipping this packet");
                    continue;
                }
            }
            
            let received_message: &[u8]  = &self.receive_buffer[..byte_count];
            //byte 20 and 21 being zeroed means this is a template
            if received_message[20] == 0 && received_message[21] == 0 {
                println!("Received data is a flow template");
                return (byte_count, source_address);
            }
            else {
                println!("Received data is not a flow template, waiting for template");
            }
        }
      
        //account for template changing
    }

    pub fn wait_for_netflow_data(&mut self) -> (usize, SocketAddr) {
         //need initial template data
         loop {
            let (byte_count, source_address) = self.start_receiving();
            match check_packet_size(byte_count) {
                Ok(x) => {
                    println!("The packet size is valid");
                },
                Err(e) => {
                    println!("The packet size too small, skipping this packet");
                    continue;
                }
            }
            
            let received_message: &[u8]  = &self.receive_buffer[..byte_count];
            //byte 20 and 21 being zeroed means this is a template
            if received_message[20] != 0 && received_message[21] != 0 {
                println!("Received data is a netflow data");
                return (byte_count, source_address);
            }
            else {
                println!("Received data is not netflow data");
            }
        }
    }

    pub fn match_sender(&self, byte_count: usize, source_address: SocketAddr) -> std::result::Result<NetflowSender, std::io::Error> {
        let mut found_sender = false;
        let sender_ip = convert_socket_to_ipv4(source_address);
        let vec_len = self.senders.len();
        for x in 0..vec_len {
            if self.senders[x] .ip_addr == sender_ip {
                println!("Found the source in the senders vector");
                println!("Sender is {sender_ip}");
                let sender = self.senders[x];
                return Ok(sender);
            }
        }
        Err(Error::new(ErrorKind::AddrNotAvailable, "Sender not found"))
    }
        
        

}

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

