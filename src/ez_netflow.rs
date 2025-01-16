

use std::net::{UdpSocket, SocketAddr};
use std::net::Ipv4Addr;
use std::convert::TryInto;
use std::io::{Error,ErrorKind, Result};
//use std::io::ErrorKind;
//use std::io::Error;

pub enum NetflowVersion {
    V5(u16),
    V9(u16)
}


#[derive(Debug, Default)]
pub struct NetflowTemplate {
    //no mpls, mpls, or application
    pub in_octets: Option<u32>, /// Can be higher
    pub in_packets: Option<u32>, /// Can be higher
    pub flows: Option<u32>, /// Can be higher   
    pub protocol: Option<u8>,
    pub src_tos: Option<u8>,
    pub tcp_flags: Option<u8>,
    pub src_port: Option<u16>,
    pub src_addr: Option<Ipv4Addr>,
    pub src_mask: Option<u8>,
    pub input_snmp: Option<u16>, /// Can be higher
    pub dst_port: Option<u16>,
    pub dst_addr: Option<Ipv4Addr>,
    pub dst_mask: Option<u8>, /// Can be higher 
    pub output_snmp: Option<u16>,
    pub ipv4_next_hop: Option<Ipv4Addr>,  
    // src_as: Option<u32>, //can be higher         
    // dst_as: Option<u32>, //can be higher    
    // bgp_next_hop: IPv4Addr,
    pub mul_dst_pkts: Option<u32>, /// Can be higher
    pub mul_dst_bytes: Option<u32>, /// Can be higher
    pub last_switched: Option<u32>, 
    pub first_switched: Option<u32>,
    pub out_bytes: Option<u32>, /// Can be higher
    pub out_pkts: Option<u32>,  /// Can be higher
    pub min_pkt_lngth: Option<u16>, 
    pub max_pkt_lngth: Option<u16>,
    pub icmp_type: Option<u16>,
    pub mul_igmp_type: Option<u8>,
    // total_bytes_exp: u32,
    // total_pkts_exp: u32,
    // total_flows_exp: u32, 
    // ipv4_src_prefix: u32,
    // ipv4_dst_prefix: u32,
    // mpls_top_label_type: u8,
    // mpls_top_label_ip_addr: u32,
    pub min_ttl: Option<u8>,
    pub max_ttl: Option<u8>,
    pub ipv4_ident: Option<u16>,
    pub dst_tos: Option<u8>,
    pub in_src_mac: Option<[u8; 6]>,
    pub out_dst_mac: Option<[u8; 6]>,
    pub src_vlan: Option<u16>,
    pub dst_vlan: Option<u16>,
    pub ip_version: Option<u8>,
    pub direction: Option<u8>,
    pub in_dst_mac: Option<[u8; 6]>,
    pub out_src_mac: Option<[u8; 6]>,
    //if_name: u64, //not sure since it's specified in the template
    //if_desc: u64, //not sure since it's specified in the template
    in_permanent_bytes: Option<u32>, /// Can be higher
    in_permanent_pkts: Option<u32>, /// Can be higher
    fragment_offset: Option<u16>,
    forwarding_status: Option<u8>,
    replication_factor: Option<u32>,
    //nothing for l2_packet section yet
    //https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html#:~:text=The%20FlowSet%20ID%20is%20used,a%20FlowSet%20ID%20of%201.
}

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


pub struct NetflowServer {
    pub initial_template_received: bool,
    pub socket: UdpSocket,
    pub receive_buffer: [u8; 2500],
    // //may need to move these around as a tuple for multiple netflow senders
    // pub byte_count: usize,
    // pub source_address: SocketAddr,
}

impl NetflowServer {
    pub fn new(addr_and_port: &str) -> Self {
        NetflowServer {
            initial_template_received: false,
            socket: UdpSocket::bind(addr_and_port)
            .expect("Unable to bind socket"),
            receive_buffer: [0; 2500],
        }
    }

    fn decode_field(&self, field_id: u16) {
        match field_id {
            1 => {println!("Field id 1 is IN_BYTES")},
            2 => {println!("Field id 2 is IN_PKTS")},
            3 => {println!("Field id 3 is FLOWS")},
            4 => {println!("Field id 4 is PROTOCOL")},
            5 => {println!("Field id 5 is SRC_TOS")},
            6 => {println!("Field id 6 is TCP_FLAGS")},
            7 => {println!("Field id 7 is SRC_PORT")},
            8 => {println!("Field id 8 is SRC_ADDR")},
            9 => {println!("Field id 9 is SRC_MASK")},
            10 => {println!("Field id 10 is INPUT_SNMP")},
            11 => {println!("Field id 11 is DST_PORT")},
            12 => {println!("Field id 12 is DST_ADDR")},
            13 => {println!("Field id 13 is DST_MASK")},
            14 => {println!("Field id 14 is OUTPUT_SNMP")},
            15 => {println!("Field id 15 is NEXT_HOP")},
            _ => {println!("Unsure of the field id {field_id}")},
        }
    }
    
    pub fn start_receiving(&mut self) -> (usize, SocketAddr) {
        self.socket.recv_from(&mut self.receive_buffer).expect("Error receiving from the socket")
    }


    // pub fn parse_netflow_packet(&self, message: &[u8], buffer_len: usize) -> NetflowPacket {

    // }

    //fn parse_flow_template(message: &[u8], buffer_len: usize) -> NetflowTemplate {
    pub fn parse_flow_template(&self, message: &[u8], buffer_len: usize) -> NetflowTemplate {
        //if flowset id == 0, it's a template
        //the udp receive func starts us at byte 30 because that's the udp payload
        //byte 20 and 21 in the payload are the flowset ID,
        //thus, if the u16 at byte 20 and 21 is 0 it's a template, else it's data
    
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

        let mut start_slice: usize = 28;
        let mut end_slice: usize = 30;
        let mut inc_size: usize = 4;
        for x in 0..field_count  {
            let field_slice: &[u8]  = &message[start_slice..end_slice];
            let field_array: [u8; 2] = field_slice.try_into().expect("Unable to convert field_slice to array");
            let field_data: u16 = u16::from_be_bytes(field_array);
            println!("The payload field_slice for field {x} is {field_data}");
            self.decode_field(field_data);
            start_slice += inc_size;
            end_slice += inc_size;
        }



        NetflowTemplate {
            protocol: Some(1),
            
            src_addr: Some(Ipv4Addr::LOCALHOST),
            ..Default::default()
        }
    }




    pub fn wait_for_initial_template(&mut self) -> NetflowTemplate {

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
            if received_message[20] == 0 && received_message[21] == 0 {
                println!("Received data is a flow template");
                println!("Parsing...");
                let test_netflow_template = self.parse_flow_template(received_message, byte_count);
                self.initial_template_received = true;
                return test_netflow_template;
            }
            else {
                println!("Received data is not a flow template, waiting for template");
            }
        }
      
        //account for template changing
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

