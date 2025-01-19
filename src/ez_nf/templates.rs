use std::net::Ipv4Addr;

use crate::ez_nf::fields::*;


#[derive(Clone, Default)]
pub struct NetflowTemplate {
    //no mpls, mpls, or application
    pub parsed: bool,
    pub order_vec: Vec<FlowField>,
    pub id: Option<u16>,
    pub field_count: Option<u16>,
    pub in_octets: Option<U32Field>, /// Can be higher
    pub in_packets: Option<U32Field>, /// Can be higher
    pub flows: Option<U32Field>, /// Can be higher   
    pub protocol: Option<U8Field>,
    pub src_tos: Option<U8Field>,
    pub tcp_flags: Option<U8Field>,
    pub src_port: Option<U16Field>,
    pub src_addr: Option<Ipv4Field>,
    pub src_mask: Option<U8Field>,
    pub input_snmp: Option<U32Field>, /// Can be higher
    pub dst_port: Option<U16Field>,
    pub dst_addr: Option<Ipv4Field>,
    pub dst_mask: Option<U8Field>, /// Can be higher 
    pub output_snmp: Option<U32Field>,
    pub next_hop: Option<Ipv4Field>,  
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
    pub ident: Option<U16Field>,
    pub dst_tos: Option<U8Field>,
    pub in_src_mac: Option<U64Field>,
    pub out_dst_mac: Option<U64Field>,
    pub src_vlan: Option<U16Field>,
    pub dst_vlan: Option<U16Field>,
    pub ip_version: Option<U8Field>,
    pub direction: Option<U8Field>,
    pub in_dst_mac: Option<U64Field>,
    pub out_src_mac: Option<U64Field>,
    //if_name: u64, //not sure since it's specified in the template
    //if_desc: u64, //not sure since it's specified in the template
    in_permanent_bytes: Option<U32Field>, /// Can be higher
    in_permanent_pkts: Option<U32Field>, /// Can be higher
    fragment_offset: Option<U16Field>,
    forwarding_status: Option<U8Field>,
    replication_factor: Option<U32Field>,
    //nothing for l2_packet section yet
}



pub struct NetFlow {
    pub src_and_dst_ip: (Ipv4Addr, Ipv4Addr),
    pub src_and_dst_port: (u16, u16),
    pub protocol: u8,
    pub in_octets: u32,
    pub in_packets: u32,
}


#[derive(Clone)]
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