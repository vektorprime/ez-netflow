

use std::net::{UdpSocket, SocketAddr};
use std::net::Ipv4Addr;
use std::convert::TryInto;
use std::io::{Error,ErrorKind};


use crate::ez_nf::fields::*;
use crate::ez_nf::senders::*;
use crate::ez_nf::templates::*;
use crate::ez_nf::utils::*;




pub struct NetflowServer {
    pub initial_template_received: bool,
    pub socket: UdpSocket,
    pub receive_buffer: [u8; 2500],
    // //may need to move these around as a tuple for multiple netflow senders
    // pub byte_count: usize,
    // pub source_address: SocketAddr,
    pub senders: Vec<NetflowSender>,
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
            let sender_index =  self.match_sender(byte_count, source_address).expect("Sender not found");
            self.parse_data_to_packet(byte_count, sender_index);
            //let test: &mut NetflowSender = &mut self.senders[0];
            let senders_len = self.senders.len();
            for x in 0..senders_len {
                self.senders[x].parse_packet_to_flow();
                self.senders[x].report_flow_stats();
            }
            

           
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
                flow_packets: Vec::new(),
                flow_stats: Vec::new(),
            };
            self.senders.push(new_sender);
        }
    }

    

    fn decode_field_order(&self, field_id: u16, received_template: &mut NetflowTemplate) {
        match field_id {
            1 => {
                println!("Field id 0 is IN_BYTES");
                //received_template.in_octets = Some(FlowField::InOctets());
                received_template.order_vec.push(FlowField::InOctets);
                
            },
            2 => {
                println!("Field id 1 is IN_PKTS");
                //received_template.in_packets = Some(U32Field::Enabled(order));
                received_template.order_vec.push(FlowField::InPkts);
            },
            3 => {
                println!("Field id 2 is FLOWS");
                //received_template.flows = Some(U32Field::Enabled(order));
                received_template.order_vec.push(FlowField::Flows);
            },
            4 => {
                println!("Field id 3 is PROTOCOL");
                //received_template.protocol = Some(U8Field::Enabled(order));
                received_template.order_vec.push(FlowField::Protocol);
            },
            5 => {
                println!("Field id 4 is SRC_TOS");
                //received_template.src_tos = Some(U8Field::Enabled(order));
                received_template.order_vec.push(FlowField::SrcTOS);
            },
            6 => {
                println!("Field id 5 is TCP_FLAGS");
                //received_template.tcp_flags = Some(U8Field::Enabled(order));
                received_template.order_vec.push(FlowField::TCPFlags);
            },
            7 => {
                println!("Field id 6 is SRC_PORT");
                //received_template.src_port = Some(FlowField::SrcPort(Some(U16Field::Enabled(order))));
                received_template.order_vec.push(FlowField::SrcPort);
            },
            8 => {
                println!("Field id 7 is SRC_ADDR");
                //received_template.src_addr = Some(FlowField::SrcAddr);
                received_template.order_vec.push(FlowField::SrcAddr);
            },
            9 => {
                println!("Field id 8 is SRC_MASK");
                //received_template.src_mask = Some(U8Field::Enabled(order));
                received_template.order_vec.push(FlowField::SrcMask);
            },
            10 => {
                println!("Field id 9 is INPUT_SNMP");
                //received_template.input_snmp = Some(U16Field::Enabled(order));
                received_template.order_vec.push(FlowField::InputSNMP);
            },
            11 => {
                println!("Field id 10 is DST_PORT");
                //received_template.dst_port = Some(U16Field::Enabled(order));
                received_template.order_vec.push(FlowField::DstPort);
            },
            12 => {
                println!("Field id 11 is DST_ADDR");
                //received_template.dst_addr = Some(Ipv4Field::Enabled(order));
                received_template.order_vec.push(FlowField::DstAddr);
            },
            13 => {
                println!("Field id 12 is DST_MASK");
                //received_template.dst_mask = Some(U8Field::Enabled(order));
                received_template.order_vec.push(FlowField::DstMask);
            },
            14 => {
                println!("Field id 13 is OUTPUT_SNMP");
                //received_template.output_snmp = Some(U16Field::Enabled(order));
                received_template.order_vec.push(FlowField::OutputSNMP);
            },
            15 => {
                println!("Field id 14 is NEXT_HOP");
                //received_template.ipv4_next_hop = Some(Ipv4Field::Enabled(order));
                received_template.order_vec.push(FlowField::NextHop);
            },
            _ => {
                println!("Unsure of the field id {field_id}");
            },
        }
    }
    fn get_field_type(&self, flow_field: FlowField) -> FlowField {
        match flow_field {
            FlowField::InOctets => {
                FlowField::InOctets
            },
            FlowField::InPkts => {
                FlowField::InPkts
            },
            FlowField::Flows => {
                FlowField::Flows
            },
            FlowField::Protocol => {
                FlowField::Protocol
            },
            FlowField::SrcTOS => {
                FlowField::SrcTOS
            },
            FlowField::TCPFlags => {
                FlowField::TCPFlags
            },
            FlowField::SrcPort => {
                FlowField::SrcPort
            },
            FlowField::SrcAddr => {
                FlowField::SrcAddr
            },
            FlowField::SrcMask => {
                FlowField::SrcMask
            },
            FlowField::InputSNMP => {
                FlowField::InputSNMP
            },
            FlowField::DstPort => {
                FlowField::DstPort
            },
            FlowField::DstAddr => {
                FlowField::DstAddr
            },
            FlowField::DstMask => {
                FlowField::DstMask
            },
            FlowField::OutputSNMP => {
                FlowField::OutputSNMP
            },
            FlowField::NextHop => {
                FlowField::NextHop
            },
            _ => {
                println!("Unsure of the field in get_field_type");
                FlowField::None
            },
        }
    }

    fn get_field_size(&self, flow_field: FlowField) -> usize {
        match flow_field {
            FlowField::InOctets => {
                4
            },
            FlowField::InPkts => {
                4
            },
            FlowField::Flows => {
                4
            },
            FlowField::Protocol => {
                1
            },
            FlowField::SrcTOS => {
                1
            },
            FlowField::TCPFlags => {
                1
            },
            FlowField::SrcPort => {
                2
            },
            FlowField::SrcAddr => {
                4
            },
            FlowField::SrcMask => {
                1
            },
            FlowField::InputSNMP => {
                4
            },
            FlowField::DstPort => {
                2
            },
            FlowField::DstAddr => {
                4
            },
            FlowField::DstMask => {
                1
            },
            FlowField::OutputSNMP => {
                4
            },
            FlowField::NextHop => {
                4
            },
            _ => {
                println!("Unsure of the field size in get_field_size");
                0
            },
        }
    }

    fn set_field_value(&self, flow_field: FlowField, sender_index: usize, new_packet: &mut NetflowTemplate, field_slice: &[u8]) {
        match flow_field {
            FlowField::InOctets => {
                let field_array: [u8; 4] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u32::from_be_bytes(field_array);
                println!("The field is InOctets and the converted payload is {}",field_data );
                new_packet.in_octets = Some(U32Field::Value(field_data));
            },
            FlowField::InPkts => {
                let field_array: [u8; 4] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u32::from_be_bytes(field_array);
                println!("The field is InPkts and the converted payload is {}",field_data );
                new_packet.in_packets = Some(U32Field::Value(field_data));
            },
            // FlowField::Flows => {

            // },
            FlowField::Protocol => {
                let field_array: [u8; 1] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u8::from_be_bytes(field_array);
                println!("The field is Protocol and the converted payload is {}",field_data);
                new_packet.protocol = Some(U8Field::Value(field_data));
            },
            FlowField::SrcTOS => {
                let field_array: [u8; 1] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u8::from_be_bytes(field_array);
                println!("The field is SrcTOS and the converted payload is {}",field_data);
                new_packet.src_tos = Some(U8Field::Value(field_data));
            },
            FlowField::TCPFlags => {
                let field_array: [u8; 1] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u8::from_be_bytes(field_array);
                println!("The field is TCPFlags and the converted payload is {}",field_data);
                new_packet.tcp_flags = Some(U8Field::Value(field_data));
            },
            FlowField::SrcPort => {
                let field_array: [u8; 2] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u16::from_be_bytes(field_array);
                println!("The field is SrcPort and the converted payload is {}",field_data );
                new_packet.src_port = Some(U16Field::Value(field_data));
            },
            FlowField::SrcAddr => {
                let field_array: [u8; 4] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u32::from_be_bytes(field_array);
                let field_data_ipv4: Ipv4Addr = Ipv4Addr::from_bits(field_data);
                println!("The field is SrcAddr and the converted payload is {}", field_data_ipv4);
                new_packet.src_addr = Some(Ipv4Field::Value(field_data_ipv4));
            },
            FlowField::SrcMask => {
                let field_array: [u8; 1] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u8::from_be_bytes(field_array);
                println!("The field is SrcMask and the converted payload is {}",field_data);
                new_packet.src_mask = Some(U8Field::Value(field_data));
            },
            FlowField::InputSNMP => {
                let field_array: [u8; 4] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u32::from_be_bytes(field_array);
                println!("The field is InputSNMP and the converted payload is {}",field_data );
                new_packet.input_snmp = Some(U32Field::Value(field_data));
            },
            FlowField::DstPort => {
                let field_array: [u8; 2] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u16::from_be_bytes(field_array);
                println!("The field is DstPort and the converted payload is {}",field_data );
                new_packet.dst_port = Some(U16Field::Value(field_data));
            },
            FlowField::DstAddr => {
                let field_array: [u8; 4] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data: u32 = u32::from_be_bytes(field_array);
                let field_data_ipv4: Ipv4Addr = Ipv4Addr::from_bits(field_data);
                println!("The field is DstAddr and the converted payload is {}", field_data_ipv4);
                new_packet.dst_addr = Some(Ipv4Field::Value(field_data_ipv4));
            },
            FlowField::DstMask => {
                let field_array: [u8; 1] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u8::from_be_bytes(field_array);
                println!("The field is DstMask and the converted payload is {}",field_data);
                new_packet.dst_mask = Some(U8Field::Value(field_data));
            },
            FlowField::OutputSNMP => {
                let field_array: [u8; 4] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data = u32::from_be_bytes(field_array);
                println!("The field is OutputSNMP and the converted payload is {}",field_data );
                new_packet.output_snmp = Some(U32Field::Value(field_data));
            },
            FlowField::NextHop => {
                let field_array: [u8; 4] = field_slice.try_into().expect("Unable to convert field_slice to array");
                let field_data_u32: u32 = u32::from_be_bytes(field_array);
                let field_data_ipv4: Ipv4Addr = Ipv4Addr::from_bits(field_data_u32);
                println!("The field is SrcAddr and the converted payload is {}", field_data_ipv4);
                new_packet.next_hop = Some(Ipv4Field::Value(field_data_ipv4));
            },
            _ => {
                println!("Unsure of the field in get_field_type");
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

    pub fn parse_flow_length(&self, message: &[u8]) -> u16 {
        //flowset length
        let data_len_slice: &[u8]  = &message[22..24];
        let data_len_array: [u8; 2] = data_len_slice.try_into().expect("Unable to convert data_len_slice to array");
        let data_len: u16 = u16::from_be_bytes(data_len_array);
        println!("The payload data_len is {data_len}");
        data_len
    }

    pub fn parse_flow_template_id_from_template(&self, message: &[u8]) -> u16 {
        //template id
        let template_id_slice: &[u8]  = &message[24..26];
        let template_id_array: [u8; 2] = template_id_slice.try_into().expect("Unable to convert template_id_slice to array");
        let template_id: u16 = u16::from_be_bytes(template_id_array);
        println!("The payload template_id is {template_id}");
        template_id
    }

    pub fn parse_flow_template_id_from_data(&self, message: &[u8]) -> u16 {
        //template id is at different location when the packet is flow data
        let template_id_slice: &[u8]  = &message[20..22];
        let template_id_array: [u8; 2] = template_id_slice.try_into().expect("Unable to convert template_id_slice to array");
        let template_id: u16 = u16::from_be_bytes(template_id_array);
        println!("The payload template_id is {template_id}");
        template_id
    }

    pub fn parse_flow_field_count(&self, message: &[u8]) -> u16 {
        //field count
        let field_count_slice: &[u8]  = &message[26..28];
        let field_count_array: [u8; 2] = field_count_slice.try_into().expect("Unable to convert field_count_slice to array");
        let field_count: u16 = u16::from_be_bytes(field_count_array);
        println!("The payload field_count is {field_count}");
        field_count
    }


    pub fn parse_flow_template(&mut self, byte_count: usize) -> NetflowTemplate {
        //if flowset id == 0, it's a template
        //the udp receive func starts us at byte 30 because that's the udp payload
        //byte 20 and 21 in the payload are the flowset ID,
        //thus, if the u16 at byte 20 and 21 is 0 it's a template, else it's data
    
        let message: &[u8]  = &self.receive_buffer[..byte_count];
        println!("Parsing...");

        let mut received_template = NetflowTemplate::default();
        //flowset length
        self.parse_flow_length(message);
     
 
        //template id
        let template_id = self.parse_flow_template_id_from_template(message);
        received_template.id = Some(template_id);
    
    
        //field count
        let field_count = self.parse_flow_field_count(message);
        //save the field count so we can easily iterate later
        received_template.field_count = Some(field_count);

        let mut start_slice: usize = 28;
        let mut end_slice: usize = 30;
        let inc_size: usize = 4;
        for x in 0..field_count  {
            let field_slice: &[u8]  = &message[start_slice..end_slice];
            let field_array: [u8; 2] = field_slice.try_into().expect("Unable to convert field_slice to array");
            let field_data: u16 = u16::from_be_bytes(field_array);
            println!("The payload field_slice for field {x} is {field_data}");
            let order = x;
            self.decode_field_order(field_data, &mut received_template);
            start_slice += inc_size;
            end_slice += inc_size;
        }

        self.initial_template_received = true;

        received_template

    }




    pub fn parse_data_to_packet(&mut self, byte_count: usize, sender_index: usize) {
        let message: &[u8]  = &self.receive_buffer[..byte_count];
        println!("Parsing...");

        //flowset length
        self.parse_flow_length(message);
     
        //let sender: &mut NetflowSender = &mut self.senders[sender_index];

        //template id
        let template_id = self.parse_flow_template_id_from_data(message);
        if template_id != self.senders[sender_index].active_template.id.expect("sender.active_template.id is None") {
            println!("The flow data template_id does not match the sender.active_template.id");
            return;
        }

        //field count
        let field_count = self.senders[sender_index].active_template.field_count.unwrap();

        //data can be parsed
        let mut start_slice: usize = 24;
        //get the intial size of the first field
        let mut field_type = self.get_field_type(self.senders[sender_index].active_template.order_vec[0]);
        let mut inc_size: usize = self.get_field_size(self.senders[sender_index].active_template.order_vec[0]);
        let mut end_slice: usize = start_slice + inc_size;
        let mut initial_field_parsed = false;
        let vec_len: u16 = self.senders[sender_index].active_template.order_vec.len().try_into().unwrap();
        if field_count != vec_len {
            println!("The order_vec length is not equal to the field_count, cannot parse or else we'll crash");
            return;
        }

        let mut new_packet: NetflowTemplate = NetflowTemplate::default();

        let field_count_size: usize = field_count.into();
        for x in 0..field_count_size  {
            //this runs after the first iteration because we already incremented before the for loop
            if initial_field_parsed {
                //update size per field
                field_type = self.get_field_type(self.senders[sender_index].active_template.order_vec[x]);
                inc_size = self.get_field_size(self.senders[sender_index].active_template.order_vec[x]);
                start_slice = end_slice;
                end_slice  += inc_size;
            }
 
            let field_slice: &[u8]  = &message[start_slice..end_slice];
            self.set_field_value(field_type, sender_index, &mut new_packet, field_slice);

            if !initial_field_parsed {
                initial_field_parsed = true;
            }
        }
        self.senders[sender_index].flow_packets.push(new_packet);

    }




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

    pub fn match_sender(&mut self, byte_count: usize, source_address: SocketAddr) -> std::result::Result<usize, std::io::Error> {
        let mut found_sender = false;
        let sender_ip = convert_socket_to_ipv4(source_address);
        let vec_len = self.senders.len();
        for x in 0..vec_len {
            if self.senders[x] .ip_addr == sender_ip {
                println!("Found the source in the senders vector");
                println!("Sender is {sender_ip}");
                // let sender = self.senders[x].clone();
                // return Ok(&sender);
                return Ok(x);
            }
        }
        Err(Error::new(ErrorKind::AddrNotAvailable, "Sender not found"))
    }
        
        

}

