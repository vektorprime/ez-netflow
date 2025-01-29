use std::net::Ipv4Addr;

#[derive(Copy, Clone)]
pub enum NetflowVersion {
    V5(u16),
    V9(u16)
}

pub enum PacketType {
    Template,
    Data
}

//enabled is the order
//value is actual payload
#[derive(Copy, Clone)]
pub enum U8Field {
    Disabled,
    Enabled,
    Value(u8),
}

#[derive(Copy, Clone)]
pub enum U64Field {
    Disabled,
    Enabled,
    Value(u64),
}


#[derive(Copy, Clone)]
pub enum U16Field {
    Disabled,
    Enabled,
    Value(u16),
}

#[derive(Copy, Clone)]
pub enum U32Field {
    Disabled,
    Enabled,
    Value(u32),
}

#[derive(Copy, Clone)]
pub enum Ipv4Field {
    Disabled,
    Enabled,
    Value(Ipv4Addr),
}

#[derive(Copy, Clone, Default)]
pub enum FlowField {
   #[default]
   None,
   TemplateID(Option<u16>),
   FieldCount(Option<u16>),
   InOctets,
   InPkts,
   Flows,
   Protocol,
   SrcTOS,
   TCPFlags,
   SrcPort,
   SrcAddr,
   SrcMask,
   InputSNMP,
   DstPort,
   DstAddr,
   DstMask,
   OutputSNMP,
   NextHop,
   MulDstPkts,
   MulDstBytes,
   LastSwitched,
   FirstSwitched,
   OutBytes,
   OutPkts,
   MinPktLength,
   MaxPktLength,
   IcmpType,
   MulIgmpType,
   MinTTL,
   MaxTTL,
   Ident,
   DstTOS,
   InSrcMac,
   OutDstMac,
   SrcVLAN,
   DstVLAN,
   IpVersion,
   Direction,
   InDstMac,
   OutSrcMac,
   //missing 5 last
   

}