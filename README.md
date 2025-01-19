This is a netflow server (receiver) built in Rust.

This is a project used to learn Rust.


EXAMPLE OUTPUT:
```
Sender is 10.0.0.35
Parsing...
The payload data_len is 36
The payload template_id is 257
The field is SrcAddr and the converted payload is 10.0.0.31
The field is DstAddr and the converted payload is 10.0.0.45
The field is Protocol and the converted payload is 17
The field is SrcPort and the converted payload is 49764
The field is DstPort and the converted payload is 137
The field is InputSNMP and the converted payload is 0
The field is OutputSNMP and the converted payload is 1
The field is InOctets and the converted payload is 1168
The field is InPkts and the converted payload is 13
parsing packet to flow
flow_stats is empty, creating new flow
Start flow data...
Src IP is 10.0.0.31 and Dst IP is 10.0.0.45
Protocol is 17
Bytes/octets are 1168
Packets are 13
End flow data
```
