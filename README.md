# EZNetflow
This is a netflow server (receiver) built in Rust. It automatically displays stats about the flows it receives and stores the information.  Just run ez_netflow.exe to start listening and displaying data.

## Goals
- Be lightweight
- Be easy to use (simple)
- Startup with no tinkering
  
EXAMPLE OUTPUT:
![ez_netflow_program](https://github.com/user-attachments/assets/36b340ba-8ace-4d33-a92e-3b889bd7bf34)




## Config
The config can be modified through config.ini. The file is automatically created with default settings if it doesn't exist.

Currently, these options are available.
```
database_file_or_mem: {file | mem}
flows_to_display: {int between 1-300)
sort_flows_by_bytes_or_packets: {bytes | packets}
show_only_unicast: {true | false},
```
Deleting the config.ini will restore the defaults as 
```
database_file_or_mem: file,
flows_to_display: 30,
sort_flows_by_bytes_or_packets: bytes
show_only_unicast: false,
```

## Database

The storage of flow data can be in db (sqlite) or in memory (volatile). When saved in db, the sqlite db file is named eznf_db.sqlite. To wipe the db, delete the eznf_db.sqlite file and restart ez_netflow.exe.

## Cisco Router Example Config
```

flow exporter NetExporter
 destination <IP OF EZNETFLOW SERVER>
 source <optional but good idea to specify source int>
 transport udp 2055
 template data timeout 30
 !30 is ideal above, but any value will do

flow record NetIPv4
 match ipv4 protocol
 match ipv4 source address
 match ipv4 destination address
 match transport source-port
 match transport destination-port
 match interface input
 collect interface output
 collect counter bytes
 collect counter packets
 !next line is optional and used to look for broadcast traffic that comes in on the interface
 collect datalink mac destination address input
!Basic Ipv4 flow record end


flow monitor NetMonitor
 exporter NetExporter
 cache timeout inactive 60
 cache timeout active 60
 record NetIPv4

!apply it on an interface, e.g. Gi3
interface GigabitEthernet3
 ip flow monitor NetMonitor input
 ip flow monitor NetMonitor output

```

## Limitations
These limitations are being worked on.
- ~Only listens on UDP 2055.~
- Only supports flexible netflow.
- Only supports IPv4.
- Requires waiting for an initial template (template data timeout in flow exporter config) before processing flows.
- ~Flows from different sources are counted as unique.~

### Crates
utlizes the following crates:
- rusqlite - for running the db in memory or saving to file
- tabled - for pretty table views
