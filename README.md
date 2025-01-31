# EZNetflow
This is a netflow server (receiver) built in Rust. It automatically displays stats about the flows it receives and stores the information.  Just run ez_netflow.exe to start listening and displaying data.

## Goals
- Be lightweight
- Be easy to use (simple)
- Startup with no tinkering
  
EXAMPLE OUTPUT:
![image](https://github.com/user-attachments/assets/e9ff00b1-2bc7-485d-8fe8-336ec1d39ed8)



## Config
The config can be modified through config.ini.

Currently, these options are available.
```
database_file_or_mem: {file | mem}
flows_to_display: {int between 1-300)
sort_flows_by_bytes_or_packets: {bytes | packets}
```
Deleting the config.ini will restore the defaults as 
```
database_file_or_mem: file,
flows_to_display: 30,
sort_flows_by_bytes_or_packets: bytes
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
!Basic Ipv4 flow record


flow monitor NetMonitor
 exporter NetExporter
 cache timeout inactive 60
 cache timeout active 60
 record NetIPv4

interface GigabitEthernet3
 ip flow monitor NetMonitor input
 ip flow monitor NetMonitor output

```

## Limitations
These limitations are being worked on.
- Only listens on UDP 2055.
- Only supports flexible netflow.
- Only supports IPv4.
- Requires waiting for an initial template (template data timeout in flow exporter config) before processing flows

### Crates
utlizes the following crates:
- rusqlite - for running the db in memory or saving to file
- tabled - for pretty table views
