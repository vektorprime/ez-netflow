# EZ-Netflow
This is a netflow server (receiver) built in Rust. It automatically displays stats about the flows it receives and stores the information.  Just run ez_netflow.exe to start listening and displaying data.

## Goals
- Be lightweight
- Be easy to use (simple)
- Portable (no installation)
  
EXAMPLE OUTPUT:
![image](https://github.com/user-attachments/assets/710f831e-ebd5-40a0-9fc7-cecce6049ff7)


## How to use
1. Download the release
2. Run the .exe
   - A config file and file-based DB are automatically created
   - It will listen on UDP 2055
3. Grab the config template from the "Cisco Router Example Config" section
4. Customize it for your device (change IP and interfaces)
5. Configure it on your device
   - on a Cisco router that means applying the "flow monitor" to one or multiple interfaces
6. Wait for netflow data to populate the table
   - The screen will auto-update every 5 seconds
   - Usually 60 seconds is enough time to get output


## Config
The config can be modified through config.ini. The file is automatically created with default settings if it doesn't exist.

Currently, these options are available.
```
database_file_or_mem: {file | mem},
flows_to_display: {int between 1-300),
sort_flows_by_bytes_or_packets: {bytes | packets},
show_only_unicast: {true | false},
```
Deleting the config.ini will restore the defaults as 
```
database_file_or_mem: file,
flows_to_display: 30,
sort_flows_by_bytes_or_packets: bytes,
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
 collect datalink mac destination address input
!last line is optional and used to look for broadcast traffic that comes in on the interface


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


## More Screenshots
Here's the output of setting "show_only_unicast: true"
![image](https://github.com/user-attachments/assets/3c87d5b7-de2b-476f-8c4f-ff5ba02c8c1b)

