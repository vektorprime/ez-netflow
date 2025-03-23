# EZ-Netflow
EZ-Netflow is an all-in-one netflow server and library that's really easy to use. This is the lib crate, which contains the core server and database code. Use this crate directly if you want to incorporate EZ-Netflow into your project.

If you want an executable binary to run EZ-Netflow, check out ez_netflow_cli.



## How to use
1. You can incorporate into your code by adding the following code to your main.rs or similar file.



```
//use settings from config.ini, file will be auto created if it doesn't exist
let server_settings = ServerSettings::new("config.ini");

//secure the db access for multi-thread use
let mut db_conn_cli: std::sync::Arc<Mutex<Connection>>  = Arc::new(Mutex::new(setup_db(&server_settings.conn_type)));

//clone the db connection so we can pass it to a thread
let db_conn_srv: std::sync::Arc<Mutex<Connection>>  = Arc::clone(&db_conn_cli);

//set the IP and port we want to bind to the netflow server to
let srv_addr_and_port = String::from(&server_settings.address) + ":" + &server_settings.port.to_string();

//run the netflow server in another thread
let server_thread = thread::spawn(move || {
     let mut netflow_server = NetflowServer::new(srv_addr_and_port , db_conn_srv);
     netflow_server.run();
});
```

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
- Only supports flexible netflow.
- Only supports IPv4.
- Requires waiting for an initial template (template data timeout in flow exporter config) before processing flows.