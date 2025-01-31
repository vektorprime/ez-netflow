This is a netflow server (receiver) built in Rust. It automatically displays stats about the flows it receives and stores the information.

Config

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
Database

The storage of flow data can be in db (sqlite) or in memory (volatile). When saved in db, the sqlite db file is named eznf_db.sqlite.


EXAMPLE OUTPUT:
![image](https://github.com/user-attachments/assets/e9ff00b1-2bc7-485d-8fe8-336ec1d39ed8)



utlizes the following crates:

rusqlite - for running the db in memory or saving to file

tabled - for pretty table views
