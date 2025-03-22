
use std::io::ErrorKind;
use std::sync::{Arc, Mutex, MutexGuard};
use std::net::Ipv4Addr;
use log::{error, info, debug};

use rusqlite::ffi::Error;
use rusqlite::OptionalExtension;
use rusqlite::{ErrorCode, Connection, params};
use tabled::{builder::Builder, settings::Style};

use crate::{senders::*, templates::NetFlow};
use crate::settings::*;
use crate::utils::*;
use crate::fields::*;



pub fn setup_db(conn_type: &ConnType) -> Connection {

    let db_conn: Connection = match conn_type {
        ConnType::InMemory => {
            Connection::open_in_memory().expect("Unable to open SQLITE db connection in memory")
        },
        ConnType::InFile => {
            Connection::open("./eznf_db.sqlite").expect("Unable to open SQLITE db connection in memory")
        }
    };

    db_conn.execute("PRAGMA foreign_keys = ON", []).unwrap();

    //create tables
    db_conn.execute("CREATE TABLE IF NOT EXISTS senders (
        ip TEXT PRIMARY KEY
        )",
        [],
        ).expect("Unable to create senders table in DB");

    db_conn.execute("CREATE TABLE IF NOT EXISTS flows (
        id INTEGER PRIMARY KEY,
        sender_ip TEXT NOT NULL,
        src_addr TEXT,
        dst_addr TEXT,
        protocol INTEGER,
        src_port INTEGER,
        dst_port INTEGER,
        tcp_flags INTEGER,
        input_snmp INTEGER,
        output_snmp INTEGER,
        in_octets INTEGER,
        in_pkts INTEGER,
        src_tos INTEGER,
        src_mask INTEGER,
        dst_mask INTEGER,
        next_hop TEXT,
        icmp TEXT,
        traffic_type TEXT,
         FOREIGN KEY (sender_ip) REFERENCES senders(ip)
        )",
        [],
        ).expect("Unable to create flows table in DB");

    db_conn
}

pub fn update_senders_in_db(db_conn: &mut Arc<Mutex<Connection>>, sender_ip: &str) {
    let db_conn_unlocked: MutexGuard<Connection> = db_conn.lock().unwrap();
    db_conn_unlocked.execute( 
        "INSERT OR IGNORE INTO senders (ip) VALUES (?)",
        [sender_ip.to_string()],
        ).expect("Unable to execute SQL in update_senders_in_db");
}


pub fn create_flow_in_db(db_conn: &mut Connection, flow: &NetFlow, sender_ip: &String) {

    //let traffic_type = handle_traffic_cast(&flow.src_and_dst_ip.0.to_string(), &flow.src_and_dst_ip.1.to_string());
    //let traffic_type = handle_traffic_type(&flow);
    //moved traffic type processing to the same func that processes the flow
    
    let traffic_type = match flow.traffic_type {
        TrafficType::Broadcast => "Broadcast",
        TrafficType::Multicast => "Multicast",
        TrafficType::Unicast => "Unicast",
    };

    db_conn.execute( 
        "INSERT INTO flows 
            (sender_ip, src_addr, dst_addr, src_port, dst_port, protocol, in_octets, in_pkts, traffic_type) 
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        (sender_ip.to_string(), 
            flow.src_and_dst_ip.0.to_string(), 
            flow.src_and_dst_ip.1.to_string(),
            flow.src_and_dst_port.0, 
            flow.src_and_dst_port.1, 
            flow.protocol, 
            flow.in_octets, 
            flow.in_packets,
            traffic_type),
        ).expect("Unable to execute SQL in create_flow_in_db");
}

//I can't remove the "WHERE sender_ip = ?1" because it will update all of the flows
//I first need to make sure a flow is not created twice, no matter the sender
pub fn update_flow_in_db(db_conn: &mut Connection, flow: &NetFlow, sender_ip: &String) {
    db_conn.execute( 
        "UPDATE flows SET 
            in_octets = ?1, 
            in_pkts = ?2
            WHERE src_addr = ?3
            AND dst_addr = ?4
            AND src_port = ?5
            AND dst_port = ?6
            AND protocol = ?7",
        params![
            flow.in_octets, 
            flow.in_packets,
            flow.src_and_dst_ip.0.to_string(), 
            flow.src_and_dst_ip.1.to_string(),
            flow.src_and_dst_port.0, 
            flow.src_and_dst_port.1, 
            flow.protocol, 
            ]
        ).expect("Unable to execute SQL in update_flow_in_db");
}

pub fn check_if_flow_exists_in_db(db_conn: &mut Connection, flow: &NetFlow) -> bool {

    let row_result = db_conn.query_row(
            "SELECT * FROM flows WHERE 
             ((src_addr = ?1 AND dst_addr = ?2) OR (src_addr = ?2 AND dst_addr = ?1)) AND
             ((src_port = ?3 AND dst_port = ?4) OR (src_port = ?4 AND dst_port = ?3)) AND
            protocol = ?5",
            params![
            &flow.src_and_dst_ip.0.to_string(), 
            &flow.src_and_dst_ip.1.to_string(), 
            &flow.src_and_dst_port.0, 
            &flow.src_and_dst_port.1,
            &flow.protocol],
            |row| row.get::<_, i32>(0),
    );

    match row_result {
        Ok(s) => {
            //println!("existing flow found, id is {s}");
            true 
        },
         Err(rusqlite::Error::QueryReturnedNoRows) => {
            //println!("existing flow NOT found because query returned no rows");
            false
         },
         Err(e) => {
            println!("Error in checking for existing fow in SQL, setting flow as existing,  error is {e}");
            error!("Error in checking for existing fow in SQL, setting flow as existing,  error is {e}");
            false
         }
    }
    
}


pub fn get_all_flows_from_sender(db_conn_cli: &mut Arc<Mutex<Connection>>, server_settings: &ServerSettings) -> tabled::Table {

    let mut builder = Builder::new();
    builder.push_record([
        "sender_ip", 
        "src_addr", 
        "dst_addr", 
        "protocol", 
        "src_port", 
        "dst_port", 
        "in_pkts", 
        "in_bytes",
        "icmp_type",
        "traffic_type",
        ]);
    
    let mut conn: MutexGuard<Connection> = db_conn_cli.lock().unwrap();

    let flow_limit = match server_settings.flow_limit {
        FlowsToShow::Limit { flows } => flows,
        FlowsToShow::NoLimit => 1000,
    };

    let select_statement = "SELECT * FROM flows ".to_string();
    let filter_statement = match server_settings.unicast_only {
        true => {
            "WHERE traffic_type = \'Unicast\'"
        },
        false => {""},
    };
    
    let order_statement = match server_settings.sort_by {
        SortBy::Bytes => { 
            " ORDER BY in_octets DESC LIMIT ?"
        },
        SortBy::Pkts => {
            "SELECT * FROM flows ORDER BY in_pkts DESC LIMIT ?"
        },
        SortBy::None => {
            "SELECT * FROM flows LIMIT ?"
        },
    } ;

    let joined_statement = select_statement + filter_statement + order_statement;

    let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
        .expect("Unable to prepare query");


    let mut rows = stmt.query(params![flow_limit])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let sender_ip: String = row.get(1).expect("Unable to open column 1");
          //println!("sender_ip is {sender_ip}");
          let src_addr: String = row.get(2).expect("Unable to open column 2");
          //println!("src_addr is {src_addr}");
          let dst_addr: String = row.get(3).expect("Unable to open column 3");
          //println!("dst_addr is {dst_addr}");
          let protocol: i32 = row.get(4).expect("Unable to open column 4");
          //println!("protocol is {protocol}");
          let src_port: i32 = row.get(5).expect("Unable to open column 5");
          //println!("src_port is {src_port}");
          let dst_port: i32 = row.get(6).expect("Unable to open column 6");
          //println!("dst_port is {dst_port}");
          let in_pkts: i32 = row.get(10).expect("Unable to open column 10");
          //println!("in_pkts is {in_pkts}");
          let in_bytes: i32 = row.get(11).expect("Unable to open column 11");
          //println!("in_bytes is {in_bytes}");
          let traffic_cast: String = row.get(17).expect("Unable to open column 17");

          let (icmp_type, src_port2,dst_port2) = handle_icmp_code(protocol, src_port, dst_port);
       
          //let ip_cast = handle_traffic_cast(&src_addr, &dst_addr);

            builder.push_record([
                sender_ip, 
                src_addr, 
                dst_addr, 
                protocol.to_string(), 
                src_port2.to_string(), 
                dst_port2.to_string(), 
                in_pkts.to_string(), 
                in_bytes.to_string(),
                icmp_type,
                traffic_cast,
                ]);

        }


        let mut table = builder.build();
        table.with(Style::ascii_rounded());
        table

}


pub fn get_all_hosts_as_json(db_conn_cli: &mut Arc<Mutex<Connection>>, server_settings: &ServerSettings) -> String {

    let mut all_hosts: Vec<String> = Vec::new();
   
    let mut conn: MutexGuard<Connection> = db_conn_cli.lock().unwrap();

    let flow_limit = 10;

    let select_statement = "SELECT src_ip FROM flows ".to_string();


    let mut stmt: rusqlite::Statement = conn.prepare(&select_statement)
        .expect("Unable to prepare query");


    let mut rows = stmt.query(params![flow_limit])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let src_addr: String = row.get(2).expect("Unable to open column 2");
         // build json here and add it to vec
            all_hosts.push(src_addr);
    
        }

    serde_json::to_string(&all_hosts).unwrap()

}


pub fn get_all_hosts_ip_as_json(state: &mut EZNFState) -> String {

    let mut all_flows: Vec<String> = Vec::new();
   
    let mut conn: MutexGuard<Connection> = state.db_conn_cli.lock().unwrap();

    let joined_statement = "SELECT src_addr FROM flows ORDER BY src_addr DESC";

    let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
        .expect("Unable to prepare query");

    let mut rows = stmt.query(params![])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let src_addr: String = row.get(0).expect("Unable to open column 2");
          all_flows.push(src_addr);
        }
    
    all_flows.dedup();

    //dirty code to run it twice for dst, required because dedupe works only with consec. values
    let joined_statement = "SELECT dst_addr FROM flows ORDER BY dst_addr DESC";

    let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
        .expect("Unable to prepare query");

    let mut rows = stmt.query(params![])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let dst_addr: String = row.get(0).expect("Unable to open column 2");
          all_flows.push(dst_addr);
        }

    all_flows.dedup();

    serde_json::to_string(&all_flows).unwrap()

}


pub fn get_all_flows_as_json(state: &mut EZNFState) -> String {

    let mut all_flows: Vec<NetFlowJson> = Vec::new();
   
    let mut conn: MutexGuard<Connection> = state.db_conn_cli.lock().unwrap();

    let select_statement = "SELECT * FROM flows ".to_string();
    
    let order_statement = "ORDER BY src_addr LIMIT 10000";


    let joined_statement = select_statement + order_statement;

    let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
        .expect("Unable to prepare query");


    let mut rows = stmt.query(params![])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let sender_ip: String = row.get(1).expect("Unable to open column 1");
          //println!("sender_ip is {sender_ip}");
          let src_addr: String = row.get(2).expect("Unable to open column 2");
          //println!("src_addr is {src_addr}");
          let dst_addr: String = row.get(3).expect("Unable to open column 3");
          //println!("dst_addr is {dst_addr}");
          let proto: i32 = row.get(4).expect("Unable to open column 4");
          //println!("protocol is {protocol}");
          let src_port: i32 = row.get(5).expect("Unable to open column 5");
          //println!("src_port is {src_port}");
          let dst_port: i32 = row.get(6).expect("Unable to open column 6");
          //println!("dst_port is {dst_port}");
          let in_pkts: i32 = row.get(10).expect("Unable to open column 10");
          //println!("in_pkts is {in_pkts}");
          let in_bytes: i32 = row.get(11).expect("Unable to open column 11");
          //println!("in_bytes is {in_bytes}");
          let traffic_cast: String = row.get(17).expect("Unable to open column 17");

          let (icmp_type, src_port2,dst_port2) = handle_icmp_code(proto, src_port, dst_port);
       
          //let ip_cast = handle_traffic_cast(&src_addr, &dst_addr);
          let traffic_type_as_enum: TrafficType = match traffic_cast.as_str() {
            "Unicast" => TrafficType::Unicast,
            "Multicast" => TrafficType::Multicast,
            "Broadcast" => TrafficType::Broadcast,
            _ => TrafficType::Unicast,
          };

          let current_flow =  NetFlowJson {
            src_ip: convert_string_to_ipv4(&src_addr).unwrap(),
            dst_ip: convert_string_to_ipv4(&dst_addr).unwrap(),
            src_port: src_port.try_into().unwrap(),
            dst_port: dst_port.try_into().unwrap(),
            protocol: proto.try_into().unwrap(),
            in_octets: in_bytes.try_into().unwrap(),
            in_packets: in_pkts.try_into().unwrap(),
            traffic_type: traffic_type_as_enum,
            icmp: icmp_type,
        };

        // build json here and add it to vec
        all_flows.push(current_flow);
    }

    // let mut all_flows_filtered: Vec<NetFlowJson> = Vec::new();

    // //create a new vec, store only unique flows in there, if IP found, add bytes to it
    // for x in 0..all_flows.len()  {
    //     if all_flows_filtered.is_empty() {
    //         //println!("all_flows_filtered is empty, adding IP {} in flows, cloning the flow", all_flows[x].flow_src_ip);
    //         all_flows_filtered.push(all_flows[x].clone());
    //     }

    //     let mut found_ip = false;
    //     for i in 0..all_flows_filtered.len() {
    //         if all_flows[x].src_ip == all_flows_filtered[i].src_ip {
    //             //println!("found existing ip {} in flows, adding bytes to it", all_flows[x].flow_src_ip);
    //             all_flows_filtered[i].in_octets += all_flows[x].in_octets;
    //             found_ip = true;
    //         }
    //     }

    //     if !found_ip {
    //         //println!("did not find IP {} in flows, cloning the flow", all_flows[x].flow_src_ip);
    //         all_flows_filtered.push(all_flows[x].clone());
    //     } 
        
    // }
        
    

    serde_json::to_string(&all_flows).unwrap()

}

pub fn get_top_10_flows_by_bytes_as_json(state: &mut EZNFState) -> String {

    let mut all_flows: Vec<NetflowBytesJson> = Vec::new();
   
    let mut conn: MutexGuard<Connection> = state.db_conn_cli.lock().unwrap();

    let select_statement = "SELECT * FROM flows ORDER BY in_octets DESC LIMIT 10".to_string();

    let joined_statement = select_statement;

    let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
        .expect("Unable to prepare query");


    let mut rows = stmt.query(params![])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let sender_ip: String = row.get(1).expect("Unable to open column 1");
          //println!("sender_ip is {sender_ip}");
          let src_addr: String = row.get(2).expect("Unable to open column 2");
          //println!("src_addr is {src_addr}");
          let dst_addr: String = row.get(3).expect("Unable to open column 3");
          //println!("dst_addr is {dst_addr}");
          let proto: i32 = row.get(4).expect("Unable to open column 4");
          //println!("protocol is {protocol}");
          let src_port: i32 = row.get(5).expect("Unable to open column 5");
          //println!("src_port is {src_port}");
          let dst_port: i32 = row.get(6).expect("Unable to open column 6");
          //println!("dst_port is {dst_port}");
          let in_pkts: i32 = row.get(10).expect("Unable to open column 10");
          //println!("in_pkts is {in_pkts}");
          let in_bytes: i32 = row.get(11).expect("Unable to open column 11");
          //println!("in_bytes is {in_bytes}");
          let traffic_cast: String = row.get(17).expect("Unable to open column 17");

          let (icmp_type, src_port2,dst_port2) = handle_icmp_code(proto, src_port, dst_port);
       
          //let ip_cast = handle_traffic_cast(&src_addr, &dst_addr);
          let traffic_type_as_enum: TrafficType = match traffic_cast.as_str() {
            "Unicast" => TrafficType::Unicast,
            "Multicast" => TrafficType::Multicast,
            "Broadcast" => TrafficType::Broadcast,
            _ => TrafficType::Unicast,
          };

            let current_flow = NetflowBytesJson {
                flow_src_ip: src_addr,
                flow_bytes: in_bytes,
            };
        //{"src_ip": "192.168.1.1", "bytes": 1000}

        // build json here and add it to vec
        all_flows.push(current_flow);

    }

    let mut all_flows_filtered: Vec<NetflowBytesJson> = Vec::new();

    //create a new vec, store only unique flows in there, if IP found, add bytes to it
    for x in 0..all_flows.len()  {
        if all_flows_filtered.is_empty() {
            //println!("all_flows_filtered is empty, adding IP {} in flows, cloning the flow", all_flows[x].flow_src_ip);
            all_flows_filtered.push(all_flows[x].clone());
        }

        let mut found_ip = false;
        for i in 0..all_flows_filtered.len() {
            if all_flows[x].flow_src_ip == all_flows_filtered[i].flow_src_ip {
                //println!("found existing ip {} in flows, adding bytes to it", all_flows[x].flow_src_ip);
                all_flows_filtered[i].flow_bytes += all_flows[x].flow_bytes;
                found_ip = true;
            }
        }

        if !found_ip {
            //println!("did not find IP {} in flows, cloning the flow", all_flows[x].flow_src_ip);
            all_flows_filtered.push(all_flows[x].clone());
        } 
        
    }
        
    

    serde_json::to_string(&all_flows_filtered).unwrap()

}


pub fn get_top_10_flows_by_packets_as_json(state: &mut EZNFState) -> String {

    let mut all_flows: Vec<NetflowPacketsJson> = Vec::new();
   
    let mut conn: MutexGuard<Connection> = state.db_conn_cli.lock().unwrap();

    let select_statement = "SELECT * FROM flows ORDER BY in_pkts DESC LIMIT 10".to_string();

    let joined_statement = select_statement;

    let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
        .expect("Unable to prepare query");


    let mut rows = stmt.query(params![])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let sender_ip: String = row.get(1).expect("Unable to open column 1");
          //println!("sender_ip is {sender_ip}");
          let src_addr: String = row.get(2).expect("Unable to open column 2");
          //println!("src_addr is {src_addr}");
          let dst_addr: String = row.get(3).expect("Unable to open column 3");
          //println!("dst_addr is {dst_addr}");
          let proto: i32 = row.get(4).expect("Unable to open column 4");
          //println!("protocol is {protocol}");
          let src_port: i32 = row.get(5).expect("Unable to open column 5");
          //println!("src_port is {src_port}");
          let dst_port: i32 = row.get(6).expect("Unable to open column 6");
          //println!("dst_port is {dst_port}");
          let in_pkts: i32 = row.get(10).expect("Unable to open column 10");
          //println!("in_pkts is {in_pkts}");
          let in_bytes: i32 = row.get(11).expect("Unable to open column 11");
          //println!("in_bytes is {in_bytes}");
          let traffic_cast: String = row.get(17).expect("Unable to open column 17");

          let (icmp_type, src_port2,dst_port2) = handle_icmp_code(proto, src_port, dst_port);
       
          let traffic_type_as_enum: TrafficType = match traffic_cast.as_str() {
            "Unicast" => TrafficType::Unicast,
            "Multicast" => TrafficType::Multicast,
            "Broadcast" => TrafficType::Broadcast,
            _ => TrafficType::Unicast,
          };

          
            let current_flow = NetflowPacketsJson {
                flow_src_ip: src_addr,
                flow_packets: in_pkts,
            };
            //{"src_ip": "192.168.1.1", "bytes": 1000}

            // build json here and add it to vec
            all_flows.push(current_flow);

        }

        let mut all_flows_filtered: Vec<NetflowPacketsJson> = Vec::new();

        //create a new vec, store only unique flows in there, if IP found, add packets to it
        for x in 0..all_flows.len()  {
            if all_flows_filtered.is_empty() {
                //println!("all_flows_filtered is empty, adding IP {} in flows, cloning the flow", all_flows[x].flow_src_ip);
                all_flows_filtered.push(all_flows[x].clone());
            }
            
            let mut found_ip = false;
            for i in 0..all_flows_filtered.len() {
                if all_flows[x].flow_src_ip == all_flows_filtered[i].flow_src_ip {
                    //println!("found existing ip {} in flows, adding packets to it", all_flows[x].flow_src_ip);
                    all_flows_filtered[i].flow_packets += all_flows[x].flow_packets;
                    found_ip = true;
                }
            }
    
            if !found_ip {
                //println!("did not find IP {} in flows, cloning the flow", all_flows[x].flow_src_ip);
                all_flows_filtered.push(all_flows[x].clone());
            } 
            
        }

    serde_json::to_string(&all_flows_filtered).unwrap()

}



pub fn get_top_10_flows_by_ports_as_json(state: &mut EZNFState) -> String {

    let mut all_flows: Vec<NetflowPortsAndProtocolsJson> = Vec::new();
   
    let mut conn: MutexGuard<Connection> = state.db_conn_cli.lock().unwrap();

    let select_statement = "SELECT * FROM flows ORDER BY in_octets".to_string();


    let joined_statement = select_statement;

    let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
        .expect("Unable to prepare query");


    let mut rows = stmt.query(params![])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let sender_ip: String = row.get(1).expect("Unable to open column 1");
          //println!("sender_ip is {sender_ip}");
          let src_addr: String = row.get(2).expect("Unable to open column 2");
          //println!("src_addr is {src_addr}");
          let dst_addr: String = row.get(3).expect("Unable to open column 3");
          //println!("dst_addr is {dst_addr}");
          let proto: i32 = row.get(4).expect("Unable to open column 4");
          //println!("protocol is {protocol}");
          let src_port: i32 = row.get(5).expect("Unable to open column 5");
          //println!("src_port is {src_port}");
          let dst_port: i32 = row.get(6).expect("Unable to open column 6");
          //println!("dst_port is {dst_port}");
          let in_pkts: i32 = row.get(10).expect("Unable to open column 10");
          //println!("in_pkts is {in_pkts}");
          let in_bytes: i32 = row.get(11).expect("Unable to open column 11");
          //println!("in_bytes is {in_bytes}");
          let traffic_cast: String = row.get(17).expect("Unable to open column 17");


            let current_flow = NetflowPortsAndProtocolsJson {
                flow_bytes: in_bytes,
                flow_src_port: src_port,
                flow_dst_port: dst_port,
                flow_protocol: proto,
            };
            //{"src_ip": "192.168.1.1", "bytes": 1000}

            // build json here and add it to vec
            all_flows.push(current_flow);

        }

        let mut all_flows_filtered: Vec<NetflowPortsAndProtocolsJson> = Vec::new();
        //right now I'm using the linux starting port because it's less than windows, need to impliment better logic latter
        let ephemeral_starting_port = 32768;
        //create a new vec, store only unique ports flows in there, if ports found, add bytes to it
        for x in 0..all_flows.len()  {
            if all_flows_filtered.is_empty() {
                all_flows_filtered.push(all_flows[x].clone());
            }
            
            let mut found_port = false;
            for i in 0..all_flows_filtered.len() {
                if all_flows[x].flow_src_port < ephemeral_starting_port {
                    if all_flows[x].flow_src_port == all_flows_filtered[i].flow_src_port {
                        all_flows_filtered[i].flow_bytes += all_flows[x].flow_bytes;
                        found_port = true;
                    }
                }
                else if all_flows[x].flow_dst_port < ephemeral_starting_port {
                    if all_flows[x].flow_dst_port == all_flows_filtered[i].flow_dst_port {
                        all_flows_filtered[i].flow_bytes += all_flows[x].flow_bytes;
                        found_port = true;
                    }
                }
            }
            if !found_port {
                all_flows_filtered.push(all_flows[x].clone());
            } 
        }

    serde_json::to_string(&all_flows_filtered).unwrap()

}


pub fn get_top_10_flows_by_protocols_as_json(state: &mut EZNFState) -> String {

    let mut all_flows: Vec<NetflowPortsAndProtocolsJson> = Vec::new();
   
    let mut conn: MutexGuard<Connection> = state.db_conn_cli.lock().unwrap();

    let select_statement = "SELECT * FROM flows ORDER BY in_octets".to_string();

    let joined_statement = select_statement;

    let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
        .expect("Unable to prepare query");


    let mut rows = stmt.query(params![])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let sender_ip: String = row.get(1).expect("Unable to open column 1");
          //println!("sender_ip is {sender_ip}");
          let src_addr: String = row.get(2).expect("Unable to open column 2");
          //println!("src_addr is {src_addr}");
          let dst_addr: String = row.get(3).expect("Unable to open column 3");
          //println!("dst_addr is {dst_addr}");
          let proto: i32 = row.get(4).expect("Unable to open column 4");
          //println!("protocol is {protocol}");
          let src_port: i32 = row.get(5).expect("Unable to open column 5");
          //println!("src_port is {src_port}");
          let dst_port: i32 = row.get(6).expect("Unable to open column 6");
          //println!("dst_port is {dst_port}");
          let in_pkts: i32 = row.get(10).expect("Unable to open column 10");
          //println!("in_pkts is {in_pkts}");
          let in_bytes: i32 = row.get(11).expect("Unable to open column 11");
          //println!("in_bytes is {in_bytes}");
          let traffic_cast: String = row.get(17).expect("Unable to open column 17");


            let current_flow = NetflowPortsAndProtocolsJson {
                flow_bytes: in_bytes,
                flow_src_port: src_port,
                flow_dst_port: dst_port,
                flow_protocol: proto,
            };
            //{"src_ip": "192.168.1.1", "bytes": 1000}

            // build json here and add it to vec
            all_flows.push(current_flow);

        }

        let mut all_flows_filtered: Vec<NetflowPortsAndProtocolsJson> = Vec::new();

        //create a new vec, store only unique protocols flows in there, if protocols found, add bytes to it
        for x in 0..all_flows.len()  {
            if all_flows_filtered.is_empty() {
                all_flows_filtered.push(all_flows[x].clone());
            }
            
            let mut found_port = false;
            for i in 0..all_flows_filtered.len() {
                if all_flows[x].flow_protocol == all_flows_filtered[i].flow_protocol {
                    all_flows_filtered[i].flow_bytes += all_flows[x].flow_bytes;
                    found_port = true;
                }
            }
    
            if !found_port {
                all_flows_filtered.push(all_flows[x].clone());
            } 
            
        }

    serde_json::to_string(&all_flows_filtered).unwrap()

}

// pub fn get_all_flows_as_json(db_conn_cli: &mut Arc<Mutex<Connection>>, server_settings: &ServerSettings) -> String {

//     let mut all_flows: Vec<NetflowJson> = Vec::new();
   
//     let mut conn: MutexGuard<Connection> = db_conn_cli.lock().unwrap();

//     let flow_limit = match server_settings.flow_limit {
//         FlowsToShow::Limit { flows } => flows,
//         FlowsToShow::NoLimit => 1000,
//     };

//     let select_statement = "SELECT * FROM flows ".to_string();
//     let filter_statement = match server_settings.unicast_only {
//         true => {
//             "WHERE traffic_type = \'Unicast\'"
//         },
//         false => {""},
//     };
    
//     let order_statement = match server_settings.sort_by {
//         SortBy::Bytes => { 
//             " ORDER BY in_octets DESC LIMIT ?"
//         },
//         SortBy::Pkts => {
//             "SELECT * FROM flows ORDER BY in_pkts DESC LIMIT ?"
//         },
//         SortBy::None => {
//             "SELECT * FROM flows LIMIT ?"
//         },
//     } ;

//     let joined_statement = select_statement + filter_statement + order_statement;

//     let mut stmt: rusqlite::Statement = conn.prepare(&joined_statement)
//         .expect("Unable to prepare query");


//     let mut rows = stmt.query(params![flow_limit])
//         .expect("Unable to query rows");

//        while let Some(row) = rows.next().expect("no more rows") {
//           let sender_ip: String = row.get(1).expect("Unable to open column 1");
//           //println!("sender_ip is {sender_ip}");
//           let src_addr: String = row.get(2).expect("Unable to open column 2");
//           //println!("src_addr is {src_addr}");
//           let dst_addr: String = row.get(3).expect("Unable to open column 3");
//           //println!("dst_addr is {dst_addr}");
//           let proto: i32 = row.get(4).expect("Unable to open column 4");
//           //println!("protocol is {protocol}");
//           let src_port: i32 = row.get(5).expect("Unable to open column 5");
//           //println!("src_port is {src_port}");
//           let dst_port: i32 = row.get(6).expect("Unable to open column 6");
//           //println!("dst_port is {dst_port}");
//           let in_pkts: i32 = row.get(10).expect("Unable to open column 10");
//           //println!("in_pkts is {in_pkts}");
//           let in_bytes: i32 = row.get(11).expect("Unable to open column 11");
//           //println!("in_bytes is {in_bytes}");
//           let traffic_cast: String = row.get(17).expect("Unable to open column 17");

//           let (icmp_type, src_port2,dst_port2) = handle_icmp_code(proto, src_port, dst_port);
       
//           //let ip_cast = handle_traffic_cast(&src_addr, &dst_addr);
//           let unicast_str: String = String::from("Unicast");
//           let multicast_str: String = String::from("Multicast");
//           let broadcast_str: String = String::from("Broadcoast");

//           let traffic_type_as_enum: TrafficType = match traffic_cast {
//             unicast_str => TrafficType::Unicast,
//             multicast_str => TrafficType::Multicast,
//             broadcast_str => TrafficType::Broadcast,
//             _ => TrafficType::Unicast,
//           };

//         // let current_flow: NetFlow =  NetFlow {
//         //     src_and_dst_ip: (convert_string_to_ipv4(&src_addr).unwrap(), convert_string_to_ipv4(&dst_addr).unwrap()),
//         //     src_and_dst_port: (src_port.try_into().unwrap(), dst_port.try_into().unwrap()),
//         //     protocol: proto.try_into().unwrap(),
//         //     in_octets: in_bytes.try_into().unwrap(),
//         //     in_packets: in_pkts.try_into().unwrap(),
//         //     in_db: true,
//         //     traffic_type: traffic_type_as_enum,
//         // };

//         let current_flow = NetflowJson {
//             flow_src_ip: src_addr,
//             flow_bytes: in_bytes,
//         };
//         //{"src_ip": "192.168.1.1", "bytes": 1000}

//         // build json here and add it to vec
//         all_flows.push(current_flow);

//     }

//     serde_json::to_string(&all_flows).unwrap()

// }



// pub fn get_all_senders_in_db() {
//             // {
//         //     let mut conn: MutexGuard<Connection> = db_conn_cli.lock().unwrap();
//         //     let mut stmt: rusqlite::Statement = conn.prepare("SELECT * FROM senders")
//         //         .expect("Unable to prepare query");

//         //     let mut rows = stmt.query([])
//         //         .expect("Unable to query rows");

//         //    while let Some(row) = rows.next().expect("no more rows") {
//         //       let ip_from_db: String = row.get(0).expect("Unable to open column 0");
//         //       //println!("ip_from_db is {ip_from_db}");
//         //     }
//         // }
// }


pub fn handle_icmp_code(protocol: i32, src_port:i32, dst_port:i32) -> (String, i32, i32) {
    //returning tuple in case I want to actually return type and code later
    if protocol == 1 {
        if src_port == 0 && dst_port == 0 {
            ("ECHO_REPLY".to_string(), 0, 0)
        }
        else if src_port == 2048 || dst_port == 2048 {
            ("ECHO_REQ".to_string(), 0, 0)
        }
        else if src_port == 768 || dst_port == 768 {
            ("NET_UNRCH".to_string(), 0, 0)
        }
        else if src_port == 769 || dst_port == 769 {
            ("HOST_UNRCH".to_string(), 0, 0)
        }
        else if src_port == 770 || dst_port == 770 {
            ("PROTO_UNRCH".to_string(), 0, 0)
        }
        else if src_port == 771 || dst_port == 771 {
            ("PORT_UNRCH".to_string(), 0, 0)
        }
        else {
            ("NOT_SURE".to_string(), src_port, dst_port)
        }
    }
    else {
    ("NONE".to_string(), src_port, dst_port)
    }

}

pub fn handle_traffic_type(flow: &NetFlow) -> String {
    //returning tuple in case I want to actually return type and code later

    //This only partially works because we don't know the mask for some broadcast traffic 
    //e.g. 10.0.0.255 could be valid unicast in a /16.

    let src_ip_cast = get_ip_cast_type(flow.src_and_dst_ip.0);
    let dst_ip_cast = get_ip_cast_type(flow.src_and_dst_ip.1);

    //let dst_mac = flow.

    if src_ip_cast == TrafficType::Multicast || dst_ip_cast == TrafficType::Multicast {
        "Multicast".to_string()
    }
    else if src_ip_cast == TrafficType::Broadcast || dst_ip_cast == TrafficType::Broadcast {
        "Broadcast".to_string()
    }
    // else if src_ip_cast == TrafficType::Broadcast || dst_ip_cast == TrafficType::Broadcast {
    //     "Broadcast".to_string()
    // }
    else 
    {
        "Unicast".to_string()
    }

}

pub fn handle_traffic_type_in_flow(src_addr: Ipv4Addr, dst_addr: Ipv4Addr) -> TrafficType {

    let src_ip_cast = get_ip_cast_type(src_addr);
    let dst_ip_cast = get_ip_cast_type(dst_addr);


    if src_ip_cast == TrafficType::Multicast || dst_ip_cast == TrafficType::Multicast {
        TrafficType::Multicast
    }
    else if src_ip_cast == TrafficType::Broadcast || dst_ip_cast == TrafficType::Broadcast {
        TrafficType::Broadcast
    }
    else 
    {
        TrafficType::Unicast
    }

}



pub fn get_all_flows_for_ip_as_json(state: &mut EZNFState, ip: &String) -> String {

    let mut all_flows: Vec<NetFlowJson> = Vec::new();
   
    let mut conn: MutexGuard<Connection> = state.db_conn_cli.lock().unwrap();


    let statement = "SELECT * FROM flows WHERE src_addr = ?1 OR dst_addr =?1 ORDER BY in_octets DESC LIMIT 250";

    let mut stmt: rusqlite::Statement = conn.prepare(statement)
        .expect("Unable to prepare query");


    let mut rows = stmt.query(params![ip])
        .expect("Unable to query rows");

       while let Some(row) = rows.next().expect("no more rows") {
          let sender_ip: String = row.get(1).expect("Unable to open column 1");
          //println!("sender_ip is {sender_ip}");
          let src_addr: String = row.get(2).expect("Unable to open column 2");
          //println!("src_addr is {src_addr}");
          let dst_addr: String = row.get(3).expect("Unable to open column 3");
          //println!("dst_addr is {dst_addr}");
          let proto: i32 = row.get(4).expect("Unable to open column 4");
          //println!("protocol is {protocol}");
          let src_port: i32 = row.get(5).expect("Unable to open column 5");
          //println!("src_port is {src_port}");
          let dst_port: i32 = row.get(6).expect("Unable to open column 6");
          //println!("dst_port is {dst_port}");
          let in_pkts: i32 = row.get(10).expect("Unable to open column 10");
          //println!("in_pkts is {in_pkts}");
          let in_bytes: i32 = row.get(11).expect("Unable to open column 11");
          //println!("in_bytes is {in_bytes}");
          let traffic_cast: String = row.get(17).expect("Unable to open column 17");

          let (icmp_type, src_port2,dst_port2) = handle_icmp_code(proto, src_port, dst_port);
       
        //let ip_cast = handle_traffic_cast(&src_addr, &dst_addr);
        //can't match on strings only string slice
        //let unicast_str = String::from("Unicast");
        //let multicast_str= String::from("Multicast");
        //let broadcast_str = String::from("Broadcast");

          let traffic_type_as_enum: TrafficType = match traffic_cast.as_str() {
            "Unicast" => TrafficType::Unicast,
            "Multicast" => TrafficType::Multicast,
            "Broadcast" => TrafficType::Broadcast,
            _ => TrafficType::Unicast,
          };

        let current_flow =  NetFlowJson {
            src_ip: convert_string_to_ipv4(&src_addr).unwrap(),
            dst_ip: convert_string_to_ipv4(&dst_addr).unwrap(),
            src_port: src_port.try_into().unwrap(),
            dst_port: dst_port.try_into().unwrap(),
            protocol: proto.try_into().unwrap(),
            in_octets: in_bytes.try_into().unwrap(),
            in_packets: in_pkts.try_into().unwrap(),
            traffic_type: traffic_type_as_enum,
            icmp: icmp_type,
        };
        
        // //only store unicast traffic, otherwise the graph will show empty entries
        // if current_flow.traffic_type == TrafficType::Unicast {
        //     // build json here and add it to vec
        //     all_flows.push(current_flow);
        // }

        //build json here and add it to vec
        all_flows.push(current_flow);

    }
    
    // let mut filtered_all_flows: Vec<NetFlowJson> = Vec::new();
    // filtered_all_flows.reserve(all_flows.len());

    // //need to process all flows to remove dups
    // for flow in &all_flows {
    //     for new_flow in &mut filtered_all_flows {
    //         if is_flow_match((flow.src_ip, flow.dst_ip), (new_flow.src_ip, new_flow.dst_ip), 
    //         (flow.src_port, flow.dst_port), (new_flow.src_port, new_flow.dst_port) ) {
    //             filtered_all_flows.push(flow.clone());
    //         }
    //     }
    // }

    serde_json::to_string(&all_flows).unwrap()

}
