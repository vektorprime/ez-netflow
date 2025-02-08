
use std::io::ErrorKind;
use std::sync::{Arc, Mutex, MutexGuard};
use std::net::Ipv4Addr;

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
            src_addr = ?1 AND 
            dst_addr = ?2 AND 
            src_port = ?3 AND 
            dst_port = ?4 AND 
            protocol = ?5",
            params![&flow.src_and_dst_ip.0.to_string(), 
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
            //println!("Error in checking for existing fow in SQL, setting flow as existing,  error is {e}");
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

    //switched to making parts of the query in match statements so it's more concise
    // let mut stmt: rusqlite::Statement = match server_settings.sort_by {
    //     SortBy::Bytes => { 
    //         conn.prepare(joined_statement + " ORDER BY in_octets DESC LIMIT ?2")
    //             .expect("Unable to prepare query")
    //     },
    //     SortBy::Pkts => {
    //         conn.prepare("SELECT * FROM flows ORDER BY in_pkts DESC LIMIT ?")
    //             .expect("Unable to prepare query")
    //     },
    //     SortBy::None => {
    //         conn.prepare("SELECT * FROM flows LIMIT ?")
    //             .expect("Unable to prepare query")
    //     }
    // } ;

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