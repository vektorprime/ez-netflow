use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{params, Connection, Error, Result, Row, Rows, Statement};

use tabled::tables::*;


mod cli;
use crate::cli::*;


use ez_netflow_lib::server::*;
use ez_netflow_lib::sql::*;
use ez_netflow_lib::settings::*;


fn main() {


    let server_settings = ServerSettings::new("config.ini");

    
    //secure the db access for multi-thread use
    let mut db_conn_cli: std::sync::Arc<Mutex<Connection>>  = Arc::new(Mutex::new(setup_db(&server_settings.conn_type)));
    let db_conn_srv: std::sync::Arc<Mutex<Connection>>  = Arc::clone(&db_conn_cli);

    //println!("server settings conn type is {:#?}", server_settings.conn_type);
    let srv_addr_and_port = String::from(&server_settings.address) + ":" + &server_settings.port.to_string();
    thread::spawn(move || {
        let mut netflow_server = NetflowServer::new(srv_addr_and_port , db_conn_srv);
        netflow_server.run();
    });


    loop {
       std::thread::sleep(Duration::from_secs(5));
        clear_console();
        let flow_table = get_all_flows_from_sender(&mut db_conn_cli, &server_settings);
        println!("{flow_table}");
    }
    
}
