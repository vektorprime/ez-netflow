use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{params, Connection, Error, Result, Row, Rows, Statement};

use tabled::tables::*;

mod server;
mod fields;
mod templates;
mod senders;
mod utils;
mod cli;
mod sql;
mod settings;

use server::NetflowServer;
use crate::cli::*;

use crate::sql::*;
use crate::settings::*;



fn main() {
    let server_settings = ServerSettings {
        conn_type: ConnType::InFile,
        flow_limit: FlowsToShow::Limit { flows: (30) },
        sort_by: SortBy::Bytes
    };
    
    //secure the db access for multi-thread use
    let mut db_conn_cli: std::sync::Arc<Mutex<Connection>>  = Arc::new(Mutex::new(setup_db(&server_settings.conn_type)));
    let db_conn_srv: std::sync::Arc<Mutex<Connection>>  = Arc::clone(&db_conn_cli);

    //println!("server settings conn type is {:#?}", server_settings.conn_type);

    let server_thread = thread::spawn(move || {
        let mut netflow_server = NetflowServer::new("10.0.0.40:2055", db_conn_srv);
        netflow_server.run();
    });


    loop {
       std::thread::sleep(Duration::from_secs(5));
        clear_console();
        let flow_table = get_all_flows_from_sender(&mut db_conn_cli, &server_settings);
        println!("{flow_table}");
    }
    
}
