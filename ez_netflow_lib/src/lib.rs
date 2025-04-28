use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{params, Connection, Error, Result, Row, Rows, Statement};

use tabled::tables::*;

pub mod server;
pub mod fields;
pub mod templates;
pub mod senders;
pub mod utils;
pub mod sql;
pub mod settings;
pub mod time;

use server::NetflowServer;

use crate::sql::*;
use crate::settings::*;


/////////////////////////////////////////////
//// EXAMPLE OF RUNNING THE SERVER IN YOUR CODE
//// 
//
// let server_settings = ServerSettings::new("config.ini");
//
// //secure the db access for multi-thread use
// let mut db_conn_cli: std::sync::Arc<Mutex<Connection>>  = Arc::new(Mutex::new(setup_db(&server_settings.conn_type)));
// let db_conn_srv: std::sync::Arc<Mutex<Connection>>  = Arc::clone(&db_conn_cli);
//
// //println!("server settings conn type is {:#?}", server_settings.conn_type);
// let srv_addr_and_port = String::from(&server_settings.address) + ":" + &server_settings.port.to_string();
// let server_thread = thread::spawn(move || {
//     let mut netflow_server = NetflowServer::new(srv_addr_and_port , db_conn_srv);
//     netflow_server.run();
// });
//
/////////////////////////////////////////////
//// 
//// CHECK SQL RS FOR FUNCTIONS THAT PULL DATA FROM DB
////
/////////////////////////////////////////////