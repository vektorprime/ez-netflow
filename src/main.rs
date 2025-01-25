
use std::sync::mpsc::Receiver;
use std::thread;
use std::sync::mpsc;
use std::time::Duration;

mod server;
mod fields;
mod templates;
mod senders;
mod utils;
mod cli;

use server::NetflowServer;
use crate::cli::*;
use crate::utils::*;
use crate::senders::*;


fn main() {

    let (tx , rx) = mpsc::channel();
    let tx1 = tx.clone();
    let server_thread = thread::spawn(move || {
        let mut netflow_server = NetflowServer::new("10.0.0.40:2055", tx1);
        netflow_server.run();
    });

    let saved_senders: Vec<NetflowSender> = Vec::new();

    loop {
        let available_senders_result = rx.try_recv();
        let available_senders = match available_senders_result {
            Ok(s) => s,
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                //println!("Nothing to receive, skipping");
                thread::sleep(Duration::from_secs(1));
                print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
                println!("No data available, please wait");
                //println!("\n");
                continue
            },
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                panic!("Receiver disconnected");
            }
        };
        let user_input = get_user_input(&available_senders).unwrap();
        let ip_to_check = convert_string_to_ipv4(user_input);
        let ip = match ip_to_check {
            Ok(ip) => ip,
            Err(e) => {
                println!("Unable to parse string to ipv4, skipping");
                continue
            }
        };
        show_sender_info(&available_senders, ip);
    }
    
}
