use std::io;
use std::io::{Error,ErrorKind};

use crate::senders::*;
use crate::utils::*;
use std::net::Ipv4Addr;
use std::convert::TryInto;


pub fn get_user_input(senders: &Vec<NetflowSender>) -> Result<String, std::io::Error> {
    if senders.is_empty() {
        println!("There are currently no senders to report data on");
        //println!("\n");
        Err(Error::new(ErrorKind::NotFound, "Senders not found"))
    }
    else {
        println!("Please select one of the following senders");
        //println!("\n");
        for s in senders {
            println!("{}",s.ip_addr);
        }
        let mut answer = String::new();
        io::stdin().read_line(&mut answer).expect("Failed to read line");
        Ok(answer)
    }
}


pub fn show_sender_info(senders: &Vec<NetflowSender>, ip: Ipv4Addr) {
    for s in senders {
        if s.ip_addr == ip {
            s.report_flow_stats();
        }
    }
    let mut confirmed_continue = false;
    while !confirmed_continue {
        println!("Press enter clear the screen and continue");
        let mut answer = String::new();
        io::stdin().read_line(&mut answer).expect("Failed to read line");
        //check for pressed enter
        if answer.trim().is_empty() { 
            confirmed_continue = true;
            //clear screen
            clear_console();
        };
        
    }

}


//found this fn to clear console

pub fn clear_console() {
    println!("\x1B[2J\x1B[1;1H");
}