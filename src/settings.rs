

use std::fs;
use std::io::ErrorKind;
use std::io::Write;


#[derive(Debug)]
pub struct ServerSettings {
    pub conn_type: ConnType,
    pub flow_limit: FlowsToShow,
    pub sort_by: SortBy,
}

impl ServerSettings {
    pub fn new(file: &str) -> Self {
        let default_config: &[u8] = 
        "database_file_or_mem: file,\nflows_to_display: 30,\nsort_flows_by_bytes_or_packets: bytes".as_bytes();

        let config_result = fs::read_to_string(file);
            //.expect("Unable to read config.ini");

        
        let config_string = match config_result {
            Ok(c) => c,
            Err(e) => match e.kind() { 
               ErrorKind::NotFound => {
                   let mut temp_file = fs::File::create("config.ini").expect("Unable to create config.ini");
                    temp_file.write_all(default_config).expect("Unable to write default config to config.ini");
                    temp_file.sync_all().expect("Unable to sync io after writing config.ini");
                    fs::read_to_string(file).expect("attempted to create and read config.ini, but failed")
                },
               other_error => {
                panic!("Problem opening file {other_error:?}");
               }
            }
        };

    parse_config_string(config_string)

    }

   
}

pub fn parse_config_string(config_string: String) -> ServerSettings {
    
    let mut settings = ServerSettings {
        conn_type: ConnType::InFile,
        flow_limit: FlowsToShow::Limit { flows: (30) },
        sort_by: SortBy::Bytes
    };

    let config_vec: Vec<&str> = config_string.trim().split(",").collect();
    for c in config_vec {
        if c.contains("database_file_or_mem") {
            let c2: Vec<&str> = c.split(":").collect();
            //println!("c2 is {}, AND {}", c2[0], c2[1]);
            if c2.len() == 2 {
                if c2[1].contains("file") {
                    settings.conn_type = ConnType::InFile;
                }
                else {
                    settings.conn_type = ConnType::InMemory;
                }
            }
        }
        else if c.contains("flows_to_display") {
            let c2: Vec<&str> = c.split(":").collect();
            //println!("c2 is {}, AND {}", c2[0], c2[1]);
            if c2.len() == 2 {
                let flow_limit_int :i32 = c2[1].trim().parse().unwrap();
                settings.flow_limit  = FlowsToShow::Limit { flows: (flow_limit_int) };
                //println!("existing flows is {} ", flow_limit_int);
            }
        }
        else if c.contains("sort_flows_by_bytes_or_packets") {
            let c2: Vec<&str> = c.split(":").collect();
            //println!("c2 is {}, AND {}", c2[0], c2[1]);
            if c2.len() == 2 {
                if c2[1].contains("bytes") {
                    settings.sort_by = SortBy::Bytes;
                }
                else {
                    settings.sort_by = SortBy::Pkts;
                }
            }
        }
    }
    
    settings

}

#[derive(Debug)]
pub enum FlowsToShow {
    Limit{flows: i32},
    NoLimit,
}

#[derive(Debug)]
pub enum ConnType {
    InMemory,
    InFile,
}

#[derive(Debug)]
pub enum SortBy {
    Pkts,
    Bytes,
    None
}