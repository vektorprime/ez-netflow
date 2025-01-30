

#[derive(Debug)]
pub struct ServerSettings {
    pub conn_type: ConnType,
    pub flow_limit: FlowsToShow,
    pub sort_by: SortBy,
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