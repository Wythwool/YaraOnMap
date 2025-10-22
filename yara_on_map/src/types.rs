use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub pid: u32,
    pub base: u64,
    pub size: usize,
    pub rule: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub pid: u32,
    pub base: u64,
    pub size: usize,
    pub prot: String,
    pub kind: String, // IMAGE/MAPPED/PRIVATE
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTask {
    pub pid: u32,
    pub base: u64,
    pub size: usize,
    pub priority: u8,
}
