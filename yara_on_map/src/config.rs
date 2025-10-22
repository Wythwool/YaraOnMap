use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineCfg {
    pub r#type: String,
    pub yara_path: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCfg {
    pub page_bytes: usize,
    pub timeout_ms: u64,
    pub proc_budget_ms: u64,
    pub cache_ttl_ms: u64,
    pub max_workers: usize,
    pub priorities: Priorities,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Priorities { pub exec: u8, pub write: u8, pub read: u8 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsCfg { pub listen: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogCfg { pub level: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCfg {
    pub engine: EngineCfg,
    pub scan: ScanCfg,
    pub mode: String, // audit|enforce
    pub metrics: MetricsCfg,
    pub logging: LogCfg,
}

impl Default for AppCfg {
    fn default() -> Self {
        serde_yaml::from_str(include_str!("../../config/default.yaml")).unwrap()
    }
}
