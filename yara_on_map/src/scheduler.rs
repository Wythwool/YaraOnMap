use crate::types::{ScanTask, Finding};
use crate::pager::{PageCache, scan_process_pages};
use crate::engine::YaraExternal;
use crate::metrics::Registry;
use crossbeam-channel::{unbounded, Receiver, Sender};
use rayon::prelude::*;
use std::sync::Arc;

pub struct Scheduler {
    rules: Arc<YaraExternal>,
    cache: PageCache,
    reg: Registry,
    page_bytes: usize,
}

impl Scheduler {
    pub fn new(rules: YaraExternal, cache: PageCache, reg: Registry, page_bytes: usize) -> Self {
        Self { rules: Arc::new(rules), cache, reg, page_bytes }
    }
    pub fn run_once(&self, tasks: Vec<ScanTask>) -> Vec<Finding> {
        tasks.into_par_iter().map(|t| {
            scan_process_pages(t.pid, &self.rules, self.page_bytes, &self.cache, &self.reg).unwrap_or_default()
        }).flatten().collect()
    }
}
