use crate::engine::YaraExternal;
use crate::metrics::Registry;
use crate::pager::{scan_process_pages, PageCache};
use crate::types::{Finding, ScanTask};
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
        Self {
            rules: Arc::new(rules),
            cache,
            reg,
            page_bytes,
        }
    }
    pub fn run_once(&self, tasks: Vec<ScanTask>) -> Vec<Finding> {
        tasks
            .into_par_iter()
            .flat_map(|t| {
                scan_process_pages(t.pid, &self.rules, self.page_bytes, &self.cache, &self.reg)
                    .unwrap_or_default()
            })
            .collect()
    }
}
