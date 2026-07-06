use crate::engine::YaraExternal;
use crate::metrics::Registry;
use crate::pager::{scan_process_pages, PageCache};
use crate::types::{Finding, ScanTask};
use anyhow::{Context, Result};
use rayon::{prelude::*, ThreadPool, ThreadPoolBuilder};
use std::sync::Arc;
use std::time::Duration;

pub struct Scheduler {
    rules: Arc<YaraExternal>,
    cache: PageCache,
    reg: Registry,
    page_bytes: usize,
    proc_budget: Duration,
    pool: ThreadPool,
}

impl Scheduler {
    pub fn new(
        rules: YaraExternal,
        cache: PageCache,
        reg: Registry,
        page_bytes: usize,
        max_workers: usize,
        proc_budget_ms: u64,
    ) -> Result<Self> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(max_workers.max(1))
            .thread_name(|index| format!("yom-scan-{index}"))
            .build()
            .context("failed to create scheduler worker pool")?;

        Ok(Self {
            rules: Arc::new(rules),
            cache,
            reg,
            page_bytes,
            proc_budget: Duration::from_millis(proc_budget_ms.max(1)),
            pool,
        })
    }
    pub fn run_once(&self, tasks: Vec<ScanTask>) -> Vec<Finding> {
        self.pool.install(|| {
            tasks
                .into_par_iter()
                .flat_map(|t| {
                    match scan_process_pages(
                        t.pid,
                        &self.rules,
                        self.page_bytes,
                        self.proc_budget,
                        &self.cache,
                        &self.reg,
                    ) {
                        Ok(findings) => findings,
                        Err(err) => {
                            self.reg.inc_process_scan_errors();
                            log::warn!("process scan failed for pid={}: {err}", t.pid);
                            Vec::new()
                        }
                    }
                })
                .collect()
        })
    }
}
