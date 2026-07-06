use anyhow::{anyhow, Result};
use crossbeam_channel::Receiver;
use parking_lot::Mutex;
use std::sync::Arc;
use std::thread::JoinHandle;

#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<Inner>>,
}
#[derive(Default)]
struct Inner {
    pub pages_scanned: u64,
    pub pages_skipped_cache: u64,
    pub page_scan_errors: u64,
    pub process_scan_errors: u64,
    pub process_budget_exceeded: u64,
    pub findings: u64,
    pub quarantined_pages: u64,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn inc_scanned(&self) {
        self.inner.lock().pages_scanned += 1;
    }
    pub fn inc_skipped(&self) {
        self.inner.lock().pages_skipped_cache += 1;
    }
    pub fn inc_page_scan_errors(&self) {
        self.inner.lock().page_scan_errors += 1;
    }
    pub fn inc_process_scan_errors(&self) {
        self.inner.lock().process_scan_errors += 1;
    }
    pub fn inc_process_budget_exceeded(&self) {
        self.inner.lock().process_budget_exceeded += 1;
    }
    pub fn inc_findings(&self) {
        self.inner.lock().findings += 1;
    }
    pub fn inc_quarantined(&self) {
        self.inner.lock().quarantined_pages += 1;
    }
    pub fn render(&self) -> String {
        let g = self.inner.lock();
        let mut out = String::new();
        out.push_str("# HELP yom_pages_scanned_total Pages scanned\n# TYPE yom_pages_scanned_total counter\n");
        out.push_str(&format!("yom_pages_scanned_total {}\n", g.pages_scanned));
        out.push_str("# HELP yom_pages_skipped_cache_total Pages skipped due to cache\n# TYPE yom_pages_skipped_cache_total counter\n");
        out.push_str(&format!(
            "yom_pages_skipped_cache_total {}\n",
            g.pages_skipped_cache
        ));
        out.push_str("# HELP yom_page_scan_errors_total Page-level scan errors\n# TYPE yom_page_scan_errors_total counter\n");
        out.push_str(&format!(
            "yom_page_scan_errors_total {}\n",
            g.page_scan_errors
        ));
        out.push_str("# HELP yom_process_scan_errors_total Process-level scan errors\n# TYPE yom_process_scan_errors_total counter\n");
        out.push_str(&format!(
            "yom_process_scan_errors_total {}\n",
            g.process_scan_errors
        ));
        out.push_str("# HELP yom_process_budget_exceeded_total Processes stopped after the configured budget\n# TYPE yom_process_budget_exceeded_total counter\n");
        out.push_str(&format!(
            "yom_process_budget_exceeded_total {}\n",
            g.process_budget_exceeded
        ));
        out.push_str("# HELP yom_findings_total Findings\n# TYPE yom_findings_total counter\n");
        out.push_str(&format!("yom_findings_total {}\n", g.findings));
        out.push_str("# HELP yom_quarantined_pages_total Pages quarantined\n# TYPE yom_quarantined_pages_total counter\n");
        out.push_str(&format!(
            "yom_quarantined_pages_total {}\n",
            g.quarantined_pages
        ));
        out
    }
}

pub fn serve_http(addr: String, rx: Receiver<()>, reg: Registry) -> Result<JoinHandle<()>> {
    let server = tiny_http::Server::http(&addr)
        .map_err(|err| anyhow!("failed to bind metrics server at {addr}: {err}"))?;
    Ok(std::thread::spawn(move || {
        log::info!("metrics listening on {}", addr);
        loop {
            if rx.try_recv().is_ok() {
                break;
            }
            if let Ok(Some(req)) = server.recv_timeout(std::time::Duration::from_millis(200)) {
                if req.url() == "/metrics" {
                    let resp = tiny_http::Response::from_string(reg.render()).with_status_code(200);
                    let _ = req.respond(resp);
                } else if req.url() == "/healthz" {
                    let resp = tiny_http::Response::from_string("ok").with_status_code(200);
                    let _ = req.respond(resp);
                } else {
                    let resp = tiny_http::Response::from_string("use /metrics or /healthz")
                        .with_status_code(404);
                    let _ = req.respond(resp);
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_includes_runtime_error_counters() {
        let reg = Registry::new();
        reg.inc_page_scan_errors();
        reg.inc_process_scan_errors();
        reg.inc_process_budget_exceeded();

        let out = reg.render();

        assert!(out.contains("yom_page_scan_errors_total 1"));
        assert!(out.contains("yom_process_scan_errors_total 1"));
        assert!(out.contains("yom_process_budget_exceeded_total 1"));
    }
}
