use std::sync::Arc;
use parking_lot::Mutex;
use crossbeam-channel::Receiver;

#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<Inner>>,
}
#[derive(Default)]
struct Inner {
    pub pages_scanned: u64,
    pub pages_skipped_cache: u64,
    pub findings: u64,
    pub quarantined_pages: u64,
}

impl Registry {
    pub fn new() -> Self { Self::default() }
    pub fn inc_scanned(&self) { self.inner.lock().pages_scanned += 1; }
    pub fn inc_skipped(&self) { self.inner.lock().pages_skipped_cache += 1; }
    pub fn inc_findings(&self) { self.inner.lock().findings += 1; }
    pub fn inc_quarantined(&self) { self.inner.lock().quarantined_pages += 1; }
    pub fn render(&self) -> String {
        let g = self.inner.lock();
        let mut out = String::new();
        out.push_str("# HELP yom_pages_scanned_total Pages scanned\n# TYPE yom_pages_scanned_total counter\n");
        out.push_str(&format!("yom_pages_scanned_total {}\n", g.pages_scanned));
        out.push_str("# HELP yom_pages_skipped_cache_total Pages skipped due to cache\n# TYPE yom_pages_skipped_cache_total counter\n");
        out.push_str(&format!("yom_pages_skipped_cache_total {}\n", g.pages_skipped_cache));
        out.push_str("# HELP yom_findings_total Findings\n# TYPE yom_findings_total counter\n");
        out.push_str(&format!("yom_findings_total {}\n", g.findings));
        out.push_str("# HELP yom_quarantined_pages_total Pages quarantined\n# TYPE yom_quarantined_pages_total counter\n");
        out.push_str(&format!("yom_quarantined_pages_total {}\n", g.quarantined_pages));
        out
    }
}

pub fn serve_http(addr: String, rx: Receiver<()>, reg: Registry) {
    std::thread::spawn(move || {
        let server = tiny_http::Server::http(&addr).expect("bind http");
        eprintln!("[info] metrics listening on {}", addr);
        loop {
            if let Ok(_) = rx.try_recv() { break; }
            if let Ok(req) = server.recv_timeout(std::time::Duration::from_millis(200)) {
                if req.url() == "/metrics" {
                    let resp = tiny_http::Response::from_string(reg.render()).with_status_code(200);
                    let _ = req.respond(resp);
                } else if req.url() == "/healthz" {
                    let resp = tiny_http::Response::from_string("ok").with_status_code(200);
                    let _ = req.respond(resp);
                } else {
                    let resp = tiny_http::Response::from_string("use /metrics or /healthz").with_status_code(404);
                    let _ = req.respond(resp);
                }
            }
        }
    });
}
