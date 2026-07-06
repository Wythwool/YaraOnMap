use crate::engine::YaraExternal;
use crate::metrics::Registry;
use crate::types::Finding;
use anyhow::Result;
use crc32fast::Hasher as Crc32;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
#[cfg(windows)]
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_IMAGE, MEM_MAPPED, PAGE_EXECUTE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_READWRITE,
    PAGE_WRITECOPY,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
};

#[derive(Clone)]
pub struct PageCacheEntry {
    pub crc: u32,
    pub ts: Instant,
}
#[derive(Clone)]
pub struct PageCache {
    ttl: Duration,
    map: Arc<DashMap<(u32, u64), PageCacheEntry>>, // key=(pid,base)
}
impl PageCache {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            ttl: Duration::from_millis(ttl_ms),
            map: Arc::new(DashMap::new()),
        }
    }
    pub fn check(&self, pid: u32, base: u64, buf: &[u8]) -> bool {
        let mut h = Crc32::new();
        h.update(buf);
        let crc = h.finalize();
        if let Some(mut e) = self.map.get_mut(&(pid, base)) {
            if e.crc == crc && e.ts.elapsed() < self.ttl {
                return true;
            }
            e.crc = crc;
            e.ts = Instant::now();
            false
        } else {
            self.map.insert(
                (pid, base),
                PageCacheEntry {
                    crc,
                    ts: Instant::now(),
                },
            );
            false
        }
    }
}

#[cfg(windows)]
fn read_page(h: HANDLE, addr: u64, page_bytes: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; page_bytes];
    let mut read = 0usize;
    unsafe {
        if ReadProcessMemory(
            h,
            addr as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            page_bytes,
            Some(&mut read),
        )
        .is_ok()
            && read > 0
        {
            buf.truncate(read);
            return Some(buf);
        }
    }
    None
}

#[cfg(windows)]
fn page_iter(h: HANDLE, page_bytes: usize) -> Vec<(u64, usize, u32, String, String)> {
    let mut res = Vec::new();
    let mut addr: usize = 0;
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    loop {
        let q = unsafe {
            VirtualQueryEx(
                h,
                Some(addr as *const c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if q == 0 {
            break;
        }
        let base = mbi.BaseAddress as usize;
        let size = mbi.RegionSize;
        let prot = mbi.Protect;
        let state_kind = if mbi.Type == MEM_IMAGE {
            "IMAGE"
        } else if mbi.Type == MEM_MAPPED {
            "MAPPED"
        } else {
            "PRIVATE"
        };
        let pstr = format!("{:?}", prot);
        // choose only meaningful pages
        let exec = prot == PAGE_EXECUTE
            || prot == PAGE_EXECUTE_READ
            || prot == PAGE_EXECUTE_READWRITE
            || prot == PAGE_EXECUTE_WRITECOPY;
        let write = prot == PAGE_READWRITE
            || prot == PAGE_WRITECOPY
            || prot == PAGE_EXECUTE_READWRITE
            || prot == PAGE_EXECUTE_WRITECOPY;
        if exec || write {
            // iterate by pages inside region
            let end = base + size;
            let mut cur = base;
            while cur < end {
                res.push((
                    cur as u64,
                    page_bytes.min(end - cur),
                    prot.0,
                    pstr.clone(),
                    state_kind.to_string(),
                ));
                cur += page_bytes;
            }
        }
        addr = base + size;
    }
    res
}

pub fn scan_process_pages(
    pid: u32,
    rules: &YaraExternal,
    page_bytes: usize,
    proc_budget: Duration,
    cache: &PageCache,
    reg: &Registry,
) -> Result<Vec<Finding>> {
    #[cfg(windows)]
    unsafe {
        let mask = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION;
        let Ok(h) = OpenProcess(mask, false, pid) else {
            return Ok(Vec::new());
        };
        if h.is_invalid() {
            return Ok(vec![]);
        }
        let iter = page_iter(h, page_bytes);
        let mut out = Vec::new();
        let started = Instant::now();
        for (base, size, _prot, prot_str, kind) in iter {
            if started.elapsed() >= proc_budget {
                reg.inc_process_budget_exceeded();
                log::warn!("process scan budget exceeded for pid={pid}");
                break;
            }

            if let Some(buf) = read_page(h, base, page_bytes) {
                if cache.check(pid, base, &buf) {
                    reg.inc_skipped();
                    continue;
                }
                reg.inc_scanned();
                match rules.scan_bytes(&buf) {
                    Ok(hits) if !hits.is_empty() => {
                        for rule in hits {
                            out.push(Finding {
                                pid,
                                base,
                                size,
                                rule: rule.clone(),
                                severity: "high".into(),
                                message: format!(
                                    "match {} at 0x{:x} {} {}",
                                    rule, base, kind, prot_str
                                ),
                            });
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        reg.inc_page_scan_errors();
                        log::warn!("page scan failed for pid={pid} base=0x{base:x}: {err}");
                    }
                }
            }
        }
        let _ = CloseHandle(h);
        Ok(out)
    }
    #[cfg(not(windows))]
    {
        let _ = proc_budget;
        Ok(vec![])
    }
}
