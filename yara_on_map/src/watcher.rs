use crate::types::ScanTask;
use crate::config::Priorities;

#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32W, Process32FirstW, Process32NextW};
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle};

#[cfg(windows)]
fn list_pids() -> Vec<u32> {
    unsafe {
        let h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
        let mut out = Vec::new();
        let mut pe = PROCESSENTRY32W::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(h, &mut pe).as_bool() {
            loop {
                out.push(pe.th32ProcessID);
                if !Process32NextW(h, &mut pe).as_bool() { break; }
            }
        }
        CloseHandle(h);
        out
    }
}

pub fn build_tasks(pids: Option<Vec<u32>>, prio: &Priorities) -> Vec<ScanTask> {
    #[cfg(windows)]
    {
        let mut v = Vec::new();
        let p = if let Some(ps) = pids { ps } else { list_pids() };
        for pid in p {
            v.push(ScanTask{ pid, base: 0, size: 0, priority: prio.exec }); // base/size not used at task level
        }
        v
    }
    #[cfg(not(windows))]
    { vec![] }
}
