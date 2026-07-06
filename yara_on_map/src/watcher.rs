use crate::config::Priorities;
use crate::types::ScanTask;

#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

#[cfg(windows)]
fn list_pids() -> Vec<u32> {
    unsafe {
        let Ok(h) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut pe = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(h, &mut pe).is_ok() {
            loop {
                out.push(pe.th32ProcessID);
                if Process32NextW(h, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(h);
        out
    }
}

pub fn build_tasks(pids: Option<Vec<u32>>, prio: &Priorities) -> Vec<ScanTask> {
    #[cfg(windows)]
    {
        let mut v = Vec::new();
        let p = if let Some(ps) = pids { ps } else { list_pids() };
        for pid in p {
            v.push(ScanTask {
                pid,
                base: 0,
                size: 0,
                priority: prio.exec,
            }); // base/size not used at task level
        }
        v
    }
    #[cfg(not(windows))]
    {
        vec![]
    }
}
