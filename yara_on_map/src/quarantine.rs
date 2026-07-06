use crate::metrics::Registry;
use crate::types::Finding;

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READONLY};
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

pub fn quarantine(findings: &[Finding], reg: &Registry) {
    #[cfg(windows)]
    unsafe {
        for f in findings {
            let Ok(h) = OpenProcess(PROCESS_VM_OPERATION, false, f.pid) else {
                continue;
            };
            if h.is_invalid() {
                continue;
            }
            let mut old = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtectEx(h, f.base as *const c_void, f.size, PAGE_READONLY, &mut old);
            let _ = CloseHandle(h);
            reg.inc_quarantined();
        }
    }
}
