use crate::types::Finding;
use crate::metrics::Registry;

#[cfg(windows)]
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READONLY};
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle};

pub fn quarantine(findings: &[Finding], reg: &Registry) {
    #[cfg(windows)]
    unsafe {
        for f in findings {
            let h = OpenProcess(PROCESS_VM_OPERATION, false, f.pid);
            if h.is_invalid() { continue; }
            let mut old = PAGE_PROTECTION_FLAGS(0);
            let _ = VirtualProtectEx(h, f.base as _, f.size, PAGE_READONLY, &mut old);
            CloseHandle(h);
            reg.inc_quarantined();
        }
    }
}
