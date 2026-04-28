//! Workstation locking abstraction.

/// Lock target used by the watchdog policy.
pub trait Locker {
    /// Requests a workstation lock.
    fn lock(&mut self) -> Result<(), String>;
}

/// Windows `LockWorkStation` implementation.
#[derive(Clone, Debug)]
pub struct WorkstationLocker {
    enabled: bool,
}

impl WorkstationLocker {
    /// Creates a locker. `enabled=false` is used only for dry-run mode.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }
}

impl Locker for WorkstationLocker {
    fn lock(&mut self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        platform::lock_workstation()
    }
}

#[cfg(windows)]
mod platform {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn LockWorkStation() -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLastError() -> u32;
    }

    pub(super) fn lock_workstation() -> Result<(), String> {
        let ok = unsafe { LockWorkStation() };
        if ok == 0 {
            Err(format!(
                "LockWorkStation failed with Windows error {}",
                unsafe { GetLastError() }
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub(super) fn lock_workstation() -> Result<(), String> {
        Err("LockWorkStation is only available on Windows".to_string())
    }
}
