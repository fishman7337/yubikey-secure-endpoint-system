//! Single-instance guard for the native watchdog.
//!
//! Task Scheduler can only prevent duplicate launcher processes that it still
//! owns. The watchdog therefore also protects itself with a named mutex keyed
//! to the configured `.env` path.

use std::path::{Path, PathBuf};

/// Error returned while acquiring the process-wide instance guard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstanceError {
    /// Another watchdog is already running for the same configuration file.
    AlreadyRunning,
    /// Windows rejected the mutex request.
    System(String),
}

/// Holds the OS handle that keeps this instance registered.
#[derive(Debug)]
pub struct InstanceGuard {
    _platform: platform::PlatformGuard,
}

impl InstanceGuard {
    /// Acquires the singleton guard for an environment file.
    pub fn acquire_for_env_file(env_file: &Path) -> Result<Self, InstanceError> {
        Self::acquire_named(&mutex_name_for_env_file(env_file))
    }

    fn acquire_named(name: &str) -> Result<Self, InstanceError> {
        platform::acquire_named(name).map(|platform| Self {
            _platform: platform,
        })
    }
}

/// Returns the deterministic mutex name used for `env_file`.
pub fn mutex_name_for_env_file(env_file: &Path) -> String {
    let normalized = normalized_env_path(env_file);
    format!("Local\\YubiWatch-{:016x}", stable_hash(&normalized))
}

fn normalized_env_path(env_file: &Path) -> String {
    let absolute = absolute_env_path(env_file);
    absolute.to_string_lossy().to_ascii_lowercase()
}

fn absolute_env_path(env_file: &Path) -> PathBuf {
    if let Ok(canonical) = env_file.canonicalize() {
        return canonical;
    }

    if env_file.is_absolute() {
        return env_file.to_path_buf();
    }

    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(env_file)
}

fn stable_hash(value: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::ptr;

    use super::InstanceError;

    const ERROR_ALREADY_EXISTS: u32 = 183;

    #[derive(Debug)]
    pub(super) struct PlatformGuard {
        handle: *mut c_void,
    }

    impl Drop for PlatformGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe {
                    CloseHandle(self.handle);
                }
            }
        }
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateMutexW(
            lp_mutex_attributes: *mut c_void,
            b_initial_owner: i32,
            lp_name: *const u16,
        ) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }

    pub(super) fn acquire_named(name: &str) -> Result<PlatformGuard, InstanceError> {
        let name = wide_null(name);
        let handle = unsafe { CreateMutexW(ptr::null_mut(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err(InstanceError::System(format!(
                "CreateMutexW failed with Windows error {}",
                unsafe { GetLastError() }
            )));
        }

        let error = unsafe { GetLastError() };
        if error == ERROR_ALREADY_EXISTS {
            unsafe {
                CloseHandle(handle);
            }
            return Err(InstanceError::AlreadyRunning);
        }

        Ok(PlatformGuard { handle })
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::InstanceError;

    #[derive(Debug)]
    pub(super) struct PlatformGuard;

    pub(super) fn acquire_named(name: &str) -> Result<PlatformGuard, InstanceError> {
        if name.trim().is_empty() {
            Err(InstanceError::System(
                "instance mutex name is empty".to_string(),
            ))
        } else {
            Ok(PlatformGuard)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutex_name_is_stable_for_same_path() {
        let path = Path::new(".env");
        assert_eq!(mutex_name_for_env_file(path), mutex_name_for_env_file(path));
    }

    #[cfg(windows)]
    #[test]
    fn named_mutex_detects_duplicate_until_guard_is_dropped() {
        let name = format!(
            "Local\\YubiWatchTest-{}-{}",
            std::process::id(),
            stable_hash("duplicate-test")
        );

        let first = InstanceGuard::acquire_named(&name).unwrap();
        assert_eq!(
            InstanceGuard::acquire_named(&name).unwrap_err(),
            InstanceError::AlreadyRunning
        );

        drop(first);
        let second = InstanceGuard::acquire_named(&name).unwrap();
        drop(second);
    }
}
