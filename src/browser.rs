//! Default-browser launcher for the local dashboard.
//!
//! The watchdog keeps the dashboard server inside the native process. This
//! helper only asks Windows to open the already-local URL in the user's default
//! browser; it does not create any network listener.

/// Opens `url` in the user's default browser.
pub fn open_url(url: &str) -> Result<(), String> {
    if url.trim().is_empty() {
        return Err("dashboard URL is empty".to_string());
    }

    platform::open_url(url)
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::ptr;

    const SW_SHOWNORMAL: i32 = 1;

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn ShellExecuteW(
            hwnd: *mut c_void,
            lp_operation: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show_cmd: i32,
        ) -> isize;
    }

    pub(super) fn open_url(url: &str) -> Result<(), String> {
        let operation = wide_null("open");
        let target = wide_null(url);

        // ShellExecuteW returns a value greater than 32 on success.
        let result = unsafe {
            ShellExecuteW(
                ptr::null_mut(),
                operation.as_ptr(),
                target.as_ptr(),
                ptr::null(),
                ptr::null(),
                SW_SHOWNORMAL,
            )
        };

        if result <= 32 {
            Err(format!(
                "ShellExecuteW failed to open dashboard with code {result}"
            ))
        } else {
            Ok(())
        }
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    pub(super) fn open_url(_url: &str) -> Result<(), String> {
        Err("opening the dashboard browser is only supported on Windows".to_string())
    }
}
