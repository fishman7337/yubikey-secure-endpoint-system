//! Windows USB detector for the native watchdog.
//!
//! The detector reads present hardware IDs through SetupAPI and matches the
//! configured Yubico vendor/product identifiers. It does not talk to libusb.

use crate::config::AppConfig;
use std::sync::{Arc, RwLock};

/// A matching present device reported by Windows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceMatch {
    /// Raw Windows hardware or compatible ID that matched.
    pub hardware_id: String,
    /// USB product ID extracted from the hardware ID when present.
    pub product_id: Option<u16>,
}

/// A present Yubico device, whether trusted or still a candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YubicoDevice {
    /// Raw Windows hardware or compatible ID.
    pub hardware_id: String,
    /// USB product ID extracted from the hardware ID.
    pub product_id: u16,
}

/// Shared trusted product ID store.
#[derive(Clone, Debug)]
pub struct TrustedProducts {
    inner: Arc<RwLock<Vec<u16>>>,
}

impl TrustedProducts {
    /// Creates a trusted product store.
    pub fn new(product_ids: Vec<u16>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(deduplicate_product_ids(product_ids))),
        }
    }

    /// Returns trusted product IDs in configured order.
    pub fn product_ids(&self) -> Vec<u16> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Returns whether a product ID is currently trusted.
    pub fn contains(&self, product_id: u16) -> bool {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&product_id)
    }

    /// Replaces the trusted product list.
    pub fn replace(&self, product_ids: Vec<u16>) {
        *self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            deduplicate_product_ids(product_ids);
    }
}

/// Device presence abstraction used by the watchdog.
pub trait DeviceDetector {
    /// Returns whether the configured key is currently present.
    fn is_connected(&mut self) -> Result<bool, String>;
}

/// SetupAPI-backed detector for security-key hardware IDs.
#[derive(Clone, Debug)]
pub struct NativeYubiKeyDetector {
    vid_pattern: String,
    trusted_products: TrustedProducts,
}

impl NativeYubiKeyDetector {
    /// Creates a detector from typed application configuration.
    pub fn new(config: &AppConfig) -> Self {
        Self::new_with_store(config, TrustedProducts::new(config.product_ids.clone()))
    }

    /// Creates a detector with a shared trusted product store.
    pub fn new_with_store(config: &AppConfig, trusted_products: TrustedProducts) -> Self {
        Self {
            vid_pattern: format!("VID_{:04X}", config.vendor_id),
            trusted_products,
        }
    }

    /// Returns every matching present hardware ID.
    pub fn connected_devices(&self) -> Result<Vec<DeviceMatch>, String> {
        let hardware_ids = platform::present_hardware_ids()?;
        Ok(hardware_ids
            .into_iter()
            .filter(|hardware_id| self.matches(hardware_id))
            .map(|hardware_id| DeviceMatch {
                product_id: product_id_from_hardware_id(&hardware_id),
                hardware_id,
            })
            .collect())
    }

    /// Returns present Yubico devices even if their product IDs are untrusted.
    pub fn all_yubico_devices(&self) -> Result<Vec<YubicoDevice>, String> {
        let hardware_ids = platform::present_hardware_ids()?;
        Ok(hardware_ids
            .into_iter()
            .filter(|hardware_id| hardware_id.to_ascii_uppercase().contains(&self.vid_pattern))
            .filter_map(|hardware_id| {
                product_id_from_hardware_id(&hardware_id).map(|product_id| YubicoDevice {
                    hardware_id,
                    product_id,
                })
            })
            .collect())
    }

    /// Returns trusted product IDs in configured order.
    pub fn trusted_product_ids(&self) -> Vec<u16> {
        self.trusted_products.product_ids()
    }

    fn matches(&self, hardware_id: &str) -> bool {
        let normalized = hardware_id.to_ascii_uppercase();
        let product_ids = self.trusted_products.product_ids();
        normalized.contains(&self.vid_pattern)
            && (product_ids.is_empty()
                || product_id_from_hardware_id(&normalized)
                    .is_some_and(|product_id| product_ids.contains(&product_id)))
    }
}

impl DeviceDetector for NativeYubiKeyDetector {
    fn is_connected(&mut self) -> Result<bool, String> {
        Ok(!self.connected_devices()?.is_empty())
    }
}

/// Formats a product ID as dotenv-compatible hex.
pub fn product_id_label(product_id: u16) -> String {
    format!("0x{product_id:04X}")
}

fn product_id_from_hardware_id(hardware_id: &str) -> Option<u16> {
    let normalized = hardware_id.to_ascii_uppercase();
    let index = normalized.find("PID_")?;
    let hex = normalized.get(index + 4..index + 8)?;
    u16::from_str_radix(hex, 16).ok()
}

fn deduplicate_product_ids(product_ids: Vec<u16>) -> Vec<u16> {
    let mut deduplicated = Vec::new();
    for product_id in product_ids {
        if !deduplicated.contains(&product_id) {
            deduplicated.push(product_id);
        }
    }
    deduplicated
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::mem;
    use std::ptr::{null, null_mut};

    const DIGCF_PRESENT: u32 = 0x0000_0002;
    const DIGCF_ALLCLASSES: u32 = 0x0000_0004;
    const SPDRP_HARDWAREID: u32 = 0x0000_0001;
    const SPDRP_COMPATIBLEIDS: u32 = 0x0000_0002;
    const ERROR_NO_MORE_ITEMS: u32 = 259;

    type Bool = i32;
    type Dword = u32;
    type Hwnd = *mut c_void;
    type Hdevinfo = *mut c_void;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Debug)]
    struct SpDevinfoData {
        cb_size: Dword,
        class_guid: Guid,
        dev_inst: Dword,
        reserved: usize,
    }

    impl Default for SpDevinfoData {
        fn default() -> Self {
            Self {
                cb_size: mem::size_of::<Self>() as Dword,
                class_guid: Guid::default(),
                dev_inst: 0,
                reserved: 0,
            }
        }
    }

    #[link(name = "setupapi")]
    unsafe extern "system" {
        fn SetupDiGetClassDevsW(
            class_guid: *const Guid,
            enumerator: *const u16,
            hwnd_parent: Hwnd,
            flags: Dword,
        ) -> Hdevinfo;

        fn SetupDiEnumDeviceInfo(
            device_info_set: Hdevinfo,
            member_index: Dword,
            device_info_data: *mut SpDevinfoData,
        ) -> Bool;

        fn SetupDiGetDeviceRegistryPropertyW(
            device_info_set: Hdevinfo,
            device_info_data: *mut SpDevinfoData,
            property: Dword,
            property_reg_data_type: *mut Dword,
            property_buffer: *mut u8,
            property_buffer_size: Dword,
            required_size: *mut Dword,
        ) -> Bool;

        fn SetupDiDestroyDeviceInfoList(device_info_set: Hdevinfo) -> Bool;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLastError() -> Dword;
    }

    struct DeviceInfoSet(Hdevinfo);

    impl DeviceInfoSet {
        fn new() -> Result<Self, String> {
            let handle = unsafe {
                SetupDiGetClassDevsW(null(), null(), null_mut(), DIGCF_PRESENT | DIGCF_ALLCLASSES)
            };

            if is_invalid_handle(handle) {
                Err(format!(
                    "SetupDiGetClassDevsW failed with Windows error {}",
                    last_error()
                ))
            } else {
                Ok(Self(handle))
            }
        }
    }

    impl Drop for DeviceInfoSet {
        fn drop(&mut self) {
            if !is_invalid_handle(self.0) {
                unsafe {
                    SetupDiDestroyDeviceInfoList(self.0);
                }
            }
        }
    }

    pub(super) fn present_hardware_ids() -> Result<Vec<String>, String> {
        let info_set = DeviceInfoSet::new()?;
        let mut hardware_ids = Vec::new();
        let mut index = 0;

        loop {
            let mut device_info = SpDevinfoData::default();
            let ok = unsafe { SetupDiEnumDeviceInfo(info_set.0, index, &mut device_info) };

            if ok == 0 {
                let error = last_error();
                if error == ERROR_NO_MORE_ITEMS {
                    break;
                }
                return Err(format!(
                    "SetupDiEnumDeviceInfo failed with Windows error {error}"
                ));
            }

            for property in [SPDRP_HARDWAREID, SPDRP_COMPATIBLEIDS] {
                for hardware_id in registry_multi_sz(info_set.0, &mut device_info, property) {
                    if !hardware_ids.contains(&hardware_id) {
                        hardware_ids.push(hardware_id);
                    }
                }
            }

            index += 1;
        }

        Ok(hardware_ids)
    }

    fn registry_multi_sz(
        info_set: Hdevinfo,
        device_info: &mut SpDevinfoData,
        property: Dword,
    ) -> Vec<String> {
        let mut required_size = 0;
        unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                info_set,
                device_info,
                property,
                null_mut(),
                null_mut(),
                0,
                &mut required_size,
            );
        }

        if required_size == 0 {
            return Vec::new();
        }

        let mut buffer = vec![0_u8; required_size as usize];
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                info_set,
                device_info,
                property,
                null_mut(),
                buffer.as_mut_ptr(),
                buffer.len() as Dword,
                &mut required_size,
            )
        };

        if ok == 0 {
            return Vec::new();
        }

        multi_sz_from_bytes(&buffer[..required_size as usize])
    }

    fn multi_sz_from_bytes(bytes: &[u8]) -> Vec<String> {
        let wide: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let mut values = Vec::new();
        let mut start = 0;

        for (index, character) in wide.iter().enumerate() {
            if *character != 0 {
                continue;
            }

            if index == start {
                break;
            }

            values.push(String::from_utf16_lossy(&wide[start..index]));
            start = index + 1;
        }

        values
    }

    fn is_invalid_handle(handle: Hdevinfo) -> bool {
        handle as isize == -1
    }

    fn last_error() -> Dword {
        unsafe { GetLastError() }
    }

    #[cfg(test)]
    mod tests {
        use super::multi_sz_from_bytes;

        #[test]
        fn parses_multi_sz_values() {
            let input: Vec<u8> = "USB\\VID_1050&PID_0402\0HID\\VID_1050&PID_0402\0\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();

            assert_eq!(
                multi_sz_from_bytes(&input),
                vec!["USB\\VID_1050&PID_0402", "HID\\VID_1050&PID_0402"]
            );
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub(super) fn present_hardware_ids() -> Result<Vec<String>, String> {
        Err("native security-key detection is only implemented on Windows".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_original_product_id() {
        let config = AppConfig::default();
        let detector = NativeYubiKeyDetector::new(&config);

        assert!(detector.matches("USB\\VID_1050&PID_0402&REV_0527"));
        assert!(detector.matches("hid\\vid_1050&pid_0402"));
        assert!(!detector.matches("USB\\VID_1050&PID_0407"));
    }

    #[test]
    fn blank_product_ids_accept_all_yubico_devices() {
        let mut config = AppConfig::default();
        config.product_ids.clear();
        let detector = NativeYubiKeyDetector::new(&config);

        assert!(detector.matches("USB\\VID_1050&PID_0402"));
        assert!(detector.matches("USB\\VID_1050&PID_0407"));
        assert!(!detector.matches("USB\\VID_1234&PID_0402"));
    }

    #[test]
    fn extracts_product_ids_from_hardware_ids() {
        assert_eq!(
            product_id_from_hardware_id("USB\\VID_1050&PID_0402&REV_0574"),
            Some(0x0402)
        );
        assert_eq!(product_id_from_hardware_id("USB\\VID_1050"), None);
    }

    #[test]
    fn shared_trusted_products_update_detector_matches() {
        let config = AppConfig {
            product_ids: vec![0x0402],
            ..AppConfig::default()
        };
        let trusted = TrustedProducts::new(config.product_ids.clone());
        let detector = NativeYubiKeyDetector::new_with_store(&config, trusted.clone());

        assert!(!detector.matches("USB\\VID_1050&PID_0407"));
        trusted.replace(vec![0x0402, 0x0407]);
        assert!(detector.matches("USB\\VID_1050&PID_0407"));
    }
}
