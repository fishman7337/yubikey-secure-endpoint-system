//! Configuration loading for the native watchdog.
//!
//! Values are read from `.env` first and then overridden by process
//! environment variables. Native protection starts disabled unless
//! `YUBIWATCH_ALWAYS_KEEP_ENABLED=true`; runtime changes are controlled from
//! the localhost dashboard.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::audit::{DEFAULT_AUDIT_MAX_BYTES, default_audit_log_path};
use crate::mode::{module_definitions, module_env_key};

const DEFAULT_VENDOR_ID: u16 = 0x1050;
const DEFAULT_PRODUCT_ID: u16 = 0x0402;

/// Typed application settings loaded from `.env`.
///
/// Durations are clamped to conservative minimums so a typo cannot create a
/// busy loop. USB IDs are stored as numeric values but match Windows hardware
/// ID strings later in the detector.
#[derive(Clone, Debug, PartialEq)]
pub struct AppConfig {
    /// USB vendor ID to match. Yubico's vendor ID is `0x1050`.
    pub vendor_id: u16,
    /// USB product IDs to accept. An empty list accepts any Yubico product.
    pub product_ids: Vec<u16>,
    /// Poll interval while the configured key is present.
    pub present_poll: Duration,
    /// Poll interval during the missing-key grace window.
    pub missing_poll: Duration,
    /// Time to wait before locking after the key disappears.
    pub missing_grace: Duration,
    /// Poll interval after a lock while waiting for reinsertion.
    pub post_lock_poll: Duration,
    /// Minimum time between repeated locks while the key remains absent.
    pub relock: Duration,
    /// Startup delay before the lock policy is enforced.
    pub startup_grace: Duration,
    /// Treat USB detector errors as a missing key.
    pub fail_safe_lock: bool,
    /// Compatibility/debug setting for the Python fallback.
    pub lock_enabled: bool,
    /// Start native lock enforcement enabled on every launch.
    pub always_keep_enabled: bool,
    /// Serve the localhost dashboard from the native watchdog process.
    pub dashboard_enabled: bool,
    /// Localhost dashboard TCP port.
    pub dashboard_port: u16,
    /// Open the localhost dashboard in the default browser when the watchdog starts.
    pub open_dashboard_on_startup: bool,
    /// Local Security PIN verifier file.
    pub pin_file: PathBuf,
    /// Global Protected Mode startup state.
    pub secure_mode_enabled: bool,
    /// Per-module Protected Mode toggle overrides.
    pub module_overrides: HashMap<String, bool>,
    /// Structured audit log path.
    pub audit_log_file: PathBuf,
    /// Maximum current audit log size before rotation.
    pub audit_max_bytes: u64,
    /// Legacy time allowed to remove and reinsert the key during disable proof.
    pub disable_proof_timeout: Duration,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            vendor_id: DEFAULT_VENDOR_ID,
            product_ids: vec![DEFAULT_PRODUCT_ID],
            present_poll: Duration::from_secs_f64(2.0),
            missing_poll: Duration::from_secs_f64(0.5),
            missing_grace: Duration::from_secs_f64(2.0),
            post_lock_poll: Duration::from_secs_f64(2.0),
            relock: Duration::from_secs_f64(5.0),
            startup_grace: Duration::from_secs_f64(5.0),
            fail_safe_lock: true,
            lock_enabled: false,
            always_keep_enabled: false,
            dashboard_enabled: true,
            dashboard_port: 8765,
            open_dashboard_on_startup: false,
            pin_file: default_pin_path(),
            secure_mode_enabled: false,
            module_overrides: HashMap::new(),
            audit_log_file: default_audit_log_path(),
            audit_max_bytes: DEFAULT_AUDIT_MAX_BYTES,
            disable_proof_timeout: Duration::from_secs(45),
        }
    }
}

impl AppConfig {
    /// Loads settings from a `.env` file plus process environment overrides.
    pub fn from_env_file(path: &Path) -> Self {
        let values = read_env_file(path);
        Self::from_values(&values)
    }

    /// Builds settings from a pre-parsed key-value map.
    ///
    /// This is used by tests so config parsing can be checked without touching
    /// the real process environment.
    pub fn from_values(values: &HashMap<String, String>) -> Self {
        let default = Self::default();

        Self {
            vendor_id: get_hex_u16(values, "YUBIWATCH_VENDOR_ID", default.vendor_id),
            product_ids: get_product_ids(values),
            present_poll: get_seconds(
                values,
                "YUBIWATCH_PRESENT_POLL_SECONDS",
                default.present_poll,
                Duration::from_millis(200),
            ),
            missing_poll: get_seconds(
                values,
                "YUBIWATCH_MISSING_POLL_SECONDS",
                default.missing_poll,
                Duration::from_millis(200),
            ),
            missing_grace: get_seconds(
                values,
                "YUBIWATCH_MISSING_GRACE_SECONDS",
                default.missing_grace,
                Duration::ZERO,
            ),
            post_lock_poll: get_seconds(
                values,
                "YUBIWATCH_POST_LOCK_POLL_SECONDS",
                default.post_lock_poll,
                Duration::from_millis(500),
            ),
            relock: get_seconds(
                values,
                "YUBIWATCH_RELOCK_SECONDS",
                default.relock,
                Duration::from_secs(1),
            ),
            startup_grace: get_seconds(
                values,
                "YUBIWATCH_STARTUP_GRACE_SECONDS",
                default.startup_grace,
                Duration::ZERO,
            ),
            fail_safe_lock: get_bool(values, "YUBIWATCH_FAIL_SAFE_LOCK", default.fail_safe_lock),
            always_keep_enabled: get_bool(
                values,
                "YUBIWATCH_ALWAYS_KEEP_ENABLED",
                default.always_keep_enabled,
            ),
            lock_enabled: get_bool(
                values,
                "YUBIWATCH_LOCK_ENABLED",
                get_bool(
                    values,
                    "YUBIWATCH_ALWAYS_KEEP_ENABLED",
                    default.always_keep_enabled,
                ),
            ),
            dashboard_enabled: get_bool(
                values,
                "YUBIWATCH_DASHBOARD_ENABLED",
                default.dashboard_enabled,
            ),
            dashboard_port: get_u16(
                values,
                "YUBIWATCH_DASHBOARD_PORT",
                default.dashboard_port,
                1024,
            ),
            open_dashboard_on_startup: get_bool(
                values,
                "YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP",
                default.open_dashboard_on_startup,
            ),
            pin_file: get_path(values, "YUBIWATCH_PIN_FILE", default.pin_file),
            secure_mode_enabled: get_bool(
                values,
                "YUBIWATCH_SECURE_MODE_ENABLED",
                default.secure_mode_enabled,
            ),
            module_overrides: get_module_overrides(values),
            audit_log_file: get_path(values, "YUBIWATCH_AUDIT_LOG_FILE", default.audit_log_file),
            audit_max_bytes: get_u64(
                values,
                "YUBIWATCH_AUDIT_MAX_BYTES",
                default.audit_max_bytes,
                64 * 1024,
            ),
            disable_proof_timeout: get_seconds(
                values,
                "YUBIWATCH_DISABLE_PROOF_TIMEOUT_SECONDS",
                default.disable_proof_timeout,
                Duration::from_secs(10),
            ),
        }
    }
}

/// Returns the default `.env` path for the current working directory.
pub fn default_env_path() -> PathBuf {
    env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".env")
}

/// Returns the default Security PIN verifier path.
pub fn default_pin_path() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".local")
        })
        .join("YubiWatch")
        .join("pin.dat")
}

fn read_env_file(path: &Path) -> HashMap<String, String> {
    let mut values = HashMap::new();

    let Ok(contents) = fs::read_to_string(path) else {
        return values;
    };

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        let key = key.trim();
        if key.is_empty() {
            continue;
        }

        values.insert(key.to_string(), clean_env_value(value));
    }

    for (key, value) in env::vars() {
        if key.starts_with("YUBIWATCH_") {
            values.insert(key, value);
        }
    }

    values
}

fn clean_env_value(raw: &str) -> String {
    let mut value = raw.trim().to_string();
    let mut quote: Option<char> = None;
    let mut cut_at: Option<usize> = None;

    for (index, character) in value.char_indices() {
        if character == '\'' || character == '"' {
            quote = if quote == Some(character) {
                None
            } else {
                Some(character)
            };
            continue;
        }

        if character == '#'
            && quote.is_none()
            && (index == 0
                || value[..index]
                    .chars()
                    .last()
                    .is_some_and(char::is_whitespace))
        {
            cut_at = Some(index);
            break;
        }
    }

    if let Some(index) = cut_at {
        value.truncate(index);
        value = value.trim().to_string();
    }

    let chars: Vec<char> = value.chars().collect();
    if chars.len() >= 2
        && chars.first() == chars.last()
        && matches!(chars.first(), Some('\'' | '"'))
    {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        value
    }
}

fn get_bool(values: &HashMap<String, String>, key: &str, default: bool) -> bool {
    values
        .get(key)
        .map(|value| {
            matches!(
                value.to_lowercase().as_str(),
                "1" | "true" | "yes" | "y" | "on"
            )
        })
        .unwrap_or(default)
}

fn get_seconds(
    values: &HashMap<String, String>,
    key: &str,
    default: Duration,
    minimum: Duration,
) -> Duration {
    values
        .get(key)
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
        .map(|value| Duration::from_secs_f64(value.max(minimum.as_secs_f64())))
        .unwrap_or(default)
}

fn get_hex_u16(values: &HashMap<String, String>, key: &str, default: u16) -> u16 {
    values
        .get(key)
        .and_then(|value| parse_int(value))
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(default)
}

fn get_u16(values: &HashMap<String, String>, key: &str, default: u16, minimum: u16) -> u16 {
    values
        .get(key)
        .and_then(|value| parse_int(value))
        .and_then(|value| u16::try_from(value).ok())
        .map(|value| value.max(minimum))
        .unwrap_or(default)
}

fn get_u64(values: &HashMap<String, String>, key: &str, default: u64, minimum: u64) -> u64 {
    values
        .get(key)
        .and_then(|value| parse_int(value))
        .map(u64::from)
        .map(|value| value.max(minimum))
        .unwrap_or(default)
}

fn get_path(values: &HashMap<String, String>, key: &str, default: PathBuf) -> PathBuf {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .map(|value| PathBuf::from(value.trim()))
        .unwrap_or(default)
}

fn get_module_overrides(values: &HashMap<String, String>) -> HashMap<String, bool> {
    let mut overrides = HashMap::new();
    for definition in module_definitions() {
        let key = module_env_key(definition.id);
        if values.contains_key(&key) {
            overrides.insert(
                definition.id.to_string(),
                get_bool(values, &key, definition.default_enabled),
            );
        }
    }
    overrides
}

fn get_product_ids(values: &HashMap<String, String>) -> Vec<u16> {
    let Some(value) = values.get("YUBIWATCH_PRODUCT_IDS") else {
        return vec![DEFAULT_PRODUCT_ID];
    };

    if value.trim().is_empty() {
        return Vec::new();
    }

    let mut product_ids = Vec::new();
    for item in value.split([',', ';']) {
        let Some(parsed) = parse_int(item).and_then(|value| u16::try_from(value).ok()) else {
            continue;
        };
        if !product_ids.contains(&parsed) {
            product_ids.push(parsed);
        }
    }
    product_ids
}

fn parse_int(value: &str) -> Option<u32> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_original_key() {
        let config = AppConfig::from_values(&HashMap::new());
        assert_eq!(config.vendor_id, 0x1050);
        assert_eq!(config.product_ids, vec![0x0402]);
    }

    #[test]
    fn parses_and_deduplicates_product_ids() {
        let mut values = HashMap::new();
        values.insert(
            "YUBIWATCH_PRODUCT_IDS".to_string(),
            "0x0402, 0x0402, 1027, nope".to_string(),
        );

        let config = AppConfig::from_values(&values);
        assert_eq!(config.product_ids, vec![0x0402, 1027]);
    }

    #[test]
    fn blank_product_ids_accept_all_yubico_devices() {
        let mut values = HashMap::new();
        values.insert("YUBIWATCH_PRODUCT_IDS".to_string(), String::new());

        let config = AppConfig::from_values(&values);
        assert!(config.product_ids.is_empty());
    }

    #[test]
    fn seconds_respect_minimum_values() {
        let mut values = HashMap::new();
        values.insert(
            "YUBIWATCH_PRESENT_POLL_SECONDS".to_string(),
            "0.01".to_string(),
        );

        let config = AppConfig::from_values(&values);
        assert_eq!(config.present_poll, Duration::from_millis(200));
    }

    #[test]
    fn strips_inline_comments_outside_quotes() {
        assert_eq!(clean_env_value("0x0402 # original"), "0x0402");
        assert_eq!(
            clean_env_value("\"abc # still value\""),
            "abc # still value"
        );
    }

    #[test]
    fn parses_dashboard_browser_startup_setting() {
        let mut values = HashMap::new();
        values.insert(
            "YUBIWATCH_OPEN_DASHBOARD_ON_STARTUP".to_string(),
            "true".to_string(),
        );

        let config = AppConfig::from_values(&values);
        assert!(config.open_dashboard_on_startup);
    }

    #[test]
    fn starts_disabled_unless_always_keep_enabled_is_set() {
        let default_config = AppConfig::from_values(&HashMap::new());
        assert!(!default_config.always_keep_enabled);
        assert!(!default_config.lock_enabled);

        let mut values = HashMap::new();
        values.insert(
            "YUBIWATCH_ALWAYS_KEEP_ENABLED".to_string(),
            "true".to_string(),
        );

        let config = AppConfig::from_values(&values);
        assert!(config.always_keep_enabled);
        assert!(config.lock_enabled);
    }

    #[test]
    fn parses_secure_mode_and_module_settings() {
        let mut values = HashMap::new();
        values.insert(
            "YUBIWATCH_SECURE_MODE_ENABLED".to_string(),
            "true".to_string(),
        );
        values.insert(
            "YUBIWATCH_MODULE_DEVICE_CONTROL".to_string(),
            "true".to_string(),
        );
        values.insert(
            "YUBIWATCH_AUDIT_MAX_BYTES".to_string(),
            "131072".to_string(),
        );

        let config = AppConfig::from_values(&values);

        assert!(config.secure_mode_enabled);
        assert_eq!(config.module_overrides.get("device_control"), Some(&true));
        assert_eq!(config.audit_max_bytes, 131_072);
    }
}
