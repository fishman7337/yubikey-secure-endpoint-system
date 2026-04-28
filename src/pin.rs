//! Security PIN storage and verification.
//!
//! The dashboard PIN is stored as a salted PBKDF2-HMAC-SHA256 verifier. The
//! plaintext PIN is never written to disk. The in-memory gate also throttles
//! repeated failures so the localhost API is not a practical brute-force
//! surface.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HASH_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const ITERATIONS: u32 = 210_000;
const MAX_FAILURES: u32 = 5;
const LOCKOUT_SECONDS: u64 = 60;

/// Dashboard-visible PIN state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinSnapshot {
    /// Whether the Security PIN has been configured.
    pub is_set: bool,
    /// Remaining throttle seconds after repeated bad attempts.
    pub locked_seconds_remaining: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct AttemptState {
    failures: u32,
    locked_until: Option<Instant>,
}

/// Shared PIN gate used by dashboard request handlers.
#[derive(Clone, Debug)]
pub struct PinGate {
    store: PinStore,
    attempts: Arc<Mutex<AttemptState>>,
}

impl PinGate {
    /// Creates a PIN gate backed by `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            store: PinStore::new(path),
            attempts: Arc::new(Mutex::new(AttemptState::default())),
        }
    }

    /// Returns dashboard-safe PIN state.
    pub fn snapshot(&self) -> PinSnapshot {
        let mut attempts = self.lock_attempts();
        expire_attempt_lockout(&mut attempts, Instant::now());
        PinSnapshot {
            is_set: self.store.exists(),
            locked_seconds_remaining: attempts
                .locked_until
                .map(|deadline| deadline.saturating_duration_since(Instant::now()).as_secs()),
        }
    }

    /// Sets the PIN once. Existing PIN files are never overwritten.
    pub fn setup(&self, pin: &str, confirm_pin: &str) -> Result<(), String> {
        self.store.setup(pin, confirm_pin)
    }

    /// Verifies the PIN and applies rate limiting for failures.
    pub fn verify(&self, pin: &str) -> Result<(), String> {
        let now = Instant::now();
        {
            let mut attempts = self.lock_attempts();
            expire_attempt_lockout(&mut attempts, now);
            if let Some(deadline) = attempts.locked_until {
                return Err(format!(
                    "Too many incorrect PIN attempts. Try again in {} seconds.",
                    deadline.saturating_duration_since(now).as_secs().max(1)
                ));
            }
        }

        match self.store.verify(pin) {
            Ok(true) => {
                *self.lock_attempts() = AttemptState::default();
                Ok(())
            }
            Ok(false) => {
                let mut attempts = self.lock_attempts();
                attempts.failures = attempts.failures.saturating_add(1);
                if attempts.failures >= MAX_FAILURES {
                    attempts.locked_until = Some(now + Duration::from_secs(LOCKOUT_SECONDS));
                }
                Err("Incorrect Security PIN.".to_string())
            }
            Err(error) => Err(error),
        }
    }

    /// Clears the configured PIN after a lock-first recovery flow.
    pub fn clear_after_lock(&self) -> Result<(), String> {
        self.store.clear()?;
        *self.lock_attempts() = AttemptState::default();
        Ok(())
    }

    fn lock_attempts(&self) -> std::sync::MutexGuard<'_, AttemptState> {
        self.attempts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn expire_attempt_lockout(attempts: &mut AttemptState, now: Instant) {
    if attempts
        .locked_until
        .is_some_and(|deadline| now >= deadline)
    {
        *attempts = AttemptState::default();
    }
}

#[derive(Clone, Debug)]
struct PinStore {
    path: PathBuf,
}

impl PinStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }

    fn setup(&self, pin: &str, confirm_pin: &str) -> Result<(), String> {
        validate_pin_pair(pin, confirm_pin)?;

        if self.exists() {
            return Err("Security PIN is already set.".to_string());
        }

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create PIN directory {}: {error}",
                    parent.display()
                )
            })?;
        }

        let mut salt = [0_u8; SALT_BYTES];
        fill_random(&mut salt);
        let hash = derive_pin_hash(pin, &salt, ITERATIONS)?;
        let encoded = format!(
            "version=1\niterations={ITERATIONS}\nsalt={}\nhash={}\n",
            hex_encode(&salt),
            hex_encode(&hash)
        );

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    "Security PIN is already set.".to_string()
                } else {
                    format!("failed to create PIN file {}: {error}", self.path.display())
                }
            })?;
        file.write_all(encoded.as_bytes())
            .map_err(|error| format!("failed to write PIN file {}: {error}", self.path.display()))
    }

    fn verify(&self, pin: &str) -> Result<bool, String> {
        if !self.exists() {
            return Err("Create a Security PIN before changing protection.".to_string());
        }

        if !is_valid_pin(pin) {
            return Ok(false);
        }

        let credential = Credential::read(&self.path)?;
        let candidate = derive_pin_hash(pin, &credential.salt, credential.iterations)?;
        Ok(constant_time_eq(&candidate, &credential.hash))
    }

    fn clear(&self) -> Result<(), String> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "failed to remove PIN file {}: {error}",
                self.path.display()
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Credential {
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

impl Credential {
    fn read(path: &Path) -> Result<Self, String> {
        let contents = fs::read_to_string(path)
            .map_err(|error| format!("failed to read PIN file {}: {error}", path.display()))?;
        let mut version = None;
        let mut iterations = None;
        let mut salt = None;
        let mut hash = None;

        for line in contents.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "version" => version = Some(value.trim().to_string()),
                "iterations" => iterations = value.trim().parse::<u32>().ok(),
                "salt" => salt = hex_decode(value.trim()),
                "hash" => hash = hex_decode(value.trim()),
                _ => {}
            }
        }

        if version.as_deref() != Some("1") {
            return Err("Unsupported Security PIN file version.".to_string());
        }

        let credential = Self {
            iterations: iterations.ok_or_else(|| "PIN file is missing iterations.".to_string())?,
            salt: salt.ok_or_else(|| "PIN file is missing salt.".to_string())?,
            hash: hash.ok_or_else(|| "PIN file is missing hash.".to_string())?,
        };

        if credential.salt.len() != SALT_BYTES || credential.hash.len() != HASH_BYTES {
            return Err("PIN file is malformed.".to_string());
        }

        Ok(credential)
    }
}

fn validate_pin_pair(pin: &str, confirm_pin: &str) -> Result<(), String> {
    if pin != confirm_pin {
        return Err("PIN entries do not match.".to_string());
    }
    if !is_valid_pin(pin) {
        return Err("PIN must be 6 to 12 digits.".to_string());
    }
    Ok(())
}

fn is_valid_pin(pin: &str) -> bool {
    (6..=12).contains(&pin.len()) && pin.bytes().all(|byte| byte.is_ascii_digit())
}

fn derive_pin_hash(pin: &str, salt: &[u8], iterations: u32) -> Result<Vec<u8>, String> {
    crypto::pbkdf2_hmac_sha256(pin.as_bytes(), salt, iterations, HASH_BYTES)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right) {
        diff |= left ^ right;
    }
    diff == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&value[index..index + 2], 16).ok()?);
    }
    Some(bytes)
}

fn fill_random(bytes: &mut [u8]) {
    crypto::fill_random(bytes);
}

#[cfg(windows)]
mod crypto {
    use std::ffi::c_void;
    use std::ptr;

    const BCRYPT_ALG_HANDLE_HMAC_FLAG: u32 = 0x0000_0008;
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptOpenAlgorithmProvider(
            algorithm: *mut *mut c_void,
            psz_alg_id: *const u16,
            psz_implementation: *const u16,
            flags: u32,
        ) -> i32;

        fn BCryptCloseAlgorithmProvider(algorithm: *mut c_void, flags: u32) -> i32;

        fn BCryptDeriveKeyPBKDF2(
            algorithm: *mut c_void,
            password: *const u8,
            password_size: u32,
            salt: *const u8,
            salt_size: u32,
            iterations: u64,
            derived_key: *mut u8,
            derived_key_size: u32,
            flags: u32,
        ) -> i32;

        fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, count: u32, flags: u32) -> i32;
    }

    pub(super) fn fill_random(bytes: &mut [u8]) {
        let status = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };

        if status != 0 {
            fallback_fill_random(bytes);
        }
    }

    pub(super) fn pbkdf2_hmac_sha256(
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output_len: usize,
    ) -> Result<Vec<u8>, String> {
        let mut algorithm = ptr::null_mut();
        let algorithm_name = wide_null("SHA256");
        let open_status = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut algorithm,
                algorithm_name.as_ptr(),
                ptr::null(),
                BCRYPT_ALG_HANDLE_HMAC_FLAG,
            )
        };
        if open_status != 0 {
            return Err(format!(
                "BCryptOpenAlgorithmProvider failed with status {open_status:#x}"
            ));
        }

        let mut output = vec![0_u8; output_len];
        let derive_status = unsafe {
            BCryptDeriveKeyPBKDF2(
                algorithm,
                password.as_ptr(),
                password.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                u64::from(iterations),
                output.as_mut_ptr(),
                output.len() as u32,
                0,
            )
        };
        unsafe {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }

        if derive_status != 0 {
            Err(format!(
                "BCryptDeriveKeyPBKDF2 failed with status {derive_status:#x}"
            ))
        } else {
            Ok(output)
        }
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn fallback_fill_random(bytes: &mut [u8]) {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0)
            ^ u64::from(std::process::id());
        let mut value = seed;
        for byte in bytes {
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            *byte = value as u8;
        }
    }
}

#[cfg(not(windows))]
mod crypto {
    pub(super) fn fill_random(bytes: &mut [u8]) {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
    }

    pub(super) fn pbkdf2_hmac_sha256(
        _password: &[u8],
        _salt: &[u8],
        _iterations: u32,
        _output_len: usize,
    ) -> Result<Vec<u8>, String> {
        Err("PIN hashing requires Windows CNG".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_pin_shapes() {
        assert!(!is_valid_pin("12345"));
        assert!(!is_valid_pin("1234567890123"));
        assert!(!is_valid_pin("12345a"));
        assert!(is_valid_pin("123456"));
    }

    #[test]
    fn setup_verify_and_clear_pin() {
        let path = std::env::temp_dir().join(format!("yubiwatch-pin-{}.dat", std::process::id()));
        let _ = fs::remove_file(&path);
        let gate = PinGate::new(path.clone());

        gate.setup("123456", "123456").unwrap();
        assert!(gate.snapshot().is_set);
        assert!(gate.setup("654321", "654321").is_err());
        assert!(gate.verify("123456").is_ok());
        assert!(gate.verify("654321").is_err());

        gate.clear_after_lock().unwrap();
        assert!(!gate.snapshot().is_set);
        let _ = fs::remove_file(path);
    }
}
