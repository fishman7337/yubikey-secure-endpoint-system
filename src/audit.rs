//! Structured local audit logging.
//!
//! Audit entries are JSON Lines records kept on the local machine. The log is
//! intentionally small and reviewable from the dashboard; it is not a remote
//! SIEM or tamper-proof evidence store.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default maximum size of the current audit log before rotation.
pub const DEFAULT_AUDIT_MAX_BYTES: u64 = 1_048_576;

/// Local append-only audit log with simple rotation.
#[derive(Clone, Debug)]
pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
}

impl AuditLog {
    /// Creates an audit log writer.
    pub fn new(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            path,
            max_bytes: max_bytes.max(64 * 1024),
        }
    }

    /// Records one structured event.
    pub fn record(&self, category: &str, action: &str, outcome: &str, details: &str) {
        if let Err(error) = self.try_record(category, action, outcome, details) {
            eprintln!("audit log write failed: {error}");
        }
    }

    /// Returns recent raw JSON audit entries for dashboard embedding.
    pub fn recent_json_entries(&self, limit: usize) -> Vec<String> {
        let Ok(contents) = fs::read_to_string(&self.path) else {
            return Vec::new();
        };

        let mut lines = contents
            .lines()
            .filter(|line| line.trim_start().starts_with('{'))
            .map(str::to_string)
            .collect::<Vec<_>>();
        let keep_from = lines.len().saturating_sub(limit);
        lines.drain(0..keep_from);
        lines
    }

    fn try_record(
        &self,
        category: &str,
        action: &str,
        outcome: &str,
        details: &str,
    ) -> Result<(), String> {
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create audit directory {}: {error}",
                    parent.display()
                )
            })?;
        }

        self.rotate_if_needed();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| {
                format!("failed to open audit log {}: {error}", self.path.display())
            })?;
        writeln!(
            file,
            "{{\"timestamp\":{},\"category\":\"{}\",\"action\":\"{}\",\"outcome\":\"{}\",\"details\":\"{}\"}}",
            unix_seconds(),
            escape_json(category),
            escape_json(action),
            escape_json(outcome),
            escape_json(details)
        )
        .map_err(|error| format!("failed to write audit log {}: {error}", self.path.display()))
    }

    fn rotate_if_needed(&self) {
        let Ok(metadata) = fs::metadata(&self.path) else {
            return;
        };
        if metadata.len() <= self.max_bytes {
            return;
        }

        let backup = self.path.with_extension("jsonl.1");
        let _ = fs::remove_file(&backup);
        let _ = fs::rename(&self.path, backup);
    }
}

/// Returns the default local audit log path.
pub fn default_audit_log_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".local")
        })
        .join("YubiWatch")
        .join("audit.jsonl")
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_recent_entries() {
        let path =
            std::env::temp_dir().join(format!("yubiwatch-audit-{}.jsonl", std::process::id()));
        let _ = fs::remove_file(&path);
        let log = AuditLog::new(path.clone(), DEFAULT_AUDIT_MAX_BYTES);

        log.record("policy", "toggle", "allowed", "identity_access enabled");
        let entries = log.recent_json_entries(5);

        assert_eq!(entries.len(), 1);
        assert!(entries[0].contains("\"category\":\"policy\""));
        let _ = fs::remove_file(path);
    }
}
