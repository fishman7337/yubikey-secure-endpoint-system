//! Shared user-facing runtime diagnostics.
//!
//! Diagnostics are intentionally small and local. They help the dashboard and
//! CLI explain a broken feature with the next useful repair steps.

use std::sync::{Arc, Mutex};

/// One dashboard-safe diagnostic entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    /// Stable subsystem name, for example `scanner` or `lock`.
    pub category: String,
    /// Short user-facing failure summary.
    pub summary: String,
    /// Technical cause or local error text.
    pub cause: String,
    /// Concrete steps the user can take.
    pub fix_steps: Vec<String>,
}

impl Diagnostic {
    /// Creates a diagnostic from displayable values.
    pub fn new(
        category: impl Into<String>,
        summary: impl Into<String>,
        cause: impl Into<String>,
        fix_steps: Vec<String>,
    ) -> Self {
        Self {
            category: category.into(),
            summary: summary.into(),
            cause: cause.into(),
            fix_steps,
        }
    }
}

/// Shared diagnostic store.
#[derive(Clone, Debug, Default)]
pub struct RuntimeDiagnostics {
    inner: Arc<Mutex<Vec<Diagnostic>>>,
}

impl RuntimeDiagnostics {
    /// Creates an empty diagnostic store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the current diagnostic for one category.
    pub fn record(&self, diagnostic: Diagnostic) {
        let mut diagnostics = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        diagnostics.retain(|item| item.category != diagnostic.category);
        diagnostics.push(diagnostic);
    }

    /// Clears a subsystem diagnostic after it recovers.
    pub fn clear_category(&self, category: &str) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|item| item.category != category);
    }

    /// Returns a snapshot of current diagnostics.
    pub fn entries(&self) -> Vec<Diagnostic> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

/// Standard repair steps for security-key scanner failures.
pub fn scanner_fix_steps() -> Vec<String> {
    vec![
        "Insert the configured security key.".to_string(),
        "Verify YUBIWATCH_VENDOR_ID and YUBIWATCH_PRODUCT_IDS in .env.".to_string(),
        "Confirm the key appears in Windows Device Manager.".to_string(),
        "Run yubiwatch.exe --env-file .\\.env --foreground --dry-run for details.".to_string(),
    ]
}

/// Standard repair steps for lock failures.
pub fn lock_fix_steps() -> Vec<String> {
    vec![
        "Sign in locally and try locking Windows with Win+L.".to_string(),
        "Run YubiWatch with --foreground --dry-run before re-enabling live locks.".to_string(),
        "If Windows keeps rejecting LockWorkStation, restart Windows and try again.".to_string(),
    ]
}
