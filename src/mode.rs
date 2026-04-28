//! Modular Protected Mode controller.
//!
//! This module keeps Protected Mode state separate from the security-key watchdog. It
//! models every hardening module as independently toggleable and reversible.
//! Modules that need administrator-backed Windows policy are represented as
//! preview placeholders until a service backend is added.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const IDENTITY_ACCESS: &str = "identity_access";
const SESSION_PROTECTION: &str = "session_protection";
const AUDIT_LOGGING: &str = "audit_logging";
const COMPLIANCE_MONITORING: &str = "compliance_monitoring";

/// Static product definition for a security module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModuleDefinition {
    /// Stable machine-readable module ID.
    pub id: &'static str,
    /// Dashboard grouping.
    pub category: &'static str,
    /// User-facing module name.
    pub name: &'static str,
    /// Short behavior summary.
    pub summary: &'static str,
    /// Current enforcement capability.
    pub capability: &'static str,
    /// Whether the module starts enabled unless overridden.
    pub default_enabled: bool,
    /// Whether this module has active enforcement in the current user-mode build.
    pub implemented: bool,
}

/// Dashboard-safe state for one module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSnapshot {
    /// Static module definition.
    pub definition: ModuleDefinition,
    /// Whether the module toggle is enabled.
    pub enabled: bool,
    /// Whether the module is active under current Protected Mode conditions.
    pub active: bool,
    /// Status label.
    pub status: String,
    /// Residual risk note.
    pub risk: String,
}

/// Dashboard-safe state for the whole Protected Mode framework.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureModeSnapshot {
    /// Global Protected Mode state.
    pub enabled: bool,
    /// Compliance score from 0 to 100.
    pub score: u8,
    /// User-facing posture label.
    pub posture: String,
    /// Enabled/active state for each module.
    pub modules: Vec<ModuleSnapshot>,
    /// Dashboard-visible risks and gaps.
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
struct SecureModeState {
    enabled: bool,
    module_enabled: HashMap<String, bool>,
}

/// Shared Protected Mode state used by dashboard handlers.
#[derive(Clone, Debug)]
pub struct SecureModeController {
    inner: Arc<Mutex<SecureModeState>>,
}

impl SecureModeController {
    /// Creates a controller from persisted configuration.
    pub fn new(enabled: bool, overrides: &HashMap<String, bool>) -> Self {
        let mut module_enabled = HashMap::new();
        for definition in module_definitions() {
            module_enabled.insert(
                definition.id.to_string(),
                overrides
                    .get(definition.id)
                    .copied()
                    .unwrap_or(definition.default_enabled),
            );
        }

        Self {
            inner: Arc::new(Mutex::new(SecureModeState {
                enabled,
                module_enabled,
            })),
        }
    }

    /// Returns true if `id` is a known security module.
    pub fn module_exists(&self, id: &str) -> bool {
        module_definitions()
            .iter()
            .any(|definition| definition.id == id)
    }

    /// Returns whether a module is enabled.
    pub fn module_enabled(&self, id: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .module_enabled
            .get(id)
            .copied()
            .unwrap_or_else(|| module_default_enabled(id).unwrap_or(false))
    }

    /// Sets global Protected Mode.
    pub fn set_secure_mode(&self, enabled: bool) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .enabled = enabled;
    }

    /// Sets an individual module toggle.
    pub fn set_module_enabled(&self, id: &str, enabled: bool) -> Result<(), String> {
        if !self.module_exists(id) {
            return Err(format!("Unknown security module: {id}"));
        }

        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .module_enabled
            .insert(id.to_string(), enabled);
        Ok(())
    }

    /// Returns dashboard-safe Protected Mode state.
    pub fn snapshot(&self, guard_armed: bool, pin_set: bool) -> SecureModeSnapshot {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let modules = module_definitions()
            .iter()
            .map(|definition| module_snapshot(*definition, &state, guard_armed, pin_set))
            .collect::<Vec<_>>();

        let score = compliance_score(state.enabled, guard_armed, pin_set, &modules);
        let posture = if score >= 85 {
            "Protected"
        } else if score >= 65 {
            "Mostly Protected"
        } else if score >= 40 {
            "Needs Attention"
        } else {
            "Needs Setup"
        }
        .to_string();

        SecureModeSnapshot {
            enabled: state.enabled,
            score,
            posture,
            warnings: compliance_warnings(state.enabled, guard_armed, pin_set, &modules),
            modules,
        }
    }
}

/// Returns all supported module definitions.
pub fn module_definitions() -> &'static [ModuleDefinition] {
    &[
        ModuleDefinition {
            id: IDENTITY_ACCESS,
            category: "Sign-In & Access",
            name: "Security Key Check",
            summary: "Uses your security key and PIN before important settings can change.",
            capability: "active",
            default_enabled: true,
            implemented: true,
        },
        ModuleDefinition {
            id: "device_control",
            category: "Devices",
            name: "USB Device Check",
            summary: "Shows connected security-key devices and prepares USB allow-list controls.",
            capability: "preview",
            default_enabled: false,
            implemented: false,
        },
        ModuleDefinition {
            id: "network_security",
            category: "Network",
            name: "Network Protection",
            summary: "Prepares safer network rules for a future service-backed version.",
            capability: "planned",
            default_enabled: false,
            implemented: false,
        },
        ModuleDefinition {
            id: "application_control",
            category: "Apps",
            name: "Approved Apps",
            summary: "Prepares a list of allowed apps for a future service-backed version.",
            capability: "planned",
            default_enabled: false,
            implemented: false,
        },
        ModuleDefinition {
            id: "data_protection",
            category: "Files",
            name: "File Protection",
            summary: "Prepares controls for sensitive files and unsafe copy locations.",
            capability: "planned",
            default_enabled: false,
            implemented: false,
        },
        ModuleDefinition {
            id: "clipboard_transfer",
            category: "Copy & Paste",
            name: "Copy/Paste Protection",
            summary: "Prepares safer copy, paste, and transfer controls for future enforcement.",
            capability: "planned",
            default_enabled: false,
            implemented: false,
        },
        ModuleDefinition {
            id: SESSION_PROTECTION,
            category: "Laptop Session",
            name: "Auto Lock",
            summary: "Locks the laptop when your security key is removed and protection is on.",
            capability: "active",
            default_enabled: true,
            implemented: true,
        },
        ModuleDefinition {
            id: "tamper_detection",
            category: "Safety Checks",
            name: "Change Alerts",
            summary: "Records important setting changes and prepares deeper tamper alerts.",
            capability: "preview",
            default_enabled: false,
            implemented: false,
        },
        ModuleDefinition {
            id: AUDIT_LOGGING,
            category: "Activity",
            name: "Activity History",
            summary: "Keeps a local history of important dashboard actions.",
            capability: "active",
            default_enabled: true,
            implemented: true,
        },
        ModuleDefinition {
            id: COMPLIANCE_MONITORING,
            category: "Health",
            name: "Protection Health",
            summary: "Checks which protections are on and what still needs attention.",
            capability: "active",
            default_enabled: true,
            implemented: true,
        },
    ]
}

/// Returns the `.env` key for a module toggle.
pub fn module_env_key(id: &str) -> String {
    format!("YUBIWATCH_MODULE_{}", id.to_ascii_uppercase())
}

/// Returns the default enabled state for a module.
pub fn module_default_enabled(id: &str) -> Option<bool> {
    module_definitions()
        .iter()
        .find(|definition| definition.id == id)
        .map(|definition| definition.default_enabled)
}

/// Returns whether a module has active enforcement in this build.
pub fn module_implemented(id: &str) -> bool {
    module_definitions()
        .iter()
        .find(|definition| definition.id == id)
        .map(|definition| definition.implemented)
        .unwrap_or(false)
}

/// Serializes a Protected Mode snapshot to JSON.
pub fn secure_mode_snapshot_json(snapshot: &SecureModeSnapshot) -> String {
    format!(
        "{{\"enabled\":{},\"score\":{},\"posture\":\"{}\",\"warnings\":[{}],\"modules\":[{}]}}",
        snapshot.enabled,
        snapshot.score,
        escape_json(&snapshot.posture),
        quoted_list_json(&snapshot.warnings),
        snapshot
            .modules
            .iter()
            .map(module_snapshot_json)
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn module_snapshot(
    definition: ModuleDefinition,
    state: &SecureModeState,
    guard_armed: bool,
    pin_set: bool,
) -> ModuleSnapshot {
    let enabled = state
        .module_enabled
        .get(definition.id)
        .copied()
        .unwrap_or(definition.default_enabled);
    let active =
        state.enabled && enabled && (definition.implemented || definition.id == AUDIT_LOGGING);
    let (status, risk) = module_status(definition, state.enabled, enabled, guard_armed, pin_set);

    ModuleSnapshot {
        definition,
        enabled,
        active,
        status,
        risk,
    }
}

fn module_status(
    definition: ModuleDefinition,
    secure_mode_enabled: bool,
    enabled: bool,
    guard_armed: bool,
    pin_set: bool,
) -> (String, String) {
    if !enabled {
        return (
            "Off".to_string(),
            "This protection is turned off.".to_string(),
        );
    }
    if !secure_mode_enabled {
        return (
            "Ready".to_string(),
            "Protected Mode is off, so this is waiting.".to_string(),
        );
    }

    match definition.id {
        IDENTITY_ACCESS => {
            if !pin_set {
                (
                    "Needs PIN".to_string(),
                    "Create your Security PIN before using protected settings.".to_string(),
                )
            } else if guard_armed {
                (
                    "On".to_string(),
                    "Removing your security key locks the laptop.".to_string(),
                )
            } else {
                (
                    "Ready".to_string(),
                    "Protected Mode is on. Turn on laptop auto-lock to finish setup.".to_string(),
                )
            }
        }
        SESSION_PROTECTION => {
            if guard_armed {
                (
                    "On".to_string(),
                    "The laptop will lock when your security key is removed.".to_string(),
                )
            } else {
                (
                    "Ready".to_string(),
                    "Turn on laptop auto-lock to protect this session.".to_string(),
                )
            }
        }
        AUDIT_LOGGING => (
            "On".to_string(),
            "Important dashboard actions are saved locally.".to_string(),
        ),
        COMPLIANCE_MONITORING => (
            "Checking".to_string(),
            "The dashboard shows protection score and items needing attention.".to_string(),
        ),
        _ if definition.implemented => (
            "On".to_string(),
            "This protection is working now.".to_string(),
        ),
        _ => (
            "Preview".to_string(),
            "This option is visible now, but deeper blocking needs a future service update."
                .to_string(),
        ),
    }
}

fn compliance_score(
    secure_mode_enabled: bool,
    guard_armed: bool,
    pin_set: bool,
    modules: &[ModuleSnapshot],
) -> u8 {
    let mut score = 0_u16;
    if secure_mode_enabled {
        score += 20;
    }
    if pin_set {
        score += 15;
    }
    if guard_armed {
        score += 20;
    }
    for module in modules {
        if module.enabled {
            score += if module.definition.implemented { 7 } else { 3 };
        }
    }
    score.min(100) as u8
}

fn compliance_warnings(
    secure_mode_enabled: bool,
    guard_armed: bool,
    pin_set: bool,
    modules: &[ModuleSnapshot],
) -> Vec<String> {
    let mut warnings = Vec::new();
    if !secure_mode_enabled {
        warnings.push("Protected Mode is off.".to_string());
    }
    if !pin_set {
        warnings.push("Security PIN has not been created yet.".to_string());
    }
    if !guard_armed {
        warnings.push("Laptop auto-lock is turned off.".to_string());
    }
    if modules
        .iter()
        .any(|module| module.enabled && !module.definition.implemented)
    {
        warnings.push(
            "Some selected protections are previews and need a future service update.".to_string(),
        );
    }
    if modules
        .iter()
        .any(|module| module.definition.id == AUDIT_LOGGING && !module.enabled)
    {
        warnings.push("Recent Activity history is turned off.".to_string());
    }
    warnings
}

fn module_snapshot_json(module: &ModuleSnapshot) -> String {
    format!(
        "{{\"id\":\"{}\",\"category\":\"{}\",\"name\":\"{}\",\"summary\":\"{}\",\"capability\":\"{}\",\"implemented\":{},\"enabled\":{},\"active\":{},\"status\":\"{}\",\"risk\":\"{}\"}}",
        escape_json(module.definition.id),
        escape_json(module.definition.category),
        escape_json(module.definition.name),
        escape_json(module.definition.summary),
        escape_json(module.definition.capability),
        module.definition.implemented,
        module.enabled,
        module.active,
        escape_json(&module.status),
        escape_json(&module.risk)
    )
}

fn quoted_list_json(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect::<Vec<_>>()
        .join(",")
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
    fn controller_exposes_default_modules() {
        let controller = SecureModeController::new(false, &HashMap::new());
        let snapshot = controller.snapshot(false, false);

        assert!(!snapshot.enabled);
        assert!(
            snapshot
                .modules
                .iter()
                .any(|module| module.definition.id == IDENTITY_ACCESS)
        );
        assert!(snapshot.score < 60);
    }

    #[test]
    fn toggles_module_state() {
        let controller = SecureModeController::new(true, &HashMap::new());

        controller
            .set_module_enabled("device_control", true)
            .unwrap();
        let snapshot = controller.snapshot(true, true);

        assert!(
            snapshot
                .modules
                .iter()
                .any(|module| module.definition.id == "device_control" && module.enabled)
        );
    }

    #[test]
    fn serializes_secure_mode_json() {
        let controller = SecureModeController::new(true, &HashMap::new());
        let json = secure_mode_snapshot_json(&controller.snapshot(true, true));

        assert!(json.contains("\"posture\""));
        assert!(json.contains("Security Key Check"));
    }
}
