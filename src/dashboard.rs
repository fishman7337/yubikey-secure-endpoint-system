//! Localhost dashboard for runtime protection control.
//!
//! The dashboard is intentionally tiny: it binds only to `127.0.0.1`, uses a
//! per-process CSRF token, and only allows enabling after the configured key is
//! detected. It is a control surface for the running watchdog, not a remote
//! administration API.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use std::{fs, path::Path};

use crate::audit::AuditLog;
use crate::config::AppConfig;
use crate::detector::{NativeYubiKeyDetector, TrustedProducts, YubicoDevice, product_id_label};
use crate::diagnostics::{Diagnostic, RuntimeDiagnostics, lock_fix_steps, scanner_fix_steps};
use crate::locker::{Locker, WorkstationLocker};
use crate::mode::{
    SecureModeController, SecureModeSnapshot, module_definitions, module_env_key,
    module_implemented, secure_mode_snapshot_json,
};
use crate::pin::PinGate;
use crate::security::{GuardSnapshot, ProofStage, SecurityGate};

const MAX_REQUEST_BYTES: usize = 8192;
const PIN_AUTHORIZATION_SECONDS: u64 = 60;
const PIN_FAILURES_BEFORE_LOCK: u32 = 3;

#[derive(Clone, Debug)]
struct DashboardContext {
    config: AppConfig,
    env_file: PathBuf,
    gate: SecurityGate,
    trusted_products: TrustedProducts,
    pin_gate: PinGate,
    pin_authorization: PinAuthorization,
    mode_controller: SecureModeController,
    audit_log: AuditLog,
    diagnostics: RuntimeDiagnostics,
    lock_actions_enabled: bool,
}

#[derive(Clone, Debug)]
struct PinAuthorization {
    inner: Arc<Mutex<PinAuthorizationState>>,
}

#[derive(Clone, Debug, Default)]
struct PinAuthorizationState {
    token: Option<String>,
    expires_at: Option<Instant>,
    failures: u32,
}

impl PinAuthorization {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PinAuthorizationState::default())),
        }
    }

    fn issue(&self) -> String {
        let token = secure_token();
        let mut state = self.lock_state();
        state.token = Some(token.clone());
        state.expires_at = Some(Instant::now() + Duration::from_secs(PIN_AUTHORIZATION_SECONDS));
        state.failures = 0;
        token
    }

    fn verify(&self, token: &str) -> bool {
        let mut state = self.lock_state();
        expire_authorization_if_needed(&mut state, Instant::now());
        !token.is_empty() && state.token.as_deref() == Some(token)
    }

    fn clear(&self) {
        let mut state = self.lock_state();
        state.token = None;
        state.expires_at = None;
    }

    fn record_failure(&self) -> bool {
        let mut state = self.lock_state();
        state.token = None;
        state.expires_at = None;
        state.failures = state.failures.saturating_add(1);
        if state.failures >= PIN_FAILURES_BEFORE_LOCK {
            state.failures = 0;
            true
        } else {
            false
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, PinAuthorizationState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn expire_authorization_if_needed(state: &mut PinAuthorizationState, now: Instant) {
    if state.expires_at.is_some_and(|deadline| now >= deadline) {
        state.token = None;
        state.expires_at = None;
    }
}

/// Starts the dashboard on `127.0.0.1:<port>` in a background thread.
pub fn spawn_dashboard(
    config: AppConfig,
    env_file: PathBuf,
    gate: SecurityGate,
    trusted_products: TrustedProducts,
    diagnostics: RuntimeDiagnostics,
    lock_actions_enabled: bool,
) -> Result<thread::JoinHandle<()>, String> {
    let address = format!("127.0.0.1:{}", config.dashboard_port);
    let listener = TcpListener::bind(&address)
        .map_err(|error| format!("failed to bind dashboard at http://{address}: {error}"))?;
    let csrf_token = secure_token();
    let pin_gate = PinGate::new(config.pin_file.clone());
    let pin_authorization = PinAuthorization::new();
    let mode_controller =
        SecureModeController::new(config.secure_mode_enabled, &config.module_overrides);
    let audit_log = AuditLog::new(config.audit_log_file.clone(), config.audit_max_bytes);
    let context = DashboardContext {
        config,
        env_file,
        gate,
        trusted_products,
        pin_gate,
        pin_authorization,
        mode_controller,
        audit_log,
        diagnostics,
        lock_actions_enabled,
    };
    record_audit(
        &context,
        "system",
        "dashboard_started",
        "allowed",
        "Dashboard opened locally",
    );

    Ok(thread::spawn(move || {
        println!("YubiWatch dashboard: http://{address}/");
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let context = context.clone();
                    let csrf_token = csrf_token.clone();
                    thread::spawn(move || {
                        if let Err(error) = handle_connection(stream, context, csrf_token) {
                            eprintln!("dashboard request failed: {error}");
                        }
                    });
                }
                Err(error) => eprintln!("dashboard connection failed: {error}"),
            }
        }
    }))
}

fn handle_connection(
    mut stream: TcpStream,
    context: DashboardContext,
    csrf_token: String,
) -> Result<(), String> {
    let request = read_request(&mut stream)?;
    let parsed = HttpRequest::parse(&request)?;

    let csrf_error = if parsed.method == "POST" {
        require_csrf(&parsed, &csrf_token).err()
    } else {
        None
    };
    if csrf_error.is_none() {
        context.diagnostics.clear_category("dashboard");
    }

    let response = if let Some(error) = csrf_error {
        diagnostic_response(
            &context,
            401,
            "dashboard",
            "Dashboard request was rejected.",
            &error,
            vec![
                "Reload the dashboard page and try the action again.".to_string(),
                "Use only the local http://127.0.0.1 dashboard tab served by YubiWatch."
                    .to_string(),
            ],
        )
    } else {
        match (parsed.method.as_str(), parsed.path.as_str()) {
            ("GET", "/") => html_response(&dashboard_html(
                &csrf_token,
                &context.env_file,
                &context.config,
            )),
            ("GET", "/api/status") => status_response(&context, None),
            ("POST", "/api/pin/setup") => setup_pin_response(&context, &parsed),
            ("POST", "/api/pin/confirm") => confirm_pin_response(&context, &parsed),
            ("POST", "/api/pin/reset") => reset_pin_response(&context, &parsed),
            ("POST", "/api/secure-mode") => secure_mode_response(&context, &parsed),
            ("POST", "/api/modules/toggle") => module_toggle_response(&context, &parsed),
            ("POST", "/api/disable") => disable_response(&context, &parsed),
            ("POST", "/api/disable/start") => disable_response(&context, &parsed),
            ("POST", "/api/enable") => enable_response(&context, &parsed, false),
            ("POST", "/api/enable/always") => enable_response(&context, &parsed, true),
            ("POST", "/api/devices/add") => add_device_response(&context, &parsed),
            _ => json_response(
                404,
                &diagnostic_error_json(
                    "Dashboard endpoint was not found.",
                    "The browser requested an unknown local YubiWatch path.",
                    &["Reload the dashboard page and try again.".to_string()],
                ),
            ),
        }
    };

    stream
        .write_all(response.as_bytes())
        .map_err(|error| error.to_string())
}

fn read_request(stream: &mut TcpStream) -> Result<String, String> {
    let mut buffer = [0_u8; MAX_REQUEST_BYTES];
    let bytes_read = stream
        .read(&mut buffer)
        .map_err(|error| format!("failed to read request: {error}"))?;
    Ok(String::from_utf8_lossy(&buffer[..bytes_read]).to_string())
}

fn status_response(context: &DashboardContext, message: Option<&str>) -> String {
    let status = dashboard_status(context, message);
    let key_present = status.key_present;
    context.gate.observe_key_state(key_present);
    json_response(
        200,
        &dashboard_status_json(&status, &context.gate.snapshot()),
    )
}

fn setup_pin_response(context: &DashboardContext, request: &HttpRequest) -> String {
    let status = dashboard_status(context, None);
    if let Some(error) = status.error {
        return diagnostic_response(
            context,
            503,
            "scanner",
            "Security-key scanner failed.",
            &error,
            scanner_fix_steps(),
        );
    }

    if !status.key_present {
        return json_response(
            409,
            &error_json("Insert your security key before creating the Security PIN."),
        );
    }

    let Some(pin) = json_string_from_body(&request.body, "pin") else {
        return json_response(400, &error_json("Missing Security PIN."));
    };
    let Some(confirm_pin) = json_string_from_body(&request.body, "confirm_pin") else {
        return json_response(400, &error_json("Missing Security PIN confirmation."));
    };

    match context.pin_gate.setup(&pin, &confirm_pin) {
        Ok(()) => {
            record_audit(
                context,
                "identity",
                "pin_setup",
                "allowed",
                "Security PIN created",
            );
            status_response(
                context,
                Some("Security PIN created. Protection controls now require your key and PIN."),
            )
        }
        Err(error) => json_response(409, &error_json(&error)),
    }
}

fn confirm_pin_response(context: &DashboardContext, request: &HttpRequest) -> String {
    let status = dashboard_status(context, None);
    if let Some(error) = status.error {
        return diagnostic_response(
            context,
            503,
            "scanner",
            "Security-key scanner failed.",
            &error,
            scanner_fix_steps(),
        );
    }

    if !status.key_present {
        return json_response(
            409,
            &error_json("Insert your security key before confirming the Security PIN."),
        );
    }
    if !status.pin_set {
        return json_response(
            409,
            &error_json("Create the Security PIN before confirming it."),
        );
    }

    let Some(pin) = json_string_from_body(&request.body, "pin") else {
        return json_response(400, &error_json("Security PIN is required."));
    };

    match context.pin_gate.verify(&pin) {
        Ok(()) => {
            let token = context.pin_authorization.issue();
            record_audit(
                context,
                "identity",
                "pin_confirm",
                "allowed",
                "Security PIN confirmed for 1 minute",
            );
            json_response(
                200,
                &pin_confirm_json(
                    &token,
                    PIN_AUTHORIZATION_SECONDS,
                    "Security PIN confirmed. Protection changes are unlocked for 1 minute.",
                ),
            )
        }
        Err(error) => {
            let should_lock = context.pin_authorization.record_failure();
            record_audit(
                context,
                "identity",
                "pin_confirm",
                "blocked",
                if should_lock {
                    "Security PIN failed 3 times; locking laptop"
                } else {
                    "Security PIN verification failed"
                },
            );

            if should_lock {
                match WorkstationLocker::new(context.lock_actions_enabled).lock() {
                    Ok(()) => json_response(
                        401,
                        &error_json(
                            "Incorrect Security PIN. Laptop locked after 3 failed attempts.",
                        ),
                    ),
                    Err(lock_error) => diagnostic_response(
                        context,
                        503,
                        "lock",
                        "Windows lock request failed.",
                        &lock_error,
                        lock_fix_steps(),
                    ),
                }
            } else {
                json_response(401, &error_json(&error))
            }
        }
    }
}

fn reset_pin_response(context: &DashboardContext, request: &HttpRequest) -> String {
    let status = dashboard_status(context, None);
    if let Some(error) = status.error {
        return diagnostic_response(
            context,
            503,
            "scanner",
            "Security-key scanner failed.",
            &error,
            scanner_fix_steps(),
        );
    }

    if !status.key_present {
        return json_response(
            409,
            &error_json("Insert your security key before resetting the Security PIN."),
        );
    }

    let phrase = json_string_from_body(&request.body, "confirm_reset").unwrap_or_default();
    if phrase != "LOCK RESET PIN" {
        return json_response(
            400,
            &error_json("Type LOCK RESET PIN to confirm the lock-first PIN reset."),
        );
    }

    if let Err(error) = WorkstationLocker::new(context.lock_actions_enabled).lock() {
        return diagnostic_response(
            context,
            503,
            "lock",
            "Windows lock request failed.",
            &error,
            lock_fix_steps(),
        );
    }
    if let Err(error) = persist_guard_startup(&context.env_file, false) {
        return diagnostic_response(
            context,
            503,
            "persistence",
            "Startup protection setting could not be saved.",
            &error,
            persistence_fix_steps(&context.env_file),
        );
    }
    if let Err(error) = persist_secure_mode(&context.env_file, false) {
        return diagnostic_response(
            context,
            503,
            "persistence",
            "Protected Mode setting could not be saved.",
            &error,
            persistence_fix_steps(&context.env_file),
        );
    }
    if let Err(error) = context.pin_gate.clear_after_lock() {
        return json_response(503, &error_json(&error));
    }
    context.gate.disable();
    context.pin_authorization.clear();
    context.mode_controller.set_secure_mode(false);
    context.diagnostics.clear_category("persistence");
    record_audit(
        context,
        "identity",
        "pin_reset",
        "allowed",
        "PIN reset after laptop lock",
    );

    status_response(
        context,
        Some(
            "Laptop locked, protection turned off, and Security PIN cleared. Create a new PIN after signing back in.",
        ),
    )
}

fn secure_mode_response(context: &DashboardContext, request: &HttpRequest) -> String {
    let Some(enabled) = json_bool_from_body(&request.body, "enabled") else {
        return json_response(400, &error_json("Missing enabled value."));
    };
    if let Err(response) = authorize_dashboard_command(context, request, "changing Protected Mode")
    {
        return response;
    }

    let persist_result = if enabled {
        persist_secure_mode(&context.env_file, true)
    } else {
        persist_env_values(
            &context.env_file,
            &[
                ("YUBIWATCH_SECURE_MODE_ENABLED", "false"),
                ("YUBIWATCH_ALWAYS_KEEP_ENABLED", "false"),
                ("YUBIWATCH_LOCK_ENABLED", "false"),
            ],
        )
    };
    if let Err(error) = persist_result {
        return diagnostic_response(
            context,
            503,
            "persistence",
            "Protected Mode setting could not be saved.",
            &error,
            persistence_fix_steps(&context.env_file),
        );
    }
    context.diagnostics.clear_category("persistence");

    context.mode_controller.set_secure_mode(enabled);
    if enabled && context.mode_controller.module_enabled("identity_access") {
        context.gate.enable();
    } else if !enabled {
        context.gate.disable();
    }

    record_audit(
        context,
        "policy",
        "secure_mode",
        "allowed",
        if enabled {
            "Protected Mode started"
        } else {
            "Protected Mode stopped"
        },
    );

    status_response(
        context,
        Some(if enabled {
            "Protected Mode started. Enabled protections are active where available."
        } else {
            "Protected Mode stopped. Restrictions are lifted for this laptop."
        }),
    )
}

fn module_toggle_response(context: &DashboardContext, request: &HttpRequest) -> String {
    let Some(module_id) = json_string_from_body(&request.body, "module_id") else {
        return json_response(400, &error_json("Missing module_id."));
    };
    let Some(enabled) = json_bool_from_body(&request.body, "enabled") else {
        return json_response(400, &error_json("Missing enabled value."));
    };
    if !context.mode_controller.module_exists(&module_id) {
        return json_response(400, &error_json("Unknown security module."));
    }
    if let Err(response) =
        authorize_dashboard_command(context, request, "changing a security module")
    {
        return response;
    }

    let key = module_env_key(&module_id);
    let value = if enabled { "true" } else { "false" };
    let persist_result = if module_id == "identity_access" && !enabled {
        persist_env_values(
            &context.env_file,
            &[
                (&key, value),
                ("YUBIWATCH_ALWAYS_KEEP_ENABLED", "false"),
                ("YUBIWATCH_LOCK_ENABLED", "false"),
            ],
        )
    } else {
        persist_env_values(&context.env_file, &[(&key, value)])
    };
    if let Err(error) = persist_result {
        return diagnostic_response(
            context,
            503,
            "persistence",
            "Protection setting could not be saved.",
            &error,
            persistence_fix_steps(&context.env_file),
        );
    }
    context.diagnostics.clear_category("persistence");

    if let Err(error) = context
        .mode_controller
        .set_module_enabled(&module_id, enabled)
    {
        return json_response(400, &error_json(&error));
    }

    if module_id == "identity_access" && !enabled {
        context.gate.disable();
    } else if module_id == "identity_access" && enabled {
        let secure_snapshot = context.mode_controller.snapshot(
            context.gate.snapshot().enabled,
            context.pin_gate.snapshot().is_set,
        );
        if secure_snapshot.enabled {
            context.gate.enable();
        }
    }

    let detail = format!(
        "{} {}{}",
        module_display_name(&module_id),
        if enabled { "turned on" } else { "turned off" },
        if enabled && !module_implemented(&module_id) {
            " (preview only)"
        } else {
            ""
        }
    );
    record_audit(context, "policy", "module_toggle", "allowed", &detail);

    let message = if enabled && !module_implemented(&module_id) {
        format!(
            "Protection setting updated: {detail}. Preview display enabled only; no OS blocking is active. To enforce this, install a future Windows service or administrator policy backend."
        )
    } else {
        format!("Protection setting updated: {detail}.")
    };
    status_response(context, Some(&message))
}

fn enable_response(
    context: &DashboardContext,
    request: &HttpRequest,
    persist_startup: bool,
) -> String {
    if let Err(response) = authorize_dashboard_command(context, request, "turning protection on") {
        return response;
    }

    if persist_startup && let Err(error) = persist_guard_startup(&context.env_file, true) {
        return diagnostic_response(
            context,
            503,
            "persistence",
            "Startup protection setting could not be saved.",
            &error,
            persistence_fix_steps(&context.env_file),
        );
    }
    context.diagnostics.clear_category("persistence");

    context.gate.enable();
    record_audit(
        context,
        "identity",
        "protection_on",
        "allowed",
        if persist_startup {
            "Protection turned on and saved for startup"
        } else {
            "Protection turned on for this session"
        },
    );
    status_response(
        context,
        Some(if persist_startup {
            "Protection is on and will start automatically."
        } else {
            "Protection is on for this session."
        }),
    )
}

fn disable_response(context: &DashboardContext, request: &HttpRequest) -> String {
    if let Err(response) = authorize_dashboard_command(context, request, "turning protection off") {
        return response;
    }

    if let Err(error) = persist_env_values(
        &context.env_file,
        &[
            ("YUBIWATCH_ALWAYS_KEEP_ENABLED", "false"),
            ("YUBIWATCH_LOCK_ENABLED", "false"),
            ("YUBIWATCH_SECURE_MODE_ENABLED", "false"),
        ],
    ) {
        return diagnostic_response(
            context,
            503,
            "persistence",
            "Protection setting could not be saved.",
            &error,
            persistence_fix_steps(&context.env_file),
        );
    }
    context.diagnostics.clear_category("persistence");

    context.gate.disable();
    context.mode_controller.set_secure_mode(false);

    let message = "Protection is off and will stay off at startup.";
    record_audit(
        context,
        "identity",
        "protection_off",
        "allowed",
        "Protection and Protected Mode turned off",
    );

    status_response(context, Some(message))
}

fn add_device_response(context: &DashboardContext, request: &HttpRequest) -> String {
    let Some(product_id) = product_id_from_body(&request.body) else {
        return json_response(400, &error_json("Missing product_id."));
    };

    let status = dashboard_status(context, None);
    if let Some(error) = status.error {
        return diagnostic_response(
            context,
            503,
            "scanner",
            "Security-key scanner failed.",
            &error,
            scanner_fix_steps(),
        );
    }

    if !status.original_present {
        return json_response(
            409,
            &error_json("Insert your original security key before adding another key."),
        );
    }

    if !status
        .yubico_devices
        .iter()
        .any(|device| device.product_id == product_id)
    {
        return json_response(
            409,
            &error_json("The selected security key is not currently inserted."),
        );
    }

    if context.trusted_products.contains(product_id) {
        return status_response(context, Some("This key is already allowed."));
    }

    let mut updated = context.trusted_products.product_ids();
    updated.push(product_id);
    if let Err(error) = persist_product_ids(&context.env_file, &updated) {
        return diagnostic_response(
            context,
            503,
            "persistence",
            "Trusted security-key list could not be saved.",
            &error,
            persistence_fix_steps(&context.env_file),
        );
    }
    context.diagnostics.clear_category("persistence");

    context.trusted_products.replace(updated);
    record_audit(
        context,
        "device",
        "device_trusted",
        "allowed",
        &format!("Added security key ID {}", product_id_label(product_id)),
    );
    status_response(context, Some("Security key added and saved."))
}

fn module_display_name(module_id: &str) -> String {
    module_definitions()
        .iter()
        .find(|definition| definition.id == module_id)
        .map(|definition| definition.name.to_string())
        .unwrap_or_else(|| module_id.replace('_', " "))
}

fn record_audit(
    context: &DashboardContext,
    category: &str,
    action: &str,
    outcome: &str,
    details: &str,
) {
    match context
        .audit_log
        .record_result(category, action, outcome, details)
    {
        Ok(()) => context.diagnostics.clear_category("audit"),
        Err(error) => record_diagnostic(
            context,
            Diagnostic::new(
                "audit",
                "Activity history could not be saved.",
                error,
                audit_fix_steps(&context.config.audit_log_file),
            ),
        ),
    }
}

fn record_diagnostic(context: &DashboardContext, diagnostic: Diagnostic) {
    context.diagnostics.record(diagnostic);
}

fn diagnostic_response(
    context: &DashboardContext,
    status: u16,
    category: &str,
    summary: &str,
    cause: &str,
    fix_steps: Vec<String>,
) -> String {
    record_diagnostic(
        context,
        Diagnostic::new(category, summary, cause, fix_steps.clone()),
    );
    json_response(status, &diagnostic_error_json(summary, cause, &fix_steps))
}

fn persistence_fix_steps(env_file: &Path) -> Vec<String> {
    vec![
        format!("Check that {} exists and is writable.", env_file.display()),
        "Close editors or security tools that may be locking the file.".to_string(),
        "Run YubiWatch from a foreground PowerShell window to see the exact error.".to_string(),
    ]
}

fn audit_fix_steps(path: &Path) -> Vec<String> {
    vec![
        format!("Check that {} is writable.", path.display()),
        "Create the parent folder or update YUBIWATCH_AUDIT_LOG_FILE in .env.".to_string(),
        "Run the dashboard again after fixing the path permissions.".to_string(),
    ]
}

#[derive(Clone, Debug)]
struct DashboardStatus {
    key_present: bool,
    original_present: bool,
    always_keep_enabled: bool,
    pin_set: bool,
    pin_locked_seconds_remaining: Option<u64>,
    secure_mode: SecureModeSnapshot,
    audit_events: Vec<String>,
    error: Option<String>,
    devices: Vec<String>,
    yubico_devices: Vec<YubicoDevice>,
    trusted_product_ids: Vec<u16>,
    candidate_product_ids: Vec<u16>,
    diagnostics: Vec<Diagnostic>,
    message: Option<String>,
}

fn dashboard_status(context: &DashboardContext, message: Option<&str>) -> DashboardStatus {
    let always_keep_enabled =
        startup_enabled_from_env(&context.env_file, context.config.always_keep_enabled);
    let pin_snapshot = context.pin_gate.snapshot();
    let guard_snapshot = context.gate.snapshot();
    let secure_mode = context
        .mode_controller
        .snapshot(guard_snapshot.enabled, pin_snapshot.is_set);
    let audit_events = match context.audit_log.recent_json_entries_result(12) {
        Ok(events) => {
            context.diagnostics.clear_category("audit");
            events
        }
        Err(error) => {
            context.diagnostics.record(Diagnostic::new(
                "audit",
                "Activity history could not be read.",
                error,
                audit_fix_steps(&context.config.audit_log_file),
            ));
            Vec::new()
        }
    };
    let detector =
        NativeYubiKeyDetector::new_with_store(&context.config, context.trusted_products.clone());
    match (detector.connected_devices(), detector.all_yubico_devices()) {
        (Ok(devices), Ok(yubico_devices)) => {
            context.diagnostics.clear_category("scanner");
            let trusted_product_ids = detector.trusted_product_ids();
            let candidate_product_ids =
                candidate_product_ids(&yubico_devices, &trusted_product_ids);
            let original_product_id = original_product_id(&context.config, &trusted_product_ids);
            let original_present = yubico_devices
                .iter()
                .any(|device| device.product_id == original_product_id);
            let hardware_ids = devices
                .into_iter()
                .map(|device| device.hardware_id)
                .collect::<Vec<_>>();
            let diagnostics = status_diagnostics(context, &secure_mode);

            DashboardStatus {
                key_present: !hardware_ids.is_empty(),
                original_present,
                always_keep_enabled,
                pin_set: pin_snapshot.is_set,
                pin_locked_seconds_remaining: pin_snapshot.locked_seconds_remaining,
                secure_mode,
                audit_events,
                error: None,
                devices: hardware_ids,
                yubico_devices,
                trusted_product_ids,
                candidate_product_ids,
                diagnostics,
                message: message.map(str::to_string),
            }
        }
        (Err(error), _) | (_, Err(error)) => {
            context.diagnostics.record(Diagnostic::new(
                "scanner",
                "Security-key scanner failed.",
                error.clone(),
                scanner_fix_steps(),
            ));
            let diagnostics = status_diagnostics(context, &secure_mode);
            DashboardStatus {
                key_present: false,
                original_present: false,
                always_keep_enabled,
                pin_set: pin_snapshot.is_set,
                pin_locked_seconds_remaining: pin_snapshot.locked_seconds_remaining,
                secure_mode,
                audit_events,
                error: Some(error),
                devices: Vec::new(),
                yubico_devices: Vec::new(),
                trusted_product_ids: context.trusted_products.product_ids(),
                candidate_product_ids: Vec::new(),
                diagnostics,
                message: message.map(str::to_string),
            }
        }
    }
}

fn status_diagnostics(
    context: &DashboardContext,
    secure_mode: &SecureModeSnapshot,
) -> Vec<Diagnostic> {
    let mut diagnostics = context.diagnostics.entries();
    let preview_modules = secure_mode
        .modules
        .iter()
        .filter(|module| module.enabled && !module.definition.implemented)
        .map(|module| module.definition.name)
        .collect::<Vec<_>>();
    if !preview_modules.is_empty() {
        diagnostics.push(Diagnostic::new(
            "preview",
            "Some selected protections are preview-only.",
            format!(
                "{} do not perform OS blocking in this build.",
                preview_modules.join(", ")
            ),
            vec![
                "Use the active Security Key Check, Auto Lock, Activity History, and Protection Health modules for enforcement today.".to_string(),
                "Install a future Windows service or administrator policy backend before relying on preview modules for blocking.".to_string(),
            ],
        ));
    }
    diagnostics
}

fn candidate_product_ids(devices: &[YubicoDevice], trusted_product_ids: &[u16]) -> Vec<u16> {
    if trusted_product_ids.is_empty() {
        return Vec::new();
    }

    let mut product_ids = Vec::new();
    for device in devices {
        if !trusted_product_ids.contains(&device.product_id)
            && !product_ids.contains(&device.product_id)
        {
            product_ids.push(device.product_id);
        }
    }
    product_ids
}

fn original_product_id(config: &AppConfig, trusted_product_ids: &[u16]) -> u16 {
    config
        .product_ids
        .first()
        .copied()
        .or_else(|| trusted_product_ids.first().copied())
        .unwrap_or(0x0402)
}

fn authorize_dashboard_command(
    context: &DashboardContext,
    request: &HttpRequest,
    action: &str,
) -> Result<(), String> {
    let status = dashboard_status(context, None);
    if let Some(error) = status.error {
        return Err(diagnostic_response(
            context,
            503,
            "scanner",
            "Security-key scanner failed.",
            &error,
            scanner_fix_steps(),
        ));
    }
    if !status.key_present {
        record_audit(context, "policy", action, "blocked", "security key absent");
        return Err(json_response(
            409,
            &error_json("Insert your security key before changing protection settings."),
        ));
    }

    let Some(pin_token) = json_string_from_body(&request.body, "pin_token") else {
        return Err(json_response(
            401,
            &error_json("Confirm the Security PIN before changing protection settings."),
        ));
    };
    if !context.pin_authorization.verify(&pin_token) {
        record_audit(
            context,
            "policy",
            action,
            "blocked",
            "Security PIN confirmation missing or expired",
        );
        return Err(json_response(
            401,
            &error_json("Security PIN confirmation expired. Confirm the PIN again."),
        ));
    }

    Ok(())
}

fn require_csrf(request: &HttpRequest, expected: &str) -> Result<(), String> {
    let provided = request
        .headers
        .iter()
        .find(|(name, _value)| name.eq_ignore_ascii_case("x-yubiwatch-token"))
        .map(|(_name, value)| value.as_str());

    if provided == Some(expected) {
        Ok(())
    } else {
        Err("missing or invalid dashboard token".to_string())
    }
}

fn dashboard_html(csrf_token: &str, env_file: &std::path::Path, config: &AppConfig) -> String {
    let html = r###"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>YubiWatch</title>
  <style>
    :root {
      color-scheme: dark;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: #0c0b12;
      color: #f5f0ff;
      --surface: #17151f;
      --surface-soft: #211f2b;
      --surface-hard: #0f0e16;
      --line: #3c374d;
      --line-strong: #8171b5;
      --muted: #aaa2bd;
      --strong: #f7f2ff;
      --ok: #4cc9f0;
      --ok-bg: #102838;
      --warn: #f0b84b;
      --warn-bg: #2b2412;
      --bad: #ff665c;
      --bad-bg: #331a17;
      --accent: #b388ff;
      --focus: rgba(179, 136, 255, 0.34);
      --score-tone: var(--bad);
      --score-angle: 0deg;
    }
    * {
      box-sizing: border-box;
    }
    html {
      -webkit-text-size-adjust: 100%;
      text-size-adjust: 100%;
    }
    body {
      margin: 0;
      min-height: 100vh;
      padding: clamp(10px, 3vw, 28px);
      background:
        linear-gradient(135deg, rgba(75, 55, 130, 0.38), transparent 42%),
        repeating-linear-gradient(90deg, rgba(179, 136, 255, 0.052) 0 1px, transparent 1px 52px),
        repeating-linear-gradient(0deg, rgba(76, 201, 240, 0.04) 0 1px, transparent 1px 52px),
        #0c0b12;
    }
    .classification {
      width: min(1360px, 100%);
      margin: 0 auto 10px;
      min-height: 30px;
      display: grid;
      place-items: center;
      border: 1px solid rgba(240, 184, 75, 0.52);
      border-radius: 6px;
      background: rgba(43, 36, 18, 0.82);
      color: #ffe1a3;
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 0.86rem;
      font-weight: 800;
    }
    main {
      width: min(1360px, 100%);
      margin: 0 auto;
      border: 1px solid var(--line-strong);
      border-radius: 8px;
      background: rgba(23, 21, 31, 0.96);
      box-shadow: 0 20px 55px rgba(0, 0, 0, 0.46), inset 0 0 0 1px rgba(247, 242, 255, 0.03);
      overflow: hidden;
    }
    header {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 16px;
      align-items: center;
      padding: 24px 26px;
      border-bottom: 1px solid var(--line);
      background:
        linear-gradient(90deg, rgba(179, 136, 255, 0.16), transparent 44%),
        linear-gradient(135deg, rgba(76, 201, 240, 0.08), transparent 32%),
        linear-gradient(180deg, #222032 0%, #13111c 100%);
    }
    .eyebrow {
      color: var(--warn);
      font: 800 0.76rem Consolas, "Cascadia Mono", monospace;
      text-transform: uppercase;
      margin-bottom: 5px;
    }
    h1 {
      font-size: clamp(1.35rem, 2.2vw, 1.86rem);
      line-height: 1.2;
      margin: 0;
      letter-spacing: 0;
      text-transform: uppercase;
    }
    .subhead {
      margin-top: 5px;
      color: var(--accent);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 0.86rem;
      overflow-wrap: anywhere;
    }
    .header-actions {
      display: flex;
      flex-wrap: wrap;
      justify-content: flex-end;
      gap: 9px;
      min-width: 0;
    }
    .live {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 34px;
      padding: 0 12px;
      border: 1px solid rgba(179, 136, 255, 0.42);
      border-radius: 999px;
      color: var(--strong);
      background: rgba(15, 14, 22, 0.8);
      font-size: 0.88rem;
      white-space: nowrap;
      box-shadow: inset 0 0 18px rgba(179, 136, 255, 0.08);
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      min-height: 34px;
      padding: 0 12px;
      border: 1px solid rgba(76, 201, 240, 0.36);
      border-radius: 999px;
      color: var(--ok);
      background: rgba(16, 40, 56, 0.52);
      font: 800 0.76rem Consolas, "Cascadia Mono", monospace;
      white-space: nowrap;
    }
    .live-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent);
      box-shadow: 0 0 12px rgba(179, 136, 255, 0.72);
    }
    .command-strip {
      display: grid;
      grid-template-columns: minmax(230px, 0.68fr) minmax(0, 1.15fr) minmax(230px, 0.72fr);
      gap: 14px;
      padding: 16px;
      border-bottom: 1px solid var(--line);
      background:
        linear-gradient(90deg, rgba(76, 201, 240, 0.05), transparent 48%),
        rgba(15, 14, 22, 0.52);
    }
    .posture-card,
    .command-brief,
    .scan-panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      background:
        linear-gradient(180deg, rgba(247, 242, 255, 0.04), transparent),
        var(--surface-hard);
      min-width: 0;
    }
    .posture-card {
      display: grid;
      grid-template-columns: auto minmax(0, 1fr);
      align-items: center;
      gap: 14px;
      padding: 14px;
    }
    .score-ring {
      width: 92px;
      height: 92px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at center, var(--surface-hard) 0 58%, transparent 59%),
        conic-gradient(var(--score-tone) var(--score-angle), rgba(247, 242, 255, 0.1) 0);
      border: 1px solid rgba(247, 242, 255, 0.14);
      box-shadow: inset 0 0 24px rgba(0, 0, 0, 0.28), 0 0 20px rgba(179, 136, 255, 0.08);
      flex: 0 0 auto;
    }
    .score-value {
      font: 900 1.38rem Consolas, "Cascadia Mono", monospace;
      color: var(--strong);
    }
    .score-label {
      margin-top: 4px;
      color: var(--muted);
      font-size: 0.82rem;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .command-brief {
      padding: 14px;
      display: grid;
      gap: 12px;
      align-content: center;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 8px;
    }
    .kpi {
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: rgba(23, 21, 31, 0.78);
      padding: 10px;
    }
    .kpi-value {
      color: var(--strong);
      font: 850 1.05rem Consolas, "Cascadia Mono", monospace;
      overflow-wrap: anywhere;
    }
    .kpi-label {
      margin-top: 3px;
      color: var(--muted);
      font-size: 0.76rem;
      text-transform: uppercase;
    }
    .scan-panel {
      position: relative;
      overflow: hidden;
      min-height: 120px;
      padding: 14px;
      background:
        linear-gradient(90deg, rgba(76, 201, 240, 0.1), transparent 2px) 0 0 / 24px 24px,
        linear-gradient(0deg, rgba(179, 136, 255, 0.08), transparent 2px) 0 0 / 24px 24px,
        var(--surface-hard);
    }
    .scan-panel::after {
      content: "";
      position: absolute;
      inset: 0;
      background: linear-gradient(110deg, transparent 0 46%, rgba(76, 201, 240, 0.16) 50%, transparent 54% 100%);
      transform: translateX(-65%);
      animation: scanSweep 4.8s linear infinite;
    }
    @keyframes scanSweep {
      to {
        transform: translateX(65%);
      }
    }
    .scan-title,
    .scan-value {
      position: relative;
      z-index: 1;
    }
    .scan-title {
      color: var(--accent);
      font: 800 0.78rem Consolas, "Cascadia Mono", monospace;
      text-transform: uppercase;
    }
    .scan-value {
      margin-top: 38px;
      color: var(--strong);
      font-weight: 800;
      overflow-wrap: anywhere;
    }
    .content {
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(330px, 0.75fr);
      gap: 16px;
      padding: 16px;
    }
    .stack {
      display: grid;
      gap: 12px;
      align-content: start;
    }
    .metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 10px;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      background:
        linear-gradient(180deg, rgba(247, 242, 255, 0.035), transparent),
        var(--surface);
      padding: 15px;
      min-width: 0;
      box-shadow: inset 0 1px 0 rgba(247, 242, 255, 0.04);
    }
    .label {
      color: var(--accent);
      font-size: 0.74rem;
      text-transform: uppercase;
      letter-spacing: 0;
      margin-bottom: 7px;
      font-family: Consolas, "Cascadia Mono", monospace;
    }
    .value {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--strong);
      font-size: 1.02rem;
      font-weight: 650;
      overflow-wrap: anywhere;
      min-height: 28px;
    }
    .dot {
      flex: 0 0 auto;
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--muted);
      box-shadow: 0 0 10px rgba(157, 170, 144, 0.38);
    }
    .value.ok .dot {
      background: var(--ok);
      box-shadow: 0 0 12px rgba(76, 201, 240, 0.68);
    }
    .value.warn .dot {
      background: var(--warn);
      box-shadow: 0 0 12px rgba(240, 184, 75, 0.62);
    }
    .value.bad .dot {
      background: var(--bad);
      box-shadow: 0 0 12px rgba(255, 102, 92, 0.68);
    }
    .hero {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 14px;
      align-items: center;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background:
        linear-gradient(90deg, rgba(179, 136, 255, 0.12), transparent 55%),
        var(--surface-hard);
      position: relative;
      overflow: hidden;
    }
    .hero::after {
      content: "";
      position: absolute;
      inset: auto 0 0;
      height: 2px;
      background: linear-gradient(90deg, var(--accent), var(--ok), transparent);
      opacity: 0.76;
    }
    .shield {
      width: 54px;
      height: 54px;
      display: grid;
      place-items: center;
      border-radius: 8px;
      background: var(--ok-bg);
      color: var(--ok);
      font-weight: 800;
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 0.9rem;
      border: 1px solid rgba(76, 201, 240, 0.42);
      box-shadow: inset 0 0 18px rgba(76, 201, 240, 0.1);
    }
    .shield.paused {
      background: var(--warn-bg);
      color: var(--warn);
      border-color: rgba(240, 184, 75, 0.42);
    }
    .hero-title {
      font-size: 1.12rem;
      font-weight: 750;
      margin: 0;
      text-transform: uppercase;
    }
    .hero-copy {
      margin: 3px 0 0;
      color: var(--muted);
      font-size: 0.92rem;
      overflow-wrap: anywhere;
    }
    .actions {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      align-items: stretch;
    }
    button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 46px;
      min-width: 132px;
      border: 1px solid rgba(179, 136, 255, 0.34);
      border-radius: 6px;
      padding: 0 15px;
      background: linear-gradient(180deg, #2a2540 0%, #181523 100%);
      color: var(--strong);
      font-weight: 750;
      cursor: pointer;
      transition: transform 120ms ease, border-color 120ms ease, background 120ms ease;
      white-space: normal;
      text-align: center;
      text-transform: uppercase;
      font-size: 0.86rem;
      line-height: 1.1;
      box-shadow: inset 0 1px 0 rgba(247, 242, 255, 0.08), 0 8px 16px rgba(0, 0, 0, 0.25);
    }
    button:hover {
      transform: translateY(-1px);
      border-color: var(--accent);
    }
    button:focus-visible {
      outline: 3px solid var(--focus);
      outline-offset: 2px;
    }
    button:disabled {
      opacity: 0.55;
      cursor: not-allowed;
      transform: none;
      box-shadow: none;
    }
    button.secondary {
      background: linear-gradient(180deg, #1b1b29 0%, #11111a 100%);
      color: var(--strong);
      border-color: var(--line);
    }
    button.persistent {
      background: linear-gradient(180deg, #3b2f67 0%, #241d42 100%);
      border-color: rgba(179, 136, 255, 0.55);
      color: #f7f2ff;
    }
    button.danger {
      background: linear-gradient(180deg, #4a211d 0%, #2b1412 100%);
      border-color: rgba(255, 102, 92, 0.5);
      color: #fff1ef;
    }
    .proof-track {
      height: 7px;
      overflow: hidden;
      border-radius: 999px;
      background: var(--surface-hard);
      border: 1px solid var(--line);
      margin-top: 10px;
    }
    .proof-bar {
      width: 0%;
      height: 100%;
      background: linear-gradient(90deg, var(--warn), var(--accent));
      transition: width 220ms ease;
    }
    .devices {
      display: grid;
      gap: 8px;
      max-height: 248px;
      overflow: auto;
      padding-right: 2px;
    }
    .device {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 10px 11px;
      background: var(--surface-hard);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 0.82rem;
      overflow-wrap: anywhere;
      color: #dfd8ee;
    }
    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      min-height: 30px;
      padding: 0 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #211d31;
      color: var(--strong);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 0.82rem;
      font-weight: 650;
    }
    .candidate {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 10px;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 11px;
      background: var(--surface-hard);
      min-width: 0;
    }
    .candidate-title {
      font-family: Consolas, "Cascadia Mono", monospace;
      font-weight: 700;
      font-size: 0.9rem;
      color: var(--strong);
    }
    .candidate-note {
      margin-top: 2px;
      color: var(--muted);
      font-size: 0.82rem;
    }
    .candidate button {
      min-height: 34px;
      padding: 0 12px;
    }
    .hint {
      color: var(--muted);
      font-size: 0.86rem;
      line-height: 1.45;
      margin-top: 9px;
    }
    .message {
      min-height: 46px;
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px 13px;
      color: #dfd8ee;
      background: var(--surface-hard);
      font-size: 0.92rem;
      line-height: 1.45;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      box-shadow: inset 0 0 18px rgba(179, 136, 255, 0.035);
    }
    .pin-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-top: 10px;
    }
    .pin-grid.single {
      grid-template-columns: 1fr;
    }
    input {
      width: 100%;
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 12px;
      background: var(--surface-hard);
      color: var(--strong);
      font: 650 0.94rem Consolas, "Cascadia Mono", monospace;
      outline: none;
    }
    input:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--focus);
    }
    .pin-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 10px;
    }
    .pin-actions button {
      min-height: 38px;
    }
    .pin-expiry {
      color: var(--muted);
      font-size: 0.78rem;
      line-height: 1.35;
      margin-top: 8px;
      min-height: 18px;
      overflow-wrap: anywhere;
    }
    .pin-recovery {
      display: none;
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid var(--line);
    }
    .pin-recovery.visible {
      display: block;
    }
    .pin-console {
      text-align: center;
    }
    .pin-console .value {
      justify-content: center;
    }
    .pin-console .pin-grid {
      max-width: 760px;
      margin-left: auto;
      margin-right: auto;
    }
    .pin-console .pin-actions {
      justify-content: center;
    }
    .pin-console .pin-actions button {
      min-width: 132px;
    }
    .mode-actions {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .panel-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
    }
    .module-tabs {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }
    .module-tabs button {
      min-width: 0;
      min-height: 34px;
      padding: 0 11px;
      border-radius: 999px;
      font-size: 0.76rem;
    }
    .module-tabs button.active {
      border-color: rgba(76, 201, 240, 0.52);
      background: linear-gradient(180deg, #173044 0%, #101b28 100%);
      color: #d9f7ff;
    }
    .module-list,
    .audit-list,
    .warning-list {
      display: grid;
      gap: 8px;
      margin-top: 12px;
    }
    .module-list {
      grid-template-columns: repeat(2, minmax(0, 1fr));
      max-height: 560px;
      overflow: auto;
      padding-right: 3px;
    }
    .module-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr);
      gap: 12px;
      align-items: center;
      min-width: 0;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--surface-hard);
    }
    .module-row.active {
      border-color: rgba(76, 201, 240, 0.4);
      box-shadow: inset 3px 0 0 rgba(76, 201, 240, 0.72);
    }
    .module-row.gap {
      border-color: rgba(240, 184, 75, 0.38);
      box-shadow: inset 3px 0 0 rgba(240, 184, 75, 0.74);
    }
    .module-name {
      color: var(--strong);
      font-weight: 750;
      overflow-wrap: anywhere;
    }
    .module-topline {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px;
      margin-bottom: 4px;
    }
    .module-pill {
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      padding: 0 7px;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: var(--muted);
      font: 700 0.68rem Consolas, "Cascadia Mono", monospace;
      text-transform: uppercase;
    }
    .module-meta {
      margin-top: 3px;
      color: var(--muted);
      font-size: 0.82rem;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .module-status {
      display: inline-flex;
      align-items: center;
      min-height: 25px;
      padding: 0 8px;
      margin-top: 7px;
      border: 1px solid var(--line);
      border-radius: 999px;
      color: var(--strong);
      font: 700 0.74rem Consolas, "Cascadia Mono", monospace;
      text-transform: uppercase;
    }
    .module-status.ok {
      border-color: rgba(76, 201, 240, 0.42);
      color: var(--ok);
    }
    .module-status.warn {
      border-color: rgba(240, 184, 75, 0.42);
      color: var(--warn);
    }
    .module-status.bad {
      border-color: rgba(255, 102, 92, 0.42);
      color: var(--bad);
    }
    .module-row button {
      min-height: 36px;
      min-width: 0;
      padding: 0 11px;
      width: 100%;
    }
    .warning-item,
    .audit-entry {
      border-left: 3px solid var(--warn);
      padding: 9px 10px;
      background: rgba(15, 14, 22, 0.78);
      color: #dfd8ee;
      font-size: 0.86rem;
      line-height: 1.4;
      overflow-wrap: anywhere;
    }
    .audit-entry {
      border-left-color: var(--accent);
      font-family: Consolas, "Cascadia Mono", monospace;
      font-size: 0.78rem;
    }
    .audit-time {
      color: var(--muted);
      margin-bottom: 3px;
    }
    .audit-action {
      color: var(--strong);
      font-weight: 800;
    }
    .audit-details {
      color: #dfd8ee;
      margin-top: 3px;
    }
    @media (max-width: 920px) {
      header,
      .content,
      .command-strip {
        grid-template-columns: 1fr;
      }
      .content {
        padding: 14px;
      }
      .header-actions {
        justify-content: flex-start;
      }
    }
    @media (max-width: 640px) {
      header {
        padding: 18px;
      }
      .metrics {
        grid-template-columns: 1fr;
      }
      .hero {
        grid-template-columns: 1fr;
      }
      .live {
        justify-self: start;
      }
      .actions {
        grid-template-columns: 1fr;
      }
      .candidate {
        grid-template-columns: 1fr;
      }
      .mode-actions,
      .module-row,
      .panel-head,
      .posture-card,
      .kpi-grid {
        grid-template-columns: 1fr;
      }
      .module-list {
        grid-template-columns: 1fr;
        max-height: none;
      }
      .candidate button {
        width: 100%;
      }
      .module-row button {
        width: 100%;
      }
      .pin-grid {
        grid-template-columns: 1fr;
      }
    }
    @media (max-width: 380px) {
      body {
        padding: 8px;
      }
      header,
      .content {
        padding: 10px;
      }
      h1 {
        font-size: 1.2rem;
      }
      .panel,
      .hero {
        padding: 12px;
      }
      button {
        min-width: 0;
      }
    }
  </style>
</head>
<body>
  <div class="classification">Official (Closed), Non-Sensitive.</div>
  <main>
    <header>
      <div>
        <div class="eyebrow">Laptop Protection Center</div>
        <h1>YubiWatch Safety Center</h1>
        <div class="subhead">Runs only on this laptop // Security Key 1050 / 0402</div>
      </div>
      <div class="header-actions">
        <div class="live" aria-live="polite">
          <span class="live-dot"></span>
          <span id="updated">Connecting</span>
        </div>
        <div class="status-badge">LOCAL ONLY</div>
      </div>
    </header>
    <section class="command-strip">
      <div class="posture-card">
        <div class="score-ring" id="score-ring">
          <span class="score-value" id="score-value">--</span>
        </div>
        <div>
          <div class="label">Protection Score</div>
          <div class="value" id="score-posture"><span class="dot"></span><span>Assessing</span></div>
          <div class="score-label" id="score-label">Checking protection status.</div>
        </div>
      </div>
      <div class="command-brief">
        <div class="label">Quick Status</div>
        <div class="kpi-grid">
          <div class="kpi">
            <div class="kpi-value" id="kpi-modules">--</div>
            <div class="kpi-label">Protections On</div>
          </div>
          <div class="kpi">
            <div class="kpi-value" id="kpi-active">--</div>
            <div class="kpi-label">Working Now</div>
          </div>
          <div class="kpi">
            <div class="kpi-value" id="kpi-warnings">--</div>
            <div class="kpi-label">Needs Attention</div>
          </div>
        </div>
      </div>
      <div class="scan-panel" aria-hidden="true">
        <div class="scan-title">Security Key Status</div>
        <div class="scan-value" id="scan-value">Checking key status</div>
      </div>
    </section>
    <div class="content">
      <section class="stack">
        <div class="hero">
          <div class="shield" id="shield">SYS</div>
          <div>
            <p class="hero-title" id="headline">Checking protection state</p>
            <p class="hero-copy" id="summary">Waiting for the app to report status.</p>
          </div>
        </div>
        <div class="metrics">
          <section class="panel">
            <div class="label">Laptop Lock</div>
            <div class="value" id="guard"><span class="dot"></span><span>Loading</span></div>
          </section>
          <section class="panel">
            <div class="label">Security Key</div>
            <div class="value" id="key"><span class="dot"></span><span>Loading</span></div>
          </section>
          <section class="panel">
            <div class="label">Starts Automatically</div>
            <div class="value" id="proof"><span class="dot"></span><span>Idle</span></div>
          </section>
          <section class="panel">
            <div class="label">Protected Mode</div>
            <div class="value" id="secure-mode"><span class="dot"></span><span>Waiting</span></div>
          </section>
        </div>
        <section class="panel">
          <div class="label">Right Now</div>
          <div class="value" id="proof-time"><span>Not active</span></div>
          <div class="proof-track" aria-hidden="true">
            <div class="proof-bar" id="proof-bar"></div>
          </div>
        </section>
        <section class="panel pin-console">
          <div class="label">Security PIN</div>
          <div class="value" id="pin-state"><span class="dot"></span><span>Checking</span></div>
          <div class="pin-grid" id="pin-setup">
            <input id="new-pin" type="password" inputmode="numeric" autocomplete="new-password" placeholder="Create 6-12 digit PIN">
            <input id="confirm-pin" type="password" inputmode="numeric" autocomplete="new-password" placeholder="Confirm PIN">
          </div>
          <div class="pin-grid single" id="pin-auth">
            <input id="command-pin" type="password" inputmode="numeric" autocomplete="current-password" placeholder="Enter PIN, then press Confirm PIN">
          </div>
          <div class="pin-expiry" id="pin-expiry" aria-live="polite">Press Confirm PIN to unlock changes for 1 minute.</div>
          <div class="pin-actions">
            <button id="set-pin" class="persistent" type="button">Create PIN</button>
            <button id="confirm-pin-session" class="persistent" type="button">Confirm PIN</button>
            <button id="show-reset" class="secondary" type="button">Forgot PIN</button>
          </div>
          <div class="pin-recovery" id="pin-recovery">
            <div class="hint">Reset locks the laptop first, then turns protection off and clears the PIN. After signing back in with Windows, create a new PIN.</div>
            <div class="pin-grid single">
              <input id="reset-confirm" type="text" autocomplete="off" placeholder="Type LOCK RESET PIN">
            </div>
            <div class="pin-actions">
              <button id="reset-pin" class="danger" type="button">Lock And Reset PIN</button>
            </div>
          </div>
        </section>
        <div class="actions">
          <button id="enable" class="secondary" type="button" title="Turn on for this session">Turn On</button>
          <button id="always-enable" class="persistent" type="button" title="Turn on now and at startup">Always On</button>
          <button id="disable" class="danger" type="button" title="Turn off now and at startup">Turn Off</button>
        </div>
        <div class="message" id="message" aria-live="polite">Ready.</div>
        <section class="panel">
          <div class="panel-head">
            <div>
              <div class="label">Protection Settings</div>
              <div class="value" id="compliance"><span class="dot"></span><span>Assessing</span></div>
            </div>
            <div class="module-tabs" role="group" aria-label="Module filter">
              <button class="secondary" type="button" data-module-filter="all">All</button>
              <button class="secondary active" type="button" data-module-filter="enabled">On</button>
              <button class="secondary" type="button" data-module-filter="gaps">Needs Fix</button>
            </div>
          </div>
          <div class="mode-actions">
            <button id="secure-enable" class="persistent" type="button">Start Protected Mode</button>
            <button id="secure-disable" class="danger" type="button">Stop Protected Mode</button>
          </div>
          <div class="warning-list" id="compliance-warnings">
            <div class="warning-item">Checking protection health.</div>
          </div>
          <div class="module-list" id="modules">
            <div class="module-row">
              <div>
                <div class="module-name">Loading protection settings</div>
                <div class="module-meta">Protection settings are loading.</div>
              </div>
            </div>
          </div>
        </section>
      </section>
      <aside class="stack">
        <section class="panel">
          <div class="label">Recent Activity</div>
          <div class="audit-list" id="audit-events">
            <div class="audit-entry">No activity loaded.</div>
          </div>
        </section>
        <section class="panel">
          <div class="label">Settings File</div>
          <div class="value">__ENV_FILE__</div>
        </section>
        <section class="panel">
          <div class="label">Detected Security Key</div>
          <div class="devices" id="devices">
            <div class="device">Waiting for scan</div>
          </div>
        </section>
        <section class="panel">
          <div class="label">Allowed Key IDs</div>
          <div class="chips" id="trusted">
            <span class="chip">Loading</span>
          </div>
          <div class="hint">The first ID is your original security key.</div>
        </section>
        <section class="panel">
          <div class="label">Add Another Key</div>
          <div class="devices" id="candidates">
            <div class="device">Insert another security key while your original key is present.</div>
          </div>
        </section>
      </aside>
    </div>
  </main>
  <script>
    const TOKEN = "__CSRF_TOKEN__";
    const PROOF_TIMEOUT = __PROOF_TIMEOUT__;
    const nodes = {
      guard: document.querySelector("#guard"),
      key: document.querySelector("#key"),
      proof: document.querySelector("#proof"),
      secureMode: document.querySelector("#secure-mode"),
      compliance: document.querySelector("#compliance"),
      scoreRing: document.querySelector("#score-ring"),
      scoreValue: document.querySelector("#score-value"),
      scorePosture: document.querySelector("#score-posture"),
      scoreLabel: document.querySelector("#score-label"),
      kpiModules: document.querySelector("#kpi-modules"),
      kpiActive: document.querySelector("#kpi-active"),
      kpiWarnings: document.querySelector("#kpi-warnings"),
      scanValue: document.querySelector("#scan-value"),
      complianceWarnings: document.querySelector("#compliance-warnings"),
      modules: document.querySelector("#modules"),
      auditEvents: document.querySelector("#audit-events"),
      proofTime: document.querySelector("#proof-time"),
      proofBar: document.querySelector("#proof-bar"),
      pinState: document.querySelector("#pin-state"),
      pinSetup: document.querySelector("#pin-setup"),
      pinAuth: document.querySelector("#pin-auth"),
      newPin: document.querySelector("#new-pin"),
      confirmPin: document.querySelector("#confirm-pin"),
      commandPin: document.querySelector("#command-pin"),
      pinExpiry: document.querySelector("#pin-expiry"),
      setPin: document.querySelector("#set-pin"),
      confirmPinSession: document.querySelector("#confirm-pin-session"),
      showReset: document.querySelector("#show-reset"),
      pinRecovery: document.querySelector("#pin-recovery"),
      resetConfirm: document.querySelector("#reset-confirm"),
      resetPin: document.querySelector("#reset-pin"),
      shield: document.querySelector("#shield"),
      headline: document.querySelector("#headline"),
      summary: document.querySelector("#summary"),
      devices: document.querySelector("#devices"),
      trusted: document.querySelector("#trusted"),
      candidates: document.querySelector("#candidates"),
      message: document.querySelector("#message"),
      updated: document.querySelector("#updated"),
      enable: document.querySelector("#enable"),
      alwaysEnable: document.querySelector("#always-enable"),
      disable: document.querySelector("#disable"),
      secureEnable: document.querySelector("#secure-enable"),
      secureDisable: document.querySelector("#secure-disable"),
      moduleFilters: Array.from(document.querySelectorAll("[data-module-filter]"))
    };
    let moduleFilter = "enabled";
    let pinToken = "";
    let pinTokenExpiresAt = 0;
    let pinTokenExpiryTimer = null;
    let pinTokenExpired = false;

    async function api(path, options = {}) {
      const response = await fetch(path, {
        ...options,
        headers: {
          "X-YubiWatch-Token": TOKEN,
          ...(options.headers || {})
        }
      });
      const text = await response.text();
      let data = {};
      if (text) {
        try {
          data = JSON.parse(text);
        } catch (_error) {
          data = { error: text };
        }
      }
      if (!response.ok) {
        const steps = Array.isArray(data.fix_steps) && data.fix_steps.length
          ? ` Fix: ${data.fix_steps.join(" ")}`
          : "";
        const cause = data.cause ? ` ${data.cause}` : "";
        throw new Error(`${data.error || "Request failed"}${cause}${steps}`);
      }
      return data;
    }

    function setMetric(node, text, tone) {
      node.className = `value ${tone || ""}`;
      node.querySelector("span:last-child").textContent = text;
    }

    function clearPinAuthorization(reason) {
      if (pinTokenExpiryTimer) {
        clearTimeout(pinTokenExpiryTimer);
        pinTokenExpiryTimer = null;
      }
      pinToken = "";
      pinTokenExpiresAt = 0;
      pinTokenExpired = Boolean(reason);
      if (nodes.commandPin.value) {
        nodes.commandPin.value = "";
      }
      nodes.pinExpiry.textContent = reason || "Press Confirm PIN to unlock changes for 1 minute.";
    }

    function expirePinAuthorization() {
      clearPinAuthorization("PIN confirmation expired. Confirm it again to change protection settings.");
      nodes.message.textContent = "Security PIN confirmation expired. Confirm it again before changing protection.";
    }

    function refreshPinExpiryText() {
      if (pinAuthorizationIsExpired()) {
        expirePinAuthorization();
        return;
      }
      if (!pinToken || pinTokenExpiresAt <= 0) {
        nodes.pinExpiry.textContent = pinTokenExpired
          ? "PIN confirmation expired. Confirm it again to change protection settings."
          : "Press Confirm PIN to unlock changes for 1 minute.";
        return;
      }
      const seconds = Math.max(1, Math.ceil((pinTokenExpiresAt - Date.now()) / 1000));
      nodes.pinExpiry.textContent = `PIN confirmed. Changes unlock for ${seconds}s.`;
    }

    function armPinAuthorization(token, expiresInSeconds) {
      if (pinTokenExpiryTimer) {
        clearTimeout(pinTokenExpiryTimer);
        pinTokenExpiryTimer = null;
      }
      pinToken = token;
      pinTokenExpired = false;
      pinTokenExpiresAt = Date.now() + Math.max(1, expiresInSeconds) * 1000;
      nodes.commandPin.value = "";
      refreshPinExpiryText();
      pinTokenExpiryTimer = setTimeout(expirePinAuthorization, Math.max(1, expiresInSeconds) * 1000);
    }

    function pinAuthorizationIsExpired() {
      return Boolean(pinToken) && pinTokenExpiresAt > 0 && Date.now() >= pinTokenExpiresAt;
    }

    function proofLabel(stage) {
      if (stage === "waiting_for_removal") return "Remove the key";
      if (stage === "waiting_for_reinsert") return "Reinsert the key";
      return "Idle";
    }

    function scoreTone(score) {
      if (score >= 85) return "ok";
      if (score >= 40) return "warn";
      return "bad";
    }

    function toneColor(tone) {
      if (tone === "ok") return "#4cc9f0";
      if (tone === "warn") return "#f0b84b";
      return "#ff665c";
    }

    function renderCommandStrip(data, secure) {
      const modules = secure.modules || [];
      const enabledCount = modules.filter((module) => module.enabled).length;
      const activeCount = modules.filter((module) => module.active).length;
      const warningCount = (secure.warnings || []).length;
      const score = Number.isFinite(secure.score) ? secure.score : 0;
      const tone = scoreTone(score);

      nodes.scoreRing.style.setProperty("--score-angle", `${Math.max(0, Math.min(100, score)) * 3.6}deg`);
      nodes.scoreRing.style.setProperty("--score-tone", toneColor(tone));
      nodes.scoreValue.textContent = `${score}`;
      setMetric(nodes.scorePosture, secure.posture || "Unknown", tone);
      nodes.scoreLabel.textContent = secure.enabled
        ? "Protected Mode is on."
        : "Protected Mode is off.";
      nodes.kpiModules.textContent = `${enabledCount}/${modules.length || 0}`;
      nodes.kpiActive.textContent = `${activeCount}`;
      nodes.kpiWarnings.textContent = `${warningCount}`;
      nodes.scanValue.textContent = data.key_present
        ? "Security key detected"
        : "Security key not detected";
    }

    function renderDevices(devices) {
      nodes.devices.textContent = "";
      if (!devices || devices.length === 0) {
        const empty = document.createElement("div");
        empty.className = "device";
        empty.textContent = "No security key detected.";
        nodes.devices.appendChild(empty);
        return;
      }
      for (const id of devices) {
        const item = document.createElement("div");
        item.className = "device";
        item.textContent = id;
        nodes.devices.appendChild(item);
      }
    }

    function renderTrusted(productIds) {
      nodes.trusted.textContent = "";
      for (const productId of productIds || []) {
        const item = document.createElement("span");
        item.className = "chip";
        item.textContent = productId;
        nodes.trusted.appendChild(item);
      }
      if (!productIds || productIds.length === 0) {
        const item = document.createElement("span");
        item.className = "chip";
        item.textContent = "Any Yubico key";
        nodes.trusted.appendChild(item);
      }
    }

    function renderCandidates(data) {
      nodes.candidates.textContent = "";
      const candidates = data.candidate_product_ids || [];
      if (candidates.length === 0) {
        const empty = document.createElement("div");
        empty.className = "device";
        empty.textContent = data.original_present
          ? "No new security keys are currently inserted."
          : "Insert your original security key before adding another key.";
        nodes.candidates.appendChild(empty);
        return;
      }

      for (const productId of candidates) {
        const row = document.createElement("div");
        row.className = "candidate";

        const copy = document.createElement("div");
        const title = document.createElement("div");
        title.className = "candidate-title";
        title.textContent = productId;
        const note = document.createElement("div");
        note.className = "candidate-note";
        note.textContent = data.original_present
          ? "Present now. Original key verified."
          : "Original key required before this can be added.";
        copy.append(title, note);

        const button = document.createElement("button");
        button.type = "button";
        button.textContent = "Add";
        button.disabled = !data.original_present;
        button.addEventListener("click", () => addDevice(productId));

        row.append(copy, button);
        nodes.candidates.appendChild(row);
      }
    }

    function diagnosticMessage(diagnostic) {
      if (!diagnostic) return "";
      const steps = Array.isArray(diagnostic.fix_steps) && diagnostic.fix_steps.length
        ? ` Fix: ${diagnostic.fix_steps.join(" ")}`
        : "";
      const cause = diagnostic.cause ? ` ${diagnostic.cause}` : "";
      return `${diagnostic.summary || "YubiWatch needs attention."}${cause}${steps}`;
    }

    function renderWarnings(warnings, diagnostics) {
      nodes.complianceWarnings.textContent = "";
      const items = [];
      for (const warning of warnings || []) items.push(warning);
      for (const diagnostic of diagnostics || []) items.push(diagnosticMessage(diagnostic));
      if (items.length === 0) items.push("Nothing needs attention right now.");
      for (const warning of items) {
        const item = document.createElement("div");
        item.className = "warning-item";
        item.textContent = warning;
        nodes.complianceWarnings.appendChild(item);
      }
    }

    function friendlyEventLabel(value) {
      const labels = {
        activity: "Activity",
        allowed: "Done",
        blocked: "Blocked",
        dashboard_started: "Dashboard opened",
        device: "Security Key",
        device_trusted: "Key added",
        identity: "Access",
        module_toggle: "Protection setting changed",
        pin_confirm: "PIN confirmed",
        pin_reset: "PIN reset",
        pin_setup: "PIN created",
        policy: "Settings",
        protection_off: "Protection turned off",
        protection_on: "Protection turned on",
        secure_mode: "Protected Mode",
        system: "System"
      };
      if (labels[value]) return labels[value];
      return String(value || "")
        .replace(/_/g, " ")
        .replace(/\b\w/g, (letter) => letter.toUpperCase());
    }

    function friendlyEventDetails(value) {
      return String(value || "")
        .replace(/localhost dashboard started/gi, "Dashboard opened locally")
        .replace(/Command PIN verifier created/gi, "Security PIN created")
        .replace(/Secure Mode engaged/gi, "Protected Mode started")
        .replace(/Secure Mode stood down/gi, "Protected Mode stopped")
        .replace(/lock-first PIN reset cleared verifier and turned protection off/gi, "PIN reset after laptop lock")
        .replace(/guard/gi, "protection");
    }

    function renderModules(data, commandLocked) {
      nodes.modules.textContent = "";
      const secure = data.secure_mode || {};
      const modules = (secure.modules || []).filter((module) => {
        if (moduleFilter === "enabled") return module.enabled;
        if (moduleFilter === "gaps") return !module.implemented || !module.enabled || module.status === "Ready";
        return true;
      });
      if (modules.length === 0) {
        const empty = document.createElement("div");
        empty.className = "module-row";
        empty.textContent = moduleFilter === "enabled"
          ? "No protections are on yet. Open All to choose what this laptop should protect."
          : moduleFilter === "gaps"
            ? "No urgent gaps found in this view."
            : "No protection settings are available right now.";
        nodes.modules.appendChild(empty);
        return;
      }

      for (const module of modules) {
        const row = document.createElement("div");
        row.className = `module-row ${module.active ? "active" : (!module.implemented || !module.enabled ? "gap" : "")}`;

        const copy = document.createElement("div");
        const topline = document.createElement("div");
        topline.className = "module-topline";
        const category = document.createElement("span");
        category.className = "module-pill";
        category.textContent = module.category;
        const capability = document.createElement("span");
        capability.className = "module-pill";
        capability.textContent = module.capability;
        topline.append(category, capability);
        const title = document.createElement("div");
        title.className = "module-name";
        title.textContent = module.name;
        const meta = document.createElement("div");
        meta.className = "module-meta";
        meta.textContent = module.summary;
        const status = document.createElement("div");
        status.className = `module-status ${module.active ? "ok" : (module.enabled ? "warn" : "bad")}`;
        status.textContent = `${module.enabled ? "On" : "Off"} - ${module.status}`;
        const risk = document.createElement("div");
        risk.className = "module-meta";
        risk.textContent = module.risk;
        copy.append(topline, title, meta, status, risk);

        const button = document.createElement("button");
        button.type = "button";
        button.className = module.enabled ? "danger" : "persistent";
        button.textContent = module.enabled ? "Switch Off" : "Switch On";
        button.disabled = commandLocked;
        button.addEventListener("click", () => toggleModule(module.id, !module.enabled, module.name));

        row.append(copy, button);
        nodes.modules.appendChild(row);
      }
    }

    function renderAudit(events) {
      nodes.auditEvents.textContent = "";
      if (!events || events.length === 0) {
        const empty = document.createElement("div");
        empty.className = "audit-entry";
        empty.textContent = "No activity yet.";
        nodes.auditEvents.appendChild(empty);
        return;
      }

      for (const event of events.slice().reverse()) {
        const item = document.createElement("div");
        item.className = "audit-entry";
        const when = event.timestamp
          ? new Date(event.timestamp * 1000).toLocaleString()
          : "time unknown";
        const time = document.createElement("div");
        time.className = "audit-time";
        time.textContent = when;
        const action = document.createElement("div");
        action.className = "audit-action";
        action.textContent = [
          friendlyEventLabel(event.category),
          friendlyEventLabel(event.action),
          friendlyEventLabel(event.outcome)
        ].join(" - ");
        const details = document.createElement("div");
        details.className = "audit-details";
        details.textContent = friendlyEventDetails(event.details);
        item.append(time, action, details);
        nodes.auditEvents.appendChild(item);
      }
    }

    function render(data) {
      const proofActive = Boolean(data.proof_stage);
      const keyPresent = data.key_present === true;
      const startupEnabled = data.always_keep_enabled === true;
      const pinSet = data.pin_set === true;
      const pinLockedSeconds = data.pin_locked_seconds_remaining;
      const pinLocked = Number.isInteger(pinLockedSeconds) && pinLockedSeconds > 0;
      const secure = data.secure_mode || {};
      const pinConfirmed = Boolean(pinToken) && !pinAuthorizationIsExpired();
      const commandLocked = !keyPresent || !pinSet || pinLocked || !pinConfirmed;
      renderCommandStrip(data, secure);

      setMetric(nodes.guard, data.enabled ? "On" : "Off", data.enabled ? "ok" : "warn");
      setMetric(nodes.key, keyPresent ? "Detected" : "Missing", keyPresent ? "ok" : "bad");
      setMetric(
        nodes.proof,
        startupEnabled ? "Yes" : "No",
        startupEnabled ? "ok" : "warn"
      );
      setMetric(
        nodes.secureMode,
        secure.enabled ? "On" : "Off",
        secure.enabled ? "ok" : "warn"
      );
      setMetric(
        nodes.compliance,
        `${secure.posture || "Unknown"} // ${secure.score ?? 0}%`,
        scoreTone(secure.score ?? 0)
      );
      setMetric(
        nodes.pinState,
        pinSet ? (pinLocked ? `Locked ${pinLockedSeconds}s` : (pinConfirmed ? "PIN Confirmed" : "PIN Created")) : "Create PIN",
        pinSet ? (pinLocked ? "bad" : "ok") : "warn"
      );

      nodes.pinSetup.style.display = pinSet ? "none" : "grid";
      nodes.pinAuth.style.display = pinSet ? "grid" : "none";
      nodes.pinExpiry.style.display = pinSet ? "block" : "none";
      nodes.setPin.style.display = pinSet ? "none" : "inline-flex";
      nodes.confirmPinSession.style.display = pinSet ? "inline-flex" : "none";
      nodes.showReset.style.display = pinSet ? "inline-flex" : "none";
      if (!pinSet || !keyPresent || pinLocked) {
        nodes.pinRecovery.classList.remove("visible");
        clearPinAuthorization();
      } else {
        refreshPinExpiryText();
      }
      nodes.setPin.disabled = !keyPresent || pinSet;
      nodes.confirmPinSession.disabled = !keyPresent || !pinSet || pinLocked;
      nodes.resetPin.disabled = !keyPresent || !pinSet;

      nodes.shield.classList.toggle("paused", !data.enabled);
      nodes.shield.textContent = data.enabled ? "ON" : "OFF";
      nodes.headline.textContent = data.enabled ? "Protection is on" : "Protection is off";
      nodes.summary.textContent = data.enabled
        ? keyPresent
          ? "Security key detected. The laptop will lock if the key is removed."
          : "Security key missing. The laptop lock trigger is active."
        : keyPresent
          ? "Security key detected. Turn protection on when ready."
          : "Insert your security key to turn protection on.";

      if (proofActive) {
        const remaining = data.proof_seconds_remaining ?? 0;
        const percent = Math.max(0, Math.min(100, (remaining / PROOF_TIMEOUT) * 100));
        nodes.proofTime.querySelector("span").textContent = `${proofLabel(data.proof_stage)}: ${remaining}s`;
        nodes.proofBar.style.width = `${percent}%`;
      } else {
        nodes.proofTime.querySelector("span").textContent = data.enabled
          ? startupEnabled
            ? "Protection is on now and after restart."
            : "Protection is on until this app closes."
          : "Protection is off now and after restart.";
        nodes.proofBar.style.width = "0%";
      }

      nodes.enable.disabled = proofActive || commandLocked || data.enabled;
      nodes.alwaysEnable.disabled = proofActive || commandLocked || (data.enabled && startupEnabled);
      nodes.disable.disabled = proofActive || commandLocked || (!data.enabled && !startupEnabled);
      nodes.secureEnable.disabled = proofActive || commandLocked || secure.enabled;
      nodes.secureDisable.disabled = proofActive || commandLocked || !secure.enabled;
      nodes.updated.textContent = new Date().toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      });
      renderDevices(data.devices);
      renderTrusted(data.trusted_product_ids);
      renderCandidates(data);
      renderWarnings(secure.warnings, data.diagnostics);
      renderModules(data, proofActive || commandLocked);
      renderAudit(data.audit_events);

      const firstDiagnostic = (data.diagnostics || [])[0];
      nodes.message.textContent = firstDiagnostic
        ? diagnosticMessage(firstDiagnostic)
        : data.error
        ? `Security-key scanner error: ${data.error}`
        : proofActive
          ? "Complete the key interaction before the timer expires."
          : data.message || (pinSet
            ? (pinTokenExpired
              ? "Security PIN confirmation expired. Confirm it again before changing protection."
              : (keyPresent ? "Ready." : "Insert your security key to turn protection on."))
            : "Create a Security PIN while your security key is inserted.");
    }

    async function refresh() {
      try {
        render(await api("/api/status"));
      } catch (error) {
        nodes.message.textContent = error.message;
        nodes.updated.textContent = "Offline";
      }
    }

    function pinTokenPayload() {
      const pin_token = pinTokenValue();
      return JSON.stringify({ pin_token });
    }

    function pinTokenValue() {
      if (pinAuthorizationIsExpired()) {
        expirePinAuthorization();
        throw new Error("Security PIN confirmation expired. Confirm it again.");
      }
      if (!pinToken) throw new Error("Confirm the Security PIN first.");
      return pinToken;
    }

    function enteredCommandPin() {
      const pin = nodes.commandPin.value.trim();
      if (!pin) throw new Error("Enter the Security PIN.");
      return pin;
    }

    document.querySelector("#enable").addEventListener("click", async () => {
      nodes.message.textContent = "Turning protection on...";
      try {
        render(await api("/api/enable", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: pinTokenPayload()
        }));
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    });

    document.querySelector("#always-enable").addEventListener("click", async () => {
      nodes.message.textContent = "Saving always-on protection...";
      try {
        render(await api("/api/enable/always", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: pinTokenPayload()
        }));
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    });

    document.querySelector("#disable").addEventListener("click", async () => {
      nodes.message.textContent = "Turning protection off...";
      try {
        render(await api("/api/disable", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: pinTokenPayload()
        }));
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    });

    document.querySelector("#secure-enable").addEventListener("click", async () => {
      nodes.message.textContent = "Starting Protected Mode...";
      try {
        render(await api("/api/secure-mode", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: true, pin_token: pinTokenValue() })
        }));
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    });

    document.querySelector("#secure-disable").addEventListener("click", async () => {
      nodes.message.textContent = "Stopping Protected Mode...";
      try {
        render(await api("/api/secure-mode", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ enabled: false, pin_token: pinTokenValue() })
        }));
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    });

    document.querySelector("#confirm-pin-session").addEventListener("click", async () => {
      nodes.message.textContent = "Confirming Security PIN...";
      try {
        const data = await api("/api/pin/confirm", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pin: enteredCommandPin() })
        });
        armPinAuthorization(data.pin_token, data.expires_in_seconds || 60);
        nodes.message.textContent = data.message || "Security PIN confirmed.";
      } catch (error) {
        clearPinAuthorization(error.message);
        nodes.message.textContent = error.message;
      }
    });

    document.querySelector("#set-pin").addEventListener("click", async () => {
      nodes.message.textContent = "Creating Security PIN...";
      try {
        render(await api("/api/pin/setup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            pin: nodes.newPin.value.trim(),
            confirm_pin: nodes.confirmPin.value.trim()
          })
        }));
        nodes.newPin.value = "";
        nodes.confirmPin.value = "";
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    });

    document.querySelector("#show-reset").addEventListener("click", () => {
      nodes.pinRecovery.classList.toggle("visible");
    });

    for (const button of nodes.moduleFilters) {
      button.addEventListener("click", () => {
        moduleFilter = button.dataset.moduleFilter || "all";
        for (const item of nodes.moduleFilters) {
          item.classList.toggle("active", item === button);
        }
        refresh();
      });
    }

    document.querySelector("#reset-pin").addEventListener("click", async () => {
      nodes.message.textContent = "Locking laptop before PIN reset...";
      try {
        render(await api("/api/pin/reset", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ confirm_reset: nodes.resetConfirm.value.trim() })
        }));
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    });

    async function addDevice(productId) {
      nodes.message.textContent = `Adding key ${productId}...`;
      try {
        render(await api("/api/devices/add", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ product_id: productId })
        }));
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    }

    async function toggleModule(moduleId, enabled, moduleName) {
      nodes.message.textContent = `${enabled ? "Turning on" : "Turning off"} ${moduleName || "this setting"}...`;
      try {
        render(await api("/api/modules/toggle", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            module_id: moduleId,
            enabled,
            pin_token: pinTokenValue()
          })
        }));
      } catch (error) {
        nodes.message.textContent = error.message;
      }
    }

    refresh();
    setInterval(refresh, 1000);
  </script>
</body>
</html>"###;

    html.replace(
        "__ENV_FILE__",
        &escape_html(&env_file.display().to_string()),
    )
    .replace("__CSRF_TOKEN__", csrf_token)
    .replace(
        "__PROOF_TIMEOUT__",
        &config.disable_proof_timeout.as_secs().max(1).to_string(),
    )
}

fn snapshot_json(
    snapshot: &GuardSnapshot,
    key_present: Option<bool>,
    error: Option<&str>,
) -> String {
    let proof_stage = snapshot
        .proof_stage
        .map(stage_name)
        .map(|stage| format!("\"{stage}\""))
        .unwrap_or_else(|| "null".to_string());
    let proof_seconds = snapshot
        .proof_seconds_remaining
        .map(|seconds| seconds.to_string())
        .unwrap_or_else(|| "null".to_string());
    let key_present = key_present
        .map(|present| present.to_string())
        .unwrap_or_else(|| "null".to_string());
    let error = error
        .map(|value| format!("\"{}\"", escape_json(value)))
        .unwrap_or_else(|| "null".to_string());

    format!(
        "{{\"enabled\":{},\"proof_stage\":{},\"proof_seconds_remaining\":{},\"key_present\":{},\"error\":{},\"devices\":[]}}",
        snapshot.enabled, proof_stage, proof_seconds, key_present, error
    )
}

fn dashboard_status_json(status: &DashboardStatus, snapshot: &GuardSnapshot) -> String {
    let base = snapshot_json(snapshot, Some(status.key_present), status.error.as_deref());
    let payload = base.trim_end_matches('}').to_string()
        + &format!(
            ",\"original_present\":{},\"always_keep_enabled\":{},\"pin_set\":{},\"pin_locked_seconds_remaining\":{},\"secure_mode\":{},\"audit_events\":[{}],\"trusted_product_ids\":[{}],\"candidate_product_ids\":[{}],\"yubico_devices\":[{}],\"diagnostics\":[{}],\"message\":{}}}",
            status.original_present,
            status.always_keep_enabled,
            status.pin_set,
            status
                .pin_locked_seconds_remaining
                .map(|seconds| seconds.to_string())
                .unwrap_or_else(|| "null".to_string()),
            secure_mode_snapshot_json(&status.secure_mode),
            status.audit_events.join(","),
            product_id_list_json(&status.trusted_product_ids),
            product_id_list_json(&status.candidate_product_ids),
            yubico_devices_json(&status.yubico_devices),
            diagnostics_json(&status.diagnostics),
            status
                .message
                .as_ref()
                .map(|message| format!("\"{}\"", escape_json(message)))
                .unwrap_or_else(|| "null".to_string())
        );

    payload.replace(
        "\"devices\":[]",
        &format!("\"devices\":[{}]", quoted_list_json(&status.devices)),
    )
}

fn error_json(error: &str) -> String {
    diagnostic_error_json(error, "", &[])
}

fn diagnostic_error_json(error: &str, cause: &str, fix_steps: &[String]) -> String {
    format!(
        "{{\"error\":\"{}\",\"cause\":\"{}\",\"fix_steps\":[{}]}}",
        escape_json(error),
        escape_json(cause),
        quoted_list_json(fix_steps)
    )
}

fn pin_confirm_json(token: &str, expires_in_seconds: u64, message: &str) -> String {
    format!(
        "{{\"pin_token\":\"{}\",\"expires_in_seconds\":{},\"message\":\"{}\"}}",
        escape_json(token),
        expires_in_seconds,
        escape_json(message)
    )
}

fn stage_name(stage: ProofStage) -> &'static str {
    match stage {
        ProofStage::WaitingForRemoval => "waiting_for_removal",
        ProofStage::WaitingForReinsert => "waiting_for_reinsert",
    }
}

fn quoted_list_json(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn product_id_list_json(product_ids: &[u16]) -> String {
    product_ids
        .iter()
        .map(|product_id| format!("\"{}\"", product_id_label(*product_id)))
        .collect::<Vec<_>>()
        .join(",")
}

fn yubico_devices_json(devices: &[YubicoDevice]) -> String {
    devices
        .iter()
        .map(|device| {
            format!(
                "{{\"product_id\":\"{}\",\"hardware_id\":\"{}\"}}",
                product_id_label(device.product_id),
                escape_json(&device.hardware_id)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn diagnostics_json(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| {
            format!(
                "{{\"category\":\"{}\",\"summary\":\"{}\",\"cause\":\"{}\",\"fix_steps\":[{}]}}",
                escape_json(&diagnostic.category),
                escape_json(&diagnostic.summary),
                escape_json(&diagnostic.cause),
                quoted_list_json(&diagnostic.fix_steps)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn html_response(body: &str) -> String {
    response(200, "text/html; charset=utf-8", body)
}

fn json_response(status: u16, body: &str) -> String {
    response(status, "application/json; charset=utf-8", body)
}

fn response(status: u16, content_type: &str, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        503 => "Service Unavailable",
        _ => "Error",
    };

    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nPermissions-Policy: camera=(), microphone=(), geolocation=()\r\nContent-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; connect-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn product_id_from_body(body: &str) -> Option<u16> {
    let key_index = body.find("product_id")?;
    let value_start = body[key_index..].find(':')? + key_index + 1;
    let value = body[value_start..]
        .trim_start()
        .trim_start_matches('"')
        .chars()
        .take_while(|character| {
            character.is_ascii_hexdigit() || *character == 'x' || *character == 'X'
        })
        .collect::<String>();

    parse_product_id(&value)
}

fn json_string_from_body(body: &str, key: &str) -> Option<String> {
    let key_pattern = format!("\"{key}\"");
    let key_index = body.find(&key_pattern)?;
    let value_start =
        body[key_index + key_pattern.len()..].find(':')? + key_index + key_pattern.len() + 1;
    let value = body[value_start..].trim_start();
    let value = value.strip_prefix('"')?;
    let mut output = String::new();
    let mut escaped = false;

    for character in value.chars() {
        if escaped {
            output.push(match character {
                '"' => '"',
                '\\' => '\\',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            });
            escaped = false;
            continue;
        }

        match character {
            '\\' => escaped = true,
            '"' => return Some(output),
            other => output.push(other),
        }
    }

    None
}

fn json_bool_from_body(body: &str, key: &str) -> Option<bool> {
    let key_pattern = format!("\"{key}\"");
    let key_index = body.find(&key_pattern)?;
    let value_start =
        body[key_index + key_pattern.len()..].find(':')? + key_index + key_pattern.len() + 1;
    let value = body[value_start..].trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn parse_product_id(value: &str) -> Option<u16> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u16::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u16>().ok()
    }
}

fn persist_guard_startup(env_file: &Path, enabled: bool) -> Result<(), String> {
    let value = if enabled { "true" } else { "false" };
    persist_env_values(
        env_file,
        &[
            ("YUBIWATCH_ALWAYS_KEEP_ENABLED", value),
            ("YUBIWATCH_LOCK_ENABLED", value),
        ],
    )
}

fn persist_secure_mode(env_file: &Path, enabled: bool) -> Result<(), String> {
    persist_env_values(
        env_file,
        &[(
            "YUBIWATCH_SECURE_MODE_ENABLED",
            if enabled { "true" } else { "false" },
        )],
    )
}

fn persist_product_ids(env_file: &Path, product_ids: &[u16]) -> Result<(), String> {
    let product_value = product_ids
        .iter()
        .map(|product_id| product_id_label(*product_id))
        .collect::<Vec<_>>()
        .join(",");
    persist_env_values(env_file, &[("YUBIWATCH_PRODUCT_IDS", &product_value)])
}

fn persist_env_values(env_file: &Path, replacements: &[(&str, &str)]) -> Result<(), String> {
    let contents = fs::read_to_string(env_file).unwrap_or_default();
    let mut found = vec![false; replacements.len()];
    let mut lines = Vec::new();

    for line in contents.lines() {
        if let Some(index) = replacements
            .iter()
            .position(|(key, _value)| line_has_env_key(line, key))
        {
            let (key, value) = replacements[index];
            lines.push(format!("{key}={value}"));
            found[index] = true;
        } else {
            lines.push(line.to_string());
        }
    }

    for (index, (key, value)) in replacements.iter().enumerate() {
        if !found[index] {
            if !lines.is_empty() && lines.last().is_some_and(|line| !line.is_empty()) {
                lines.push(String::new());
            }
            lines.push(format!("{key}={value}"));
        }
    }

    fs::write(env_file, lines.join("\n") + "\n")
        .map_err(|error| format!("failed to update {}: {error}", env_file.display()))
}

fn startup_enabled_from_env(env_file: &Path, default: bool) -> bool {
    read_env_value(env_file, "YUBIWATCH_ALWAYS_KEEP_ENABLED")
        .map(|value| parse_env_bool(&value))
        .unwrap_or(default)
}

fn read_env_value(env_file: &Path, key: &str) -> Option<String> {
    let contents = fs::read_to_string(env_file).ok()?;
    for raw_line in contents.lines() {
        if line_has_env_key(raw_line, key) {
            let (_name, value) = raw_line.split_once('=')?;
            return Some(clean_env_fragment(value));
        }
    }
    None
}

fn line_has_env_key(line: &str, expected_key: &str) -> bool {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }

    line.split_once('=')
        .map(|(key, _value)| key.trim().eq_ignore_ascii_case(expected_key))
        .unwrap_or(false)
}

fn clean_env_fragment(value: &str) -> String {
    let mut value = value.trim().to_string();
    if let Some((before_comment, _comment)) = value.split_once(" #") {
        value = before_comment.trim().to_string();
    }

    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() >= 2
        && chars.first() == chars.last()
        && matches!(chars.first(), Some('\'' | '"'))
    {
        chars[1..chars.len() - 1].iter().collect()
    } else {
        value
    }
}

fn parse_env_bool(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "y" | "on"
    )
}

fn secure_token() -> String {
    let mut bytes = [0_u8; 32];
    fill_random(&mut bytes);
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

#[cfg(windows)]
fn fill_random(bytes: &mut [u8]) {
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut std::ffi::c_void,
            buffer: *mut u8,
            count: u32,
            flags: u32,
        ) -> i32;
    }

    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };

    if status != 0 {
        fallback_fill_random(bytes);
    }
}

#[cfg(not(windows))]
fn fill_random(bytes: &mut [u8]) {
    fallback_fill_random(bytes);
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

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpRequest {
    fn parse(request: &str) -> Result<Self, String> {
        let (head, body) = request
            .split_once("\r\n\r\n")
            .or_else(|| request.split_once("\n\n"))
            .unwrap_or((request, ""));
        let mut lines = head.lines();
        let request_line = lines.next().ok_or_else(|| "request is empty".to_string())?;
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .ok_or_else(|| "request method missing".to_string())?
            .to_string();
        let path = request_parts
            .next()
            .ok_or_else(|| "request path missing".to_string())?
            .split('?')
            .next()
            .unwrap_or("/")
            .to_string();

        let mut headers = Vec::new();
        for line in lines {
            if line.trim().is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }

        Ok(Self {
            method,
            path,
            headers,
            body: body.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_line_and_headers() {
        let request = "POST /api/enable HTTP/1.1\r\nX-YubiWatch-Token: abc\r\n\r\n{\"ok\":true}";
        let parsed = HttpRequest::parse(request).unwrap();

        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/api/enable");
        assert_eq!(parsed.body, "{\"ok\":true}");
        assert_eq!(
            parsed.headers,
            vec![("X-YubiWatch-Token".to_string(), "abc".to_string())]
        );
    }

    #[test]
    fn escapes_json_strings() {
        assert_eq!(escape_json("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn secure_token_has_expected_length() {
        assert_eq!(secure_token().len(), 64);
    }

    #[test]
    fn pin_authorization_issues_tokens_and_locks_after_three_failures() {
        let authorization = PinAuthorization::new();
        let token = authorization.issue();

        assert!(authorization.verify(&token));
        assert!(!authorization.record_failure());
        assert!(!authorization.record_failure());
        assert!(authorization.record_failure());
        assert!(!authorization.verify(&token));

        let next_token = authorization.issue();
        assert!(authorization.verify(&next_token));
        assert!(!authorization.record_failure());
    }

    #[test]
    fn dashboard_html_contains_polished_shell() {
        let config = AppConfig::default();
        let html = dashboard_html("0123456789abcdef", std::path::Path::new(".env"), &config);

        assert!(html.contains("YubiWatch Safety Center"));
        assert!(html.contains("Official (Closed), Non-Sensitive."));
        assert!(html.contains("Protection Score"));
        assert!(html.contains("Quick Status"));
        assert!(html.contains("Detected Security Key"));
        assert!(html.contains("Right Now"));
        assert!(html.contains("Security PIN"));
        assert!(html.contains("Confirm PIN"));
        assert!(html.contains("Protection Settings"));
        assert!(html.contains("Recent Activity"));
        assert!(html.contains("Start Protected Mode"));
        assert!(html.contains("Allowed Key IDs"));
        assert!(html.contains("Add Another Key"));
        assert!(html.contains("Always On"));
        assert!(html.contains("0123456789abcdef"));
        assert!(!html.contains("__CSRF_TOKEN__"));
        assert!(!html.contains("__ENV_FILE__"));
        assert!(!html.contains("__PROOF_TIMEOUT__"));
    }

    #[test]
    fn parses_product_id_from_json_body() {
        assert_eq!(
            product_id_from_body(r#"{"product_id":"0x0407"}"#),
            Some(0x0407)
        );
        assert_eq!(product_id_from_body(r#"{"product_id":1031}"#), Some(1031));
    }

    #[test]
    fn persists_product_ids_to_env_file() {
        let path = std::env::temp_dir().join(format!("yubiwatch-test-{}.env", std::process::id()));
        fs::write(
            &path,
            "YUBIWATCH_VENDOR_ID=0x1050\nYUBIWATCH_PRODUCT_IDS=0x0402\n",
        )
        .unwrap();

        persist_product_ids(&path, &[0x0402, 0x0407]).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(contents.contains("YUBIWATCH_PRODUCT_IDS=0x0402,0x0407"));
    }

    #[test]
    fn persists_guard_startup_policy_to_env_file() {
        let path =
            std::env::temp_dir().join(format!("yubiwatch-policy-test-{}.env", std::process::id()));
        fs::write(&path, "YUBIWATCH_ALWAYS_KEEP_ENABLED=true\n").unwrap();

        persist_guard_startup(&path, false).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        let _ = fs::remove_file(&path);

        assert!(contents.contains("YUBIWATCH_ALWAYS_KEEP_ENABLED=false"));
        assert!(contents.contains("YUBIWATCH_LOCK_ENABLED=false"));
    }

    #[test]
    fn candidates_exclude_trusted_product_ids() {
        let devices = vec![
            YubicoDevice {
                hardware_id: "USB\\VID_1050&PID_0402".to_string(),
                product_id: 0x0402,
            },
            YubicoDevice {
                hardware_id: "USB\\VID_1050&PID_0407".to_string(),
                product_id: 0x0407,
            },
        ];

        assert_eq!(candidate_product_ids(&devices, &[0x0402]), vec![0x0407]);
    }

    #[test]
    fn dashboard_status_json_includes_devices() {
        let status = DashboardStatus {
            key_present: true,
            original_present: true,
            always_keep_enabled: true,
            pin_set: true,
            pin_locked_seconds_remaining: None,
            secure_mode: SecureModeController::new(true, &std::collections::HashMap::new())
                .snapshot(true, true),
            audit_events: vec![
                "{\"timestamp\":1,\"category\":\"policy\",\"action\":\"test\",\"outcome\":\"allowed\",\"details\":\"ok\"}"
                    .to_string(),
            ],
            error: None,
            devices: vec!["USB\\VID_1050&PID_0402".to_string()],
            yubico_devices: Vec::new(),
            trusted_product_ids: vec![0x0402],
            candidate_product_ids: Vec::new(),
            diagnostics: Vec::new(),
            message: None,
        };

        let json = dashboard_status_json(
            &status,
            &GuardSnapshot {
                enabled: true,
                proof_stage: None,
                proof_seconds_remaining: None,
            },
        );

        assert!(json.contains("\"devices\":[\"USB\\\\VID_1050&PID_0402\"]"));
        assert!(json.contains("\"always_keep_enabled\":true"));
        assert!(json.contains("\"pin_set\":true"));
        assert!(json.contains("\"secure_mode\""));
        assert!(json.contains("\"audit_events\""));
        assert!(json.contains("\"diagnostics\""));
        assert!(json.contains("\"trusted_product_ids\":[\"0x0402\"]"));
    }

    #[test]
    fn parses_json_string_fields_from_body() {
        assert_eq!(
            json_string_from_body(r#"{"pin":"123456","confirm_pin":"123456"}"#, "pin"),
            Some("123456".to_string())
        );
    }
}
