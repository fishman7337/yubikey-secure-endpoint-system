//! Command-line entry point for the native YubiWatch executable.

use std::env;
use std::path::PathBuf;
use std::process;

use yubiwatch_native::browser::open_url;
use yubiwatch_native::config::{AppConfig, default_env_path};
use yubiwatch_native::dashboard::spawn_dashboard;
use yubiwatch_native::detector::{NativeYubiKeyDetector, TrustedProducts};
use yubiwatch_native::locker::WorkstationLocker;
use yubiwatch_native::mode::module_default_enabled;
use yubiwatch_native::security::SecurityGate;
use yubiwatch_native::watchdog::Watchdog;

#[derive(Debug)]
struct Args {
    env_file: PathBuf,
    check: bool,
    foreground: bool,
    dry_run: bool,
    dashboard_override: Option<bool>,
    open_dashboard_override: Option<bool>,
}

fn main() {
    match parse_args(env::args().skip(1)) {
        Ok(None) => {}
        Ok(Some(args)) => run(args),
        Err(error) => {
            eprintln!("{error}");
            eprintln!();
            print_help();
            process::exit(2);
        }
    }
}

fn run(args: Args) -> ! {
    let config = AppConfig::from_env_file(&args.env_file);

    if args.check {
        process::exit(check_once(&config));
    }

    let identity_enabled = config
        .module_overrides
        .get("identity_access")
        .copied()
        .unwrap_or_else(|| module_default_enabled("identity_access").unwrap_or(true));
    let startup_enforcement =
        config.always_keep_enabled || (config.secure_mode_enabled && identity_enabled);
    let gate = SecurityGate::new(
        !args.dry_run && startup_enforcement,
        config.disable_proof_timeout,
    );
    let trusted_products = TrustedProducts::new(config.product_ids.clone());
    let dashboard_enabled = args
        .dashboard_override
        .unwrap_or(config.dashboard_enabled && !args.dry_run);
    let dashboard_url = format!("http://127.0.0.1:{}/", config.dashboard_port);
    let startup_browser_handled = env::var_os("YUBIWATCH_STARTUP_BROWSER_HANDLED").is_some();
    if dashboard_enabled {
        match spawn_dashboard(
            config.clone(),
            args.env_file.clone(),
            gate.clone(),
            trusted_products.clone(),
            !args.dry_run,
        ) {
            Ok(_handle) => {
                if args.foreground {
                    println!("Dashboard listening on {dashboard_url}");
                }

                let should_open_dashboard = args.open_dashboard_override.unwrap_or(
                    config.open_dashboard_on_startup && !args.dry_run && !startup_browser_handled,
                );
                if should_open_dashboard {
                    match open_url(&dashboard_url) {
                        Ok(()) if args.foreground => {
                            println!("Opened dashboard in the default browser.");
                        }
                        Ok(()) => {}
                        Err(error) => eprintln!("{error}"),
                    }
                }
            }
            Err(error) => eprintln!("{error}"),
        }
    }

    let detector = NativeYubiKeyDetector::new_with_store(&config, trusted_products);
    let locker = WorkstationLocker::new(!args.dry_run);
    let mut watchdog = Watchdog::new(config, detector, locker, gate, args.foreground);
    watchdog.run_forever();
}

fn check_once(config: &AppConfig) -> i32 {
    let detector = NativeYubiKeyDetector::new(config);
    match detector.connected_devices() {
        Ok(devices) if devices.is_empty() => {
            println!("No matching security key detected.");
            1
        }
        Ok(devices) => {
            println!("Matching security key detected:");
            for device in devices {
                println!("  {}", device.hardware_id);
            }
            0
        }
        Err(error) => {
            eprintln!("USB detection failed: {error}");
            2
        }
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut parsed = Args {
        env_file: default_env_path(),
        check: false,
        foreground: false,
        dry_run: false,
        dashboard_override: None,
        open_dashboard_override: None,
    };

    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(None);
            }
            "--check" => parsed.check = true,
            "--foreground" => parsed.foreground = true,
            "--dry-run" => parsed.dry_run = true,
            "--dashboard" => parsed.dashboard_override = Some(true),
            "--no-dashboard" => parsed.dashboard_override = Some(false),
            "--open-dashboard" => parsed.open_dashboard_override = Some(true),
            "--no-open-dashboard" => parsed.open_dashboard_override = Some(false),
            "--env-file" => {
                let Some(path) = args.next() else {
                    return Err("--env-file requires a path".to_string());
                };
                parsed.env_file = PathBuf::from(path);
            }
            _ => return Err(format!("Unknown argument: {arg}")),
        }
    }

    Ok(Some(parsed))
}

fn print_help() {
    println!(
        "\
YubiWatch native

Usage:
  yubiwatch.exe [--env-file PATH] [--check] [--foreground] [--dry-run]
                [--dashboard | --no-dashboard]
                [--open-dashboard | --no-open-dashboard]

Options:
  --env-file PATH  Path to .env settings file. Defaults to .\\.env.
  --check          Check for a matching security key once and exit without locking.
  --foreground     Print status messages to this terminal.
  --dry-run        Run the watchdog but skip the Windows lock call.
  --dashboard      Force-enable the localhost dashboard.
  --no-dashboard   Disable the localhost dashboard for this run.
  --open-dashboard Open the dashboard in the default browser after startup.
  --no-open-dashboard
                  Do not open the dashboard browser after startup.
  -h, --help       Show this help.
"
    );
}
