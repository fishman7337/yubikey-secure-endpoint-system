//! Native YubiWatch library.
//!
//! The crate keeps the long-running security policy small and testable:
//! configuration parsing, USB detection, lock enforcement, dashboard control,
//! and runtime protection state each live in separate modules.

pub mod audit;
pub mod browser;
pub mod config;
pub mod dashboard;
pub mod detector;
pub mod diagnostics;
pub mod instance;
pub mod locker;
pub mod mode;
pub mod pin;
pub mod security;
pub mod watchdog;
