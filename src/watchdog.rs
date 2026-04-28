//! Watchdog policy loop.
//!
//! The watchdog has no unbounded memory growth: it tracks only when the key
//! became absent and when the most recent lock was requested.

use std::thread;
use std::time::{Duration, Instant};

use crate::config::AppConfig;
use crate::detector::DeviceDetector;
use crate::locker::Locker;
use crate::security::{GuardDecision, SecurityGate};

/// Mutable timing state for one watchdog process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WatchdogState {
    /// Time offset when the security key was first missing.
    pub missing_since: Option<Duration>,
    /// Time offset when a lock was most recently requested.
    pub last_lock_at: Option<Duration>,
}

/// Monitors security-key presence and requests workstation locks when needed.
pub struct Watchdog<D, L> {
    config: AppConfig,
    detector: D,
    locker: L,
    security_gate: SecurityGate,
    state: WatchdogState,
    foreground: bool,
}

impl<D, L> Watchdog<D, L>
where
    D: DeviceDetector,
    L: Locker,
{
    /// Creates a watchdog with injected detector and locker dependencies.
    pub fn new(
        config: AppConfig,
        detector: D,
        locker: L,
        security_gate: SecurityGate,
        foreground: bool,
    ) -> Self {
        Self {
            config,
            detector,
            locker,
            security_gate,
            state: WatchdogState::default(),
            foreground,
        }
    }

    /// Runs the watchdog forever.
    pub fn run_forever(&mut self) -> ! {
        self.log("YubiWatch native started.");
        if !self.config.startup_grace.is_zero() {
            self.log(&format!(
                "Waiting {:.1} seconds before enforcing lock policy.",
                self.config.startup_grace.as_secs_f64()
            ));
            thread::sleep(self.config.startup_grace);
        }

        let started_at = Instant::now();
        loop {
            let sleep_for = self.tick(started_at.elapsed());
            thread::sleep(sleep_for);
        }
    }

    /// Evaluates a single watchdog tick and returns how long to sleep next.
    pub fn tick(&mut self, now: Duration) -> Duration {
        let present = self.detect_present();
        let guard_decision = self.security_gate.observe_key_state(present);

        if guard_decision == GuardDecision::SuppressLock {
            self.state = WatchdogState::default();
            return self.config.present_poll;
        }

        if present {
            if self.state.missing_since.is_some() || self.state.last_lock_at.is_some() {
                self.log("Security key detected. Monitoring resumed.");
            }
            self.state = WatchdogState::default();
            return self.config.present_poll;
        }

        if self.state.missing_since.is_none() {
            self.state.missing_since = Some(now);
            self.log("Security key not detected. Starting grace timer.");
        }

        let missing_since = self.state.missing_since.unwrap_or(now);
        let missing_for = now.saturating_sub(missing_since);
        let should_lock = missing_for >= self.config.missing_grace
            && self
                .state
                .last_lock_at
                .map(|last_lock_at| now.saturating_sub(last_lock_at) >= self.config.relock)
                .unwrap_or(true);

        if should_lock {
            self.lock_workstation();
            self.state.last_lock_at = Some(now);
        }

        if self.state.last_lock_at.is_some() {
            self.config.post_lock_poll
        } else {
            self.config.missing_poll
        }
    }

    /// Returns a copy of the current policy timing state.
    pub fn state(&self) -> WatchdogState {
        self.state
    }

    fn detect_present(&mut self) -> bool {
        match self.detector.is_connected() {
            Ok(present) => present,
            Err(error) => {
                self.log(&format!("USB detection failed: {error}"));
                !self.config.fail_safe_lock
            }
        }
    }

    fn lock_workstation(&mut self) {
        self.log("Security key absent. Locking workstation.");
        if let Err(error) = self.locker.lock() {
            self.log(&format!("Failed to lock workstation: {error}"));
        }
    }

    fn log(&self, message: &str) {
        if self.foreground {
            println!("{message}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDetector {
        states: Vec<Result<bool, String>>,
        last_state: Result<bool, String>,
    }

    impl FakeDetector {
        fn new(states: Vec<Result<bool, String>>) -> Self {
            Self {
                states,
                last_state: Ok(true),
            }
        }
    }

    impl DeviceDetector for FakeDetector {
        fn is_connected(&mut self) -> Result<bool, String> {
            if !self.states.is_empty() {
                self.last_state = self.states.remove(0);
            }
            self.last_state.clone()
        }
    }

    #[derive(Default)]
    struct FakeLocker {
        lock_count: usize,
    }

    impl Locker for FakeLocker {
        fn lock(&mut self) -> Result<(), String> {
            self.lock_count += 1;
            Ok(())
        }
    }

    fn config() -> AppConfig {
        AppConfig {
            startup_grace: Duration::ZERO,
            ..AppConfig::default()
        }
    }

    fn gate() -> SecurityGate {
        SecurityGate::new(true, Duration::from_secs(30))
    }

    #[test]
    fn present_key_uses_slow_polling_and_does_not_lock() {
        let config = config();
        let detector = FakeDetector::new(vec![Ok(true)]);
        let locker = FakeLocker::default();
        let mut watchdog = Watchdog::new(config.clone(), detector, locker, gate(), false);

        assert_eq!(watchdog.tick(Duration::from_secs(10)), config.present_poll);
    }

    #[test]
    fn missing_key_waits_for_grace_period_before_locking() {
        let config = config();
        let detector = FakeDetector::new(vec![Ok(false), Ok(false)]);
        let locker = FakeLocker::default();
        let mut watchdog = Watchdog::new(config.clone(), detector, locker, gate(), false);

        assert_eq!(watchdog.tick(Duration::from_secs(10)), config.missing_poll);
        assert_eq!(
            watchdog.tick(Duration::from_secs(12)),
            config.post_lock_poll
        );
        assert_eq!(watchdog.state().last_lock_at, Some(Duration::from_secs(12)));
    }

    #[test]
    fn absent_key_relocks_after_cooldown() {
        let config = AppConfig {
            missing_grace: Duration::ZERO,
            relock: Duration::from_secs(5),
            startup_grace: Duration::ZERO,
            ..AppConfig::default()
        };
        let detector = FakeDetector::new(vec![Ok(false), Ok(false), Ok(false)]);
        let locker = FakeLocker::default();
        let mut watchdog = Watchdog::new(config, detector, locker, gate(), false);

        watchdog.tick(Duration::from_secs(10));
        assert_eq!(watchdog.state().last_lock_at, Some(Duration::from_secs(10)));

        watchdog.tick(Duration::from_secs(14));
        assert_eq!(watchdog.state().last_lock_at, Some(Duration::from_secs(10)));

        watchdog.tick(Duration::from_secs(15));
        assert_eq!(watchdog.state().last_lock_at, Some(Duration::from_secs(15)));
    }

    #[test]
    fn reinsertion_resets_absence_state() {
        let config = AppConfig {
            missing_grace: Duration::ZERO,
            startup_grace: Duration::ZERO,
            ..AppConfig::default()
        };
        let detector = FakeDetector::new(vec![Ok(false), Ok(true)]);
        let locker = FakeLocker::default();
        let mut watchdog = Watchdog::new(config.clone(), detector, locker, gate(), false);

        watchdog.tick(Duration::from_secs(10));
        assert_eq!(watchdog.tick(Duration::from_secs(11)), config.present_poll);
        assert_eq!(watchdog.state(), WatchdogState::default());
    }

    #[test]
    fn fail_safe_detection_error_is_treated_as_missing_key() {
        let config = AppConfig {
            missing_grace: Duration::ZERO,
            startup_grace: Duration::ZERO,
            fail_safe_lock: true,
            ..AppConfig::default()
        };
        let detector = FakeDetector::new(vec![Err("backend unavailable".to_string())]);
        let locker = FakeLocker::default();
        let mut watchdog = Watchdog::new(config, detector, locker, gate(), false);

        watchdog.tick(Duration::from_secs(10));
        assert_eq!(watchdog.state().last_lock_at, Some(Duration::from_secs(10)));
    }

    #[test]
    fn disabled_security_gate_suppresses_locking() {
        let config = AppConfig {
            missing_grace: Duration::ZERO,
            startup_grace: Duration::ZERO,
            ..AppConfig::default()
        };
        let detector = FakeDetector::new(vec![Ok(false)]);
        let locker = FakeLocker::default();
        let mut watchdog = Watchdog::new(
            config.clone(),
            detector,
            locker,
            SecurityGate::new(false, Duration::from_secs(30)),
            false,
        );

        assert_eq!(watchdog.tick(Duration::from_secs(10)), config.present_poll);
        assert_eq!(watchdog.state(), WatchdogState::default());
    }
}
