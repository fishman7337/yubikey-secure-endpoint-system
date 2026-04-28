//! Runtime security gate for dashboard-controlled enforcement.
//!
//! Native protection starts from the configured startup policy. Dashboard
//! controls can enable enforcement only after the configured key is detected;
//! disabling is immediate so protection stays out of the user's way unless they
//! deliberately keep it enabled.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Decision returned to the watchdog after observing the latest key state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardDecision {
    /// The watchdog should enforce normal locking behavior.
    Enforce,
    /// The watchdog should skip lock enforcement for this tick.
    SuppressLock,
}

/// User-facing stage of the legacy disable proof ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofStage {
    /// The dashboard is waiting for the key to be removed.
    WaitingForRemoval,
    /// The key was removed and the dashboard is waiting for reinsertion.
    WaitingForReinsert,
}

/// Snapshot of dashboard-visible protection state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardSnapshot {
    /// Whether lock enforcement is currently active.
    pub enabled: bool,
    /// Active disable-proof stage, if any.
    pub proof_stage: Option<ProofStage>,
    /// Approximate seconds remaining before the active proof expires.
    pub proof_seconds_remaining: Option<u64>,
}

#[derive(Clone, Debug)]
struct DisableProof {
    stage: ProofStage,
    deadline: Instant,
}

#[derive(Clone, Debug)]
struct GateState {
    enabled: bool,
    proof: Option<DisableProof>,
}

/// Shared runtime gate used by both the watchdog loop and dashboard server.
#[derive(Clone, Debug)]
pub struct SecurityGate {
    inner: Arc<Mutex<GateState>>,
    disable_proof_timeout: Duration,
}

impl SecurityGate {
    /// Creates a new runtime gate.
    pub fn new(enabled: bool, disable_proof_timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(GateState {
                enabled,
                proof: None,
            })),
            disable_proof_timeout,
        }
    }

    /// Starts the physical-key disable ceremony.
    ///
    /// The key must be present when the ceremony starts. The user must then
    /// remove and reinsert it before the timeout expires.
    pub fn start_disable_proof(&self, key_present: bool) -> Result<GuardSnapshot, String> {
        self.start_disable_proof_at(key_present, Instant::now())
    }

    /// Enables lock enforcement and cancels any active legacy proof ceremony.
    pub fn enable(&self) -> GuardSnapshot {
        let mut state = self.lock_state();
        state.enabled = true;
        state.proof = None;
        snapshot_from_state(&state, Instant::now())
    }

    /// Disables lock enforcement and cancels any active legacy proof ceremony.
    pub fn disable(&self) -> GuardSnapshot {
        let mut state = self.lock_state();
        state.enabled = false;
        state.proof = None;
        snapshot_from_state(&state, Instant::now())
    }

    /// Applies the latest key state and returns the current enforcement decision.
    pub fn observe_key_state(&self, key_present: bool) -> GuardDecision {
        self.observe_key_state_at(key_present, Instant::now())
    }

    /// Returns a dashboard-safe snapshot of the current protection state.
    pub fn snapshot(&self) -> GuardSnapshot {
        let mut state = self.lock_state();
        expire_proof_if_needed(&mut state, Instant::now());
        snapshot_from_state(&state, Instant::now())
    }

    fn start_disable_proof_at(
        &self,
        key_present: bool,
        now: Instant,
    ) -> Result<GuardSnapshot, String> {
        if !key_present {
            return Err(
                "The configured security key must be present to start disable proof.".to_string(),
            );
        }

        let mut state = self.lock_state();
        state.enabled = true;
        state.proof = Some(DisableProof {
            stage: ProofStage::WaitingForRemoval,
            deadline: now + self.disable_proof_timeout,
        });
        Ok(snapshot_from_state(&state, now))
    }

    fn observe_key_state_at(&self, key_present: bool, now: Instant) -> GuardDecision {
        let mut state = self.lock_state();
        expire_proof_if_needed(&mut state, now);

        if let Some(proof) = &mut state.proof {
            match (proof.stage, key_present) {
                (ProofStage::WaitingForRemoval, false) => {
                    proof.stage = ProofStage::WaitingForReinsert;
                    return GuardDecision::SuppressLock;
                }
                (ProofStage::WaitingForReinsert, true) => {
                    state.enabled = false;
                    state.proof = None;
                    return GuardDecision::SuppressLock;
                }
                _ => return GuardDecision::SuppressLock,
            }
        }

        if state.enabled {
            GuardDecision::Enforce
        } else {
            GuardDecision::SuppressLock
        }
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn expire_proof_if_needed(state: &mut GateState, now: Instant) {
    if state
        .proof
        .as_ref()
        .is_some_and(|proof| now >= proof.deadline)
    {
        state.proof = None;
        state.enabled = true;
    }
}

fn snapshot_from_state(state: &GateState, now: Instant) -> GuardSnapshot {
    GuardSnapshot {
        enabled: state.enabled,
        proof_stage: state.proof.as_ref().map(|proof| proof.stage),
        proof_seconds_remaining: state
            .proof
            .as_ref()
            .map(|proof| proof.deadline.saturating_duration_since(now).as_secs()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_proof_requires_present_key_to_start() {
        let gate = SecurityGate::new(true, Duration::from_secs(30));
        assert!(gate.start_disable_proof(false).is_err());
        assert!(gate.snapshot().enabled);
    }

    #[test]
    fn remove_and_reinsert_disables_guard() {
        let now = Instant::now();
        let gate = SecurityGate::new(true, Duration::from_secs(30));

        gate.start_disable_proof_at(true, now).unwrap();
        assert_eq!(
            gate.observe_key_state_at(false, now + Duration::from_secs(1)),
            GuardDecision::SuppressLock
        );
        assert_eq!(
            gate.observe_key_state_at(true, now + Duration::from_secs(2)),
            GuardDecision::SuppressLock
        );

        let snapshot = gate.snapshot();
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.proof_stage, None);
    }

    #[test]
    fn proof_timeout_keeps_guard_enabled() {
        let now = Instant::now();
        let gate = SecurityGate::new(true, Duration::from_secs(30));

        gate.start_disable_proof_at(true, now).unwrap();
        assert_eq!(
            gate.observe_key_state_at(false, now + Duration::from_secs(31)),
            GuardDecision::Enforce
        );

        let snapshot = gate.snapshot();
        assert!(snapshot.enabled);
        assert_eq!(snapshot.proof_stage, None);
    }

    #[test]
    fn enable_cancels_disable_proof() {
        let gate = SecurityGate::new(true, Duration::from_secs(30));
        gate.start_disable_proof(true).unwrap();

        let snapshot = gate.enable();
        assert!(snapshot.enabled);
        assert_eq!(snapshot.proof_stage, None);
    }

    #[test]
    fn disable_cancels_disable_proof() {
        let gate = SecurityGate::new(true, Duration::from_secs(30));
        gate.start_disable_proof(true).unwrap();

        let snapshot = gate.disable();
        assert!(!snapshot.enabled);
        assert_eq!(snapshot.proof_stage, None);
    }
}
