# Threat Model

This document describes what YubiWatch is designed to help with and what remains out of scope.

## Assets

- The unlocked Windows session
- The watchdog startup path
- The configured trusted YubiKey product IDs
- The command PIN verifier file
- The local dashboard control path
- The Secure Mode module configuration
- The local audit log

## In Scope

YubiWatch helps when:

- the laptop is left unlocked and the configured key is removed
- someone tries to use the supported dashboard enable path without the key
- USB detection fails and fail-safe mode is enabled
- another Yubico product ID is added through the dashboard without the original key present
- someone tries to arm or disarm through the dashboard without both the configured key and command PIN
- someone tries to reset the command PIN without physical key presence and an explicit lock-first confirmation
- someone tries to change Secure Mode or module policy without the key and PIN

## Out Of Scope

YubiWatch does not fully protect against:

- Windows administrators
- offline disk edits
- disabling Task Scheduler entries with sufficient rights
- replacing the executable or config files
- booting another operating system
- sophisticated malware running as the user or admin
- attacks that require cryptographic proof of a unique physical key
- a person who already controls the signed-in Windows account and can modify the app's files or local profile data

## Trust Model

Current device trust is based on Yubico USB vendor/product IDs. This is
convenient and fast, but it is not a cryptographic identity check.

The command PIN is a local command authorization factor, not a Windows account
credential. It is stored as a salted verifier and rate-limited by the running
process.

Secure Mode module state is configuration, not magic enforcement. Modules marked
policy-ready need a Windows service or enterprise policy backend before they can
stop admin-level or kernel-level activity.

## Future Hardening

- Windows service installation with restricted ACLs
- service recovery policy
- code signing
- event-driven USB notifications
- PIV/FIDO challenge for enable and add-device flows
- serial-number-based key identity if a reliable local API is added
- service-backed USB, app, network, data, clipboard, and tamper enforcement
