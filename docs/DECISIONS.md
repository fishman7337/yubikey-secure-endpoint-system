# Architecture Decisions

## Use Rust As Primary Runtime

Rust is the primary implementation because YubiWatch is always-on, local, and security-adjacent. A native executable avoids Python interpreter overhead and virtual environment dependency.

## Keep Python As Fallback

The Python implementation remains useful as a readable reference and fallback while the Rust implementation matures.

## Use Localhost Dashboard Only

The dashboard binds to `127.0.0.1` to avoid creating a network administration surface.

## Use Product-ID Trust For Now

YubiWatch currently trusts Yubico vendor/product IDs. This is simple and works with Windows SetupAPI hardware IDs, but it is not a unique-key identity mechanism.

## Require Original Key To Add Devices

Adding another product ID requires the original configured key to be present. This reduces accidental trust expansion and matches the key-gated enable policy.

## Avoid Disk Logs By Default

The original version produced very large logs. The native runtime avoids disk logs by default to prevent storage growth and activity leakage.

## Prefer Explicit Recovery Over Absolute Claims

YubiWatch documents recovery and hard limits because a user-mode process cannot be tamper-proof against administrators or offline edits.
