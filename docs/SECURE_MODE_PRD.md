# Protected Mode PRD

## Vision

YubiWatch should provide a defence-style secure laptop mode that turns a normal
Windows endpoint into a controlled, observable, and reversible workstation for
sensitive work.

This is an endpoint hardening prototype. It is not an official government
system, a classified environment, or a replacement for enterprise security.

## Product Principles

- User-controllable: the user can see and change the posture from the dashboard.
- Reversible: every module has a safe off path.
- Modular: each protection is represented as an independent module.
- Auditable: security actions are written to structured local Recent Activity.
- Safe by default: deep OS controls stay disabled until a service-backed
  enforcement path exists.

## Protected Mode Behaviour

When Protected Mode is started, enabled modules become active where enforcement
is available. The existing security-key laptop lock is the first active
enforcement module. Other modules are represented as preview modules so they can
be toggled, reviewed, and wired to deeper Windows controls later.

When Protected Mode stops, YubiWatch turns protection off, persists Protected
Mode as off, and returns the laptop to normal behaviour.

## Modules

| Module | Current capability | Notes |
| --- | --- | --- |
| Sign-In & Access | Active | Security key plus Security PIN protects dashboard commands. |
| Devices | Preview | Safe module state exists; deep USB blocking needs admin/service backend. |
| Network | Preview | Intended for firewall/profile enforcement later. |
| Apps | Preview | Intended for allowlist enforcement later. |
| Files | Preview | Intended for sensitive-path and sync-tool controls later. |
| Copy & Paste | Preview | Intended for clipboard and remote-transfer controls later. |
| Laptop Session | Active | Locks the workstation when the key is removed while protection is on. |
| Safety Checks | Preview | Dashboard policy changes are logged; deeper tamper detection is future work. |
| Activity | Active | Structured local JSON Lines activity stream. |
| Health | Active | Dashboard score, posture, and risk gaps. |

## Safety Requirements

Protected Mode changes require the configured security key and Security PIN.
This avoids quiet browser-only changes from an unlocked session.

The framework avoids permanent lockout states. The forgotten-PIN recovery path
locks Windows first, then turns protection off and clears the PIN verifier. Administrative
recovery remains possible by editing `.env` from an authenticated Windows
session.

## Success Criteria

- Dashboard shows all modules, posture, warnings, and recent activity.
- Users can toggle modules independently.
- Protected Mode can be started and stopped safely.
- Active controls remain usable and reversible.
- Preview modules do not pretend to enforce deep OS controls before the
  backend exists.
