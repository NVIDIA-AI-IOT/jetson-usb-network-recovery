# Validation record

## 2026-09-16: user-operated Mac / Jetson test

The following results come from terminal output supplied by the user, not from
an agent-controlled Mac session. They apply to this tested combination only.
No credentials, host fingerprints, serial numbers, or corporate-network IPs
are included here.

- Script: **0.1.1**, copied as a standalone Python file.
- Mac: MacBook Air; macOS Tahoe 26.6.2 was reported by the user in this setup
  discussion, not independently queried during this test.
- Jetson: `NVIDIA Jetson Orin Nano Engineering Reference Developer Kit Super`.
- L4T: R39, revision 2.1; `nvidia-l4t-usb-service` **39.2.1-20260806224157**.
- Actual NCM network interface on this device: `usb1`.

| Stage | Observed result |
| --- | --- |
| `--diagnose` before repair | Hidden login prompt worked. NCM admin UP was false, bridge membership empty, USB service active, classification affected, helper/drop-in false/false. |
| `--repair` | Separate change confirmation and hidden sudo prompt. NCM became UP in l4tbr0, classification healthy. Mac USB interface had an IPv4 address and the SSH banner was reached through that interface. |
| `--install` | Separate approval, helper/drop-in true/true, live USB-path SSH reachability preserved. No tool-initiated reboot or USB-service restart. |
| Full reboot, then `--diagnose` only | NCM remained UP in l4tbr0, classification healthy, helper/drop-in true/true, Mac USB IPv4 and SSH reachability confirmed. No repeat repair was needed. |

The tool displayed the ED25519 fingerprint through the trusted serial console.
A later manual SSH attempt showed the same fingerprint but an obsolete
`known_hosts` entry from the shared USB IP. That is a separate trust-record
issue: the recovery tool did not alter host keys or known-hosts entries.

The tool never assigned a static IP on the Mac. Its reachability check observes
addresses, subnet, route and an SSH banner, not a DHCP packet trace. It does not
establish successful SSH user authentication or key-based login.

## Password-input regression

Version 0.1.0 attempted buffered read/write `open('/dev/tty', 'r+')`, which
requires seeking and failed before diagnosis or repair. Version 0.1.1 opens a
write-only prompt stream and lets `getpass` handle terminal input and echo.
The non-echoing login and sudo paths both completed in the user-operated test.

X299 automated validation: **40 tests passed** on September 16. Tests include
real controlling pseudo-terminal hidden input, restored terminal state after
success/EOF/Ctrl-C, failure without a controlling terminal or echo control,
simulated serial authentication, change approvals' remote state guards,
configuration-file ownership/rollback, and scoped network probes.
They use synthetic credentials and simulated target commands, not real repair
operations on the X299 host or an attached Jetson.

## Still to validate physically

- USB cable reconnect as a distinct test (do not assume the reboot log proves it).
- Windows RNDIS after the new persistent repair.
- Wrong-password, serial-owner conflict and expired-prompt paths.
- Repeating repair on a healthy device.
- Uninstall and subsequent reboot; verify vendor files and other drop-ins remain.
- Updated/fixed and unsupported device/software combinations are safely refused.
- Other Mac/Python versions and integrated-terminal permission configurations.

The successful reboot test is not proof of all acceptance criteria, a vendor
fix, or production readiness. Open-source release approval does not expand the
physical validation coverage recorded here.
