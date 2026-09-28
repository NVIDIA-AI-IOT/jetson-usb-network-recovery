# jetson-usb-network-recovery

A narrowly scoped **prototype** for recovering a Jetson Orin Nano's USB network
from a Mac, even when SSH and internet access are unavailable on the Jetson.

Copy `jetson_usb_network_recovery.py` and the accompanying [LICENSE](LICENSE)
to the Mac. The script uses the
Python standard library; Screen, pip packages and a clone on the Jetson are not
required. Python **3.9 or later** must already be available on the Mac, and
`/usr/bin/python3` must be present on the Jetson.

User-provided Mac/Jetson test output confirms diagnosis, temporary repair,
installation, and healthy USB networking after a full reboot on one R39.2.1
device. Broader validation remains incomplete; see [validation](docs/validation.md).
Linux tests are not substitutes for testing other physical combinations.

This is a **private development prototype**, not a public or approved NVIDIA
release. OSRB review and public-release approval are pending; this
repository does not claim that review has been completed.

Version **0.1.1** fixes a password-entry bug in 0.1.0: opening `/dev/tty` in
buffered read/write mode failed on a non-seekable terminal, before diagnosis or
repair. Copy the updated Python file to the Mac before retrying. The Jetson-side
helper and repair logic are unchanged.

## Scope

The recorded defect occurred with:

- Jetson Orin Nano Developer Kit, L4T R39.2.1.
- `nvidia-l4t-usb-service` version `39.2.1-20260806224157`.
- Both the RNDIS and ECM/NCM setup branches hardcode `ifname="usb0"`.
- RNDIS actually uses `usb0`; NCM uses a different interface, which is left
  administratively DOWN and outside `l4tbr0`.
- macOS detects “Linux for Tegra” but cannot obtain a USB IPv4 lease.

The tool checks the device, version, script pattern, USB function mapping,
service, interface state and bridge ownership. It refuses repairs outside this
scope. It does not implement a general USB, DHCP, SSH or Wi-Fi repair system.
An already-UP NCM interface in `l4tbr0` is not treated as broken.

## Mac: first test

1. Complete Ubuntu's first-run setup on the Jetson and allow it to reboot.
2. Connect its USB device-mode port to the Mac with a data-capable cable.
3. Close Screen and any other programs using the USB serial console.
4. Save the Python file, for example in `~/Downloads`.
5. In a local Mac terminal, check Python and run **diagnosis first**:

```bash
python3 --version
cd ~/Downloads
python3 jetson_usb_network_recovery.py --list-ports
python3 jetson_usb_network_recovery.py --diagnose
```

Do not pipe the script or a password into Python. The script asks you to confirm
the serial port, then enter the Jetson password locally with echo disabled. It
does not accept a password through a flag, environment variable or file.
The first confirmation opens the serial console only. Even with `--repair` or
`--install`, configuration changes require a separate confirmation after diagnosis.

Password entry needs a controlling terminal with echo control. An integrated
terminal is not rejected just because it is integrated, but its actual terminal
and serial-device permissions must work. Missing terminal access or echo control
stops the script rather than falling back to visible or piped password input.

The default username is `jetson`. For another username or multiple serial ports:

```bash
python3 jetson_usb_network_recovery.py --port /dev/cu.usbmodemYOUR_DEVICE --user YOUR_USER --diagnose
```

Replace both placeholders; device names are not constant. Port enumeration alone
does not prove which physical device is attached: confirm the intended Jetson.

If opening the serial device reports **Permission denied**, check its ownership
and access rights. macOS administrator permission and Jetson administrator
permission are separate. If your Mac requires elevation, launch this reviewed
local script with `sudo python3 ...`; that will ask for the **Mac administrator's**
password first. A standard Mac account is not necessarily allowed to use sudo.
Do not change device permissions broadly or run a downloaded pipe as root.

### Runtime-only repair

```bash
python3 jetson_usb_network_recovery.py --repair
```

After showing the diagnosis, this asks for explicit confirmation and Jetson
sudo authentication. It attaches the **actual NCM interface** to `l4tbr0` and
brings it UP. It does not assume the interface is named `usb1`.

This change does **not** survive USB gadget recreation or reboot.

### Persistent repair for recording preparation

After reviewing the diagnosis, use:

```bash
python3 jetson_usb_network_recovery.py --install
```

This repairs the live link and installs exactly these root-owned files:

```text
/usr/local/lib/jetson-usb-network-recovery/recovery.py
/etc/systemd/system/nv-l4t-usb-device-mode.service.d/90-jetson-usb-network-recovery.conf
```

The drop-in runs a guarded `ExecStartPost` helper after the vendor USB setup.
It resolves the NCM interface each time and rechecks the affected package and
script. If an update changes the version or fixes the script, it skips the
workaround. It does not overwrite vendor files or unrelated drop-ins. A
different/modified file at one of its own paths causes an error, not replacement.
If other USB-service drop-ins already exist, persistent installation refuses
until they have been inspected; it does not stack another workaround blindly.

The tool reloads systemd configuration but **never restarts the USB service or
reboots**. Restarting USB can also disconnect the serial console. After the tool
has exited, manually reboot the Jetson, reconnect USB and repeat `--diagnose`.
Keep macOS DHCP automatic; confirm it still obtains an address and reaches SSH.

### Uninstall / rollback

```bash
python3 jetson_usb_network_recovery.py --uninstall
```

After approval, removes only this version's unchanged helper/drop-in and reloads
systemd. Other files, including vendor files and existing workarounds, are left
alone. Live networking is deliberately preserved. A later reboot discards the
runtime change; on an unfixed system the original fault may then return.

Keep the same Python file used to install the workaround for uninstalling it.
Empty parent directories are not removed. If a persistent file was edited,
automatic uninstall refuses to delete it; inspect it manually instead.

## What is verified, and what is not

The Mac-side probe checks only reported Jetson bridge addresses, through a
“Linux for Tegra”/NVIDIA network interface with a matching route and subnet. It
reads an SSH banner from port 22. It does not perform an SSH login or accept a
host key. A matching IPv4 address alone does not establish that it came from
DHCP: leave the Mac's service set to automatic DHCP and confirm its settings.

Exit status:

- `0`: USB-path SSH banner verified, or the operation was cancelled before action.
- `1`: an error, unsupported repair, or authentication/console failure.
- `2`: inspection/action completed but Mac USB-path SSH reachability was not verified.
- `130`: interrupted. A change already applied is not silently reversed.

The trusted physical console's ED25519 host fingerprint is printed when readable.
Compare it against the first SSH connection prompt. This tool does not edit
`known_hosts`, create keys, configure key login, connect Wi-Fi, install Codex or
install Skills. Those actions can remain part of the F1–F10 recording.

If Terminal reaches SSH but the desktop app does not, investigate that app's
Local Network permission separately; this tool does not change macOS privacy
permissions. A denied serial-device permission is another separate issue.

“Inspect only” means no network/service/configuration changes. Normal login and
diagnostic commands can still produce system authentication/audit records.
Passwords are not logged or written to disk by this tool. They exist transiently
in process memory; Python does not guarantee secure memory erasure.

## Physical acceptance checklist

- [x] Recording pair and Jetson package version recorded; exact Mac version was user-reported, not independently queried.
- [x] Diagnostic mode identifies the known defect without modifying configuration.
- [ ] Wrong password stops without repeated login attempts or printing the secret.
- [ ] Concurrent serial-console use is avoided; unknown prompts fail closed.
- [x] Repair produces Mac USB IPv4 and SSH reachability without assigning a static IP; a DHCP lease trace was not collected by the tool.
- [ ] Repeated repair leaves healthy interfaces unchanged.
- [x] Persistent repair survives a full reboot, verified with diagnosis only.
- [ ] Separate USB cable reconnection test after persistent installation.
- [ ] Windows RNDIS still works after repair (regression check).
- [ ] Uninstall removes only the owned files and preserves the current connection.
- [ ] Unsupported/fixed systems are not modified.

## Development on X299

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile jetson_usb_network_recovery.py
```

Tests use simulated target files/commands and Linux pseudo-terminals, never the
real host network or systemd configuration. Password tests open a real controlling
pseudo-terminal and exercise hidden input, restoration of echo after success,
EOF and Ctrl-C, and refusal of piped input without a controlling terminal.
The host CLI intentionally refuses
physical operation on non-macOS hosts. The private development repository is
[chitoku/jetson-usb-network-recovery](https://github.com/chitoku/jetson-usb-network-recovery).
Do not make it public or distribute it as an approved release before the separate
review process. This repository contains no real credentials or raw serial logs.

## References

- [Python termios](https://docs.python.org/3/library/termios.html)
- [Python getpass](https://docs.python.org/3/library/getpass.html)
- [systemd service configuration](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)

## License and contributions

This project is licensed under the [Apache License 2.0](LICENSE).
Keep the license and copyright notices with any copy you distribute.
See [third-party software and distribution scope](THIRD_PARTY_NOTICES.md) for
information about independently installed runtime prerequisites.

External contributions are welcome. All contributions must include DCO sign-off;
see [CONTRIBUTING.md](CONTRIBUTING.md) for the requirements and full certificate.
