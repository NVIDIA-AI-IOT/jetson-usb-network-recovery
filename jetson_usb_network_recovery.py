#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Mac-side, standard-library-only recovery for one Jetson USB NCM defect.

Copy this file to the Mac. Python 3.9+ is required; no pip packages are needed.
Default: diagnose only. Run --help for explicitly approved repair/install/undo.
Prototype: physical validation is limited to the combinations documented in README.
"""

import argparse
import base64
import copy
import errno
import fcntl
import getpass
import glob
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import socket
import stat
import subprocess
import sys
import termios
import time
import warnings
import zlib

VERSION = "0.1.1"

# This code is sent over the serial console, not downloaded by the Jetson.
# It also becomes the optional root-owned ExecStartPost helper. Keep all
# configuration-changing operations here so the same guards run at boot.
REMOTE_LIB = r'''
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path("/")
PACKAGE = "39.2.1-20260806224157"
SERVICE = "nv-l4t-usb-device-mode.service"
GADGET = "/sys/kernel/config/usb_gadget/l4t/functions"
START = "/opt/nvidia/l4t-usb-device-mode/nv-l4t-usb-device-mode-start.sh"
HELPER = "/usr/local/lib/jetson-usb-network-recovery/recovery.py"
DROPIN = "/etc/systemd/system/nv-l4t-usb-device-mode.service.d/90-jetson-usb-network-recovery.conf"
MARKER = "# Managed by jetson-usb-network-recovery v0.1.0\n"

def path(name):
    return ROOT / name.lstrip("/")

def read(name):
    try:
        return path(name).read_text().replace("\x00", "").strip()
    except (OSError, UnicodeError):
        return ""

def run(args, check=True):
    p = subprocess.run(args, text=True, capture_output=True, timeout=15,
                       env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    if check and p.returncode:
        raise RuntimeError("Command failed: " + args[0] + ": " + p.stderr.strip()[:300])
    return p

def snapshot():
    model = read("/proc/device-tree/model")
    release = read("/etc/nv_tegra_release")
    package = run(["dpkg-query", "-W", "-f=${Version}", "nvidia-l4t-usb-service"], False).stdout.strip()
    source = read(START)
    branches = all(re.search(
        r'if\s+\[\s+\$\{' + key + r'\}\s+-eq\s+1\s*\];\s*then\s+ifname=[\"\x27]usb0[\"\x27]',
        source) for key in ("enable_rndis", "enable_ecm"))
    iface = read(GADGET + "/ncm.usb0/ifname")
    valid = bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,14}", iface))
    flags = read("/sys/class/net/" + iface + "/flags") if valid else ""
    up = bool(int(flags, 16) & 1) if re.fullmatch(r"0x[0-9a-fA-F]+", flags) else None
    master = ""
    if valid:
        link = path("/sys/class/net/" + iface + "/master")
        if link.is_symlink():
            master = link.resolve().name
    bridge = path("/sys/class/net/l4tbr0/bridge").is_dir()
    addresses = []
    if bridge:
        data = run(["ip", "-j", "-4", "addr", "show", "dev", "l4tbr0"], False)
        try:
            addresses = [a["local"] + "/" + str(a["prefixlen"])
                         for i in json.loads(data.stdout) for a in i.get("addr_info", [])
                         if a.get("family") == "inet"]
        except (ValueError, KeyError, TypeError):
            pass
    service = run(["systemctl", "is-active", SERVICE], False).stdout.strip()
    dropins = run(["systemctl", "show", "-p", "DropInPaths", "--value", SERVICE], False).stdout.split()
    current_user = run(["id", "-un"]).stdout.strip()
    fingerprint = run(["ssh-keygen", "-lf", "/etc/ssh/ssh_host_ed25519_key.pub"], False).stdout.strip()
    s = dict(model=model, release=release, package=package, bad_branches=branches,
             ncm_interface=iface, rndis_interface=read(GADGET + "/rndis.usb0/ifname"),
             interface_exists=bool(valid and path("/sys/class/net/" + iface).is_dir()),
             admin_up=up, master=master, bridge_exists=bridge,
             bridge_addresses=addresses, service=service, user=current_user,
             other_dropins=[p for p in dropins if p != DROPIN],
             host_fingerprint=fingerprint, vendor_script_sha256=hashlib.sha256(source.encode()).hexdigest(),
             installed_helper=path(HELPER).exists(), installed_dropin=path(DROPIN).exists())
    s["classification"], s["reason"] = classify(s)
    return s

def classify(s):
    # No broad "Jetson fix": only the one observed package and script defect.
    if "jetson orin nano" not in s["model"].lower():
        return "unsupported", "Not an identified Jetson Orin Nano."
    if not re.search(r"# R39 .*REVISION:\s*2\.1(?:,|\s|$)", s["release"]):
        return "unsupported", "L4T is not the verified R39.2.1 release."
    if s["package"] != PACKAGE or not s["bad_branches"]:
        return "unsupported", "Package/script does not match the known defect; no workaround will be applied."
    if not s["interface_exists"] or s["admin_up"] is None:
        return "unsupported", "Cannot identify the NCM network interface safely."
    if s["rndis_interface"] != "usb0" or s["ncm_interface"] == "usb0":
        return "unsupported", "USB function mapping differs from the verified defect."
    if not s["bridge_exists"] or s["service"] != "active":
        return "unsupported", "Expected active USB service / l4tbr0 bridge is missing."
    if s["master"] == "l4tbr0" and s["admin_up"]:
        return "healthy", "NCM is already UP and attached to l4tbr0."
    if not s["master"] and s["admin_up"] is False:
        return "affected", "Known defect: NCM is administratively DOWN and has no bridge."
    return "unsupported", "Unexpected interface state or bridge ownership; leaving it unchanged."

def repair_link(s):
    if s["classification"] == "healthy":
        return False
    if s["classification"] != "affected":
        raise RuntimeError(s["reason"])
    iface = s["ncm_interface"]
    run(["ip", "link", "set", "dev", iface, "master", "l4tbr0"])
    try:
        run(["ip", "link", "set", "dev", iface, "up"])
    except Exception:
        # Return to the observed DOWN/unbridged state if the second step fails.
        run(["ip", "link", "set", "dev", iface, "down"], False)
        run(["ip", "link", "set", "dev", iface, "nomaster"], False)
        raise
    return True

def expected_files(source):
    helper = MARKER + source + '\nif __name__ == "__main__":\n    boot_main()\n'
    dropin = MARKER + "[Service]\nExecStartPost=-/usr/bin/python3 " + HELPER + "\n"
    return {HELPER: helper, DROPIN: dropin}

def safe_parents(target):
    # Never install privileged code through symlinks or writable directories.
    for p in reversed(target.parents):
        if not p.exists() and not p.is_symlink():
            continue
        st = p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise RuntimeError("Unsafe privileged directory: " + str(p))

def validate_files(files):
    for name, expected in files.items():
        p = path(name)
        safe_parents(p)
        if p.exists() or p.is_symlink():
            st = p.lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022
                    or p.read_text() != expected):
                raise RuntimeError("Refusing to overwrite/remove a different or modified file: " + name)

def install(files):
    validate_files(files)
    created = []
    try:
        # Helper first, drop-in second. Interrupted installation is repairable
        # by repeating --install with this exact version of the tool.
        for name, content in files.items():
            p = path(name)
            if p.exists():
                continue
            p.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
            safe_parents(p)
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            created.append(p)
            with os.fdopen(fd, "w") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
        run(["systemctl", "daemon-reload"])
    except Exception:
        for p in reversed(created):
            p.unlink()
        run(["systemctl", "daemon-reload"], False)
        raise

def uninstall(files):
    validate_files(files)
    removed = []
    try:
        # Disable the drop-in before removing its helper.
        for name in reversed(list(files)):
            p = path(name)
            if p.exists():
                p.unlink()
                removed.append(name)
        run(["systemctl", "daemon-reload"])
    except Exception:
        # Restore only the exact files removed by this invocation.
        for name in removed:
            p = path(name)
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(files[name])
        run(["systemctl", "daemon-reload"], False)
        raise
    return removed

def execute(request, source):
    action = request["action"]
    before = snapshot()
    if action == "diagnose":
        return {"ok": True, "snapshot": before}
    if os.geteuid() != 0:
        raise RuntimeError("Jetson administrator authorization is required.")
    if "jetson" not in before["model"].lower():
        raise RuntimeError("Refusing changes on an unidentified non-Jetson host.")
    files = expected_files(source)
    if action == "uninstall":
        return {"ok": True, "removed": uninstall(files), "snapshot": snapshot(),
                "message": "Only this tool's persistent files were removed. Live networking is unchanged; reboot later to discard the runtime workaround."}
    if action not in ("repair", "install"):
        raise RuntimeError("Unknown action.")
    if before["ncm_interface"] != request["interface"]:
        raise RuntimeError("NCM interface changed since approval; diagnose again.")
    if before["classification"] not in ("affected", "healthy"):
        raise RuntimeError(before["reason"])
    if action == "install":
        if before.get("other_dropins"):
            raise RuntimeError("Other USB-service drop-ins exist; inspect them before adding a second workaround: " + ", ".join(before["other_dropins"]))
        validate_files(files)
    changed = repair_link(before)
    if action == "install":
        try:
            install(files)
        except Exception as e:
            raise RuntimeError("Persistence installation failed. Live NCM may already be repaired; no USB service was restarted. " + str(e))
    after = snapshot()
    if after["classification"] != "healthy":
        raise RuntimeError("Post-check did not confirm healthy NCM; inspect the device locally.")
    return {"ok": True, "changed": changed, "snapshot": after,
            "message": "NCM link verified. " + ("Boot workaround installed; reboot/cable-reconnect testing is still required." if action == "install" else "Runtime-only recovery; it will not survive USB gadget recreation or reboot.")}

def boot_main():
    # ExecStartPost must not turn a vendor USB-service success into a failure.
    # Re-check package, script, device and ownership on every start.
    try:
        s = snapshot()
        # During ExecStartPost, systemd reports 'activating', not 'active'.
        if s["service"] == "activating":
            s["service"] = "active"
            s["classification"], s["reason"] = classify(s)
        if s["classification"] == "affected":
            repair_link(s)
            print("jetson-usb-network-recovery: repaired NCM bridge/link")
        else:
            print("jetson-usb-network-recovery: no changes: " + s["reason"])
    except Exception as e:
        print("jetson-usb-network-recovery: skipped: " + str(e))
'''


class RecoveryError(Exception):
    pass


def hidden_password(prompt):
    """Never fall back to visible stdin or accept a password through a pipe."""
    try:
        # This stream only displays the prompt; getpass opens its own input TTY.
        # Buffered read/write ("r+") requires seeking, which terminals cannot do.
        with open("/dev/tty", "w") as tty:
            if not tty.isatty():
                raise RecoveryError("A local interactive terminal is required.")
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                value = getpass.getpass(prompt, stream=tty)
    except EOFError as e:
        raise RecoveryError("Password entry cancelled (end of input). No password was sent.") from e
    except (OSError, getpass.GetPassWarning) as e:
        raise RecoveryError("Cannot securely read a password from this terminal. An accessible controlling terminal with echo control is required; password input will not fall back to a pipe or visible input.") from e
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise RecoveryError("Empty passwords or control characters are not supported.")
    return value


def confirm(message):
    print(message)
    return input("Type yes to continue: ").strip().lower() == "yes"


class SerialPort:
    def __init__(self, device):
        self.fd = None
        self.saved = None
        self.exclusive = False
        self.buffer = ""
        if not stat.S_ISCHR(os.stat(device).st_mode):
            raise RecoveryError("The selected port is not a character device.")
        try:
            self.fd = os.open(device, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            # Cooperative lock plus TIOCEXCL. Do not evict another console owner.
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as e:
                # Some devfs implementations do not provide advisory flock.
                if e.errno not in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EINVAL):
                    raise
            fcntl.ioctl(self.fd, termios.TIOCEXCL)
            self.exclusive = True
            self.saved = termios.tcgetattr(self.fd)
            attrs = copy.deepcopy(self.saved)
            attrs[0] = 0
            attrs[1] = 0
            attrs[2] = termios.CS8 | termios.CLOCAL | termios.CREAD
            attrs[3] = 0
            attrs[4] = attrs[5] = termios.B115200
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = 0
            termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        except Exception:
            self.close()
            raise

    def close(self):
        if self.fd is not None:
            try:
                if self.saved is not None:
                    termios.tcsetattr(self.fd, termios.TCSANOW, self.saved)
                if self.exclusive:
                    fcntl.ioctl(self.fd, termios.TIOCNXCL)
            except OSError:
                pass
            os.close(self.fd)
            self.fd = None

    def send(self, data):
        data = data.encode() if isinstance(data, str) else data
        deadline = time.monotonic() + 10
        while data:
            if time.monotonic() > deadline:
                raise RecoveryError("Serial write timed out.")
            if not select.select([], [self.fd], [], 0.2)[1]:
                continue
            try:
                n = os.write(self.fd, data[:256])
                data = data[n:]
            except BlockingIOError:
                continue

    def read_once(self, timeout):
        if not select.select([self.fd], [], [], timeout)[0]:
            return ""
        try:
            raw = os.read(self.fd, 8192)
        except BlockingIOError:
            return ""
        if not raw:
            raise RecoveryError("Serial device disconnected.")
        text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw.decode("utf-8", "replace")).replace("\r", "")
        self.buffer = (self.buffer + text)[-131072:]
        return text

    def expect(self, patterns, timeout=30):
        deadline = time.monotonic() + timeout
        while True:
            for i, pattern in enumerate(patterns):
                m = re.search(pattern, self.buffer, re.M)
                if m:
                    before = self.buffer[:m.start()]
                    self.buffer = self.buffer[m.end():]
                    return i, m, before
            left = deadline - time.monotonic()
            if left <= 0:
                # Deliberately do not print raw serial buffers (may contain secrets).
                raise RecoveryError("Timed out waiting for the expected console response. No raw serial data is logged.")
            self.read_once(min(left, 0.2))


class Console:
    LOGIN = r"^[A-Za-z0-9_.-]+ login: *$"
    PASSWORD = r"^[Pp]assword: *$"
    SHELL = r"^[^\n]{0,200}[#$] *$"

    def __init__(self, port, username, password_reader=hidden_password):
        self.port = port
        self.username = username
        self.password_reader = password_reader
        self.token = "JUNR_" + secrets.token_hex(12)
        self.prompt = self.token + "> "
        self.owned_login = False
        self.subshell = False
        self.at_prompt = False

    def send_password(self, label):
        started = time.monotonic()
        secret = self.password_reader(label)
        try:
            # A login/sudo prompt may expire while the person is typing.
            # Abort rather than sending a password to a different prompt.
            changed = self.port.read_once(0.1)
            if time.monotonic() - started > 40 or changed.strip() or self.port.buffer.strip():
                raise RecoveryError("Password prompt expired or changed. Password was not sent; retry from a fresh console.")
            self.port.send(secret + "\r")
        finally:
            secret = None  # No disk/log persistence; Python cannot promise memory zeroization.

    def login(self):
        self.port.read_once(0.3)
        if re.search(self.PASSWORD, self.port.buffer, re.M):
            raise RecoveryError("Console was already at Password:. Finish/cancel that login manually, then retry.")
        self.port.buffer = ""
        self.port.send("\r")
        i, _, _ = self.port.expect([self.LOGIN, self.SHELL, self.PASSWORD], timeout=20)
        if i == 2:
            raise RecoveryError("Console was already at Password:. Finish/cancel that login manually, then retry.")
        if i == 0:
            self.port.send(self.username + "\r")
            self.port.expect([self.PASSWORD], timeout=10)
            self.send_password("Jetson login password (hidden): ")
            i, _, _ = self.port.expect([r"^Login incorrect", self.LOGIN, self.SHELL], timeout=25)
            if i != 2:
                raise RecoveryError("Jetson login failed. No automatic retries were attempted.")
            self.owned_login = True
        else:
            print("An existing shell is open; it will be checked before any device changes.")
        # Dedicated subshell: no root shell, no shell history for transferred code.
        command = "HISTFILE=/dev/null HISTSIZE=0 PS1=" + shlex.quote(self.prompt) + " /bin/bash --noprofile --norc -i"
        self.port.send(command + "\r")
        self.port.expect([r"^" + re.escape(self.prompt)], timeout=10)
        self.subshell = self.at_prompt = True

    def rpc(self, action="diagnose", interface=""):
        if not self.at_prompt:
            raise RecoveryError("Not at a verified shell prompt.")
        token = "RPC_" + secrets.token_hex(12)
        request = {"action": action, "interface": interface}
        source = REMOTE_LIB + "\ntry:\n    result = execute(" + repr(request) + ", " + repr(REMOTE_LIB) + ")\nexcept Exception as e:\n    result = {'ok': False, 'error': str(e)}\nprint(" + repr(token + "_RESULT:") + "+json.dumps(result), flush=True)\n"
        encoded = base64.b64encode(zlib.compress(source.encode())).decode()
        lines = [encoded[i:i + 160] for i in range(0, len(encoded), 160)]
        receiver = (
            "import sys,base64,zlib;print(" + repr(token + "_READY") + ",flush=True);"
            "data=''.join(sys.stdin.readline().strip() for _ in range(" + str(len(lines)) + "));"
            "exec(compile(zlib.decompress(base64.b64decode(data)),'<jetson-usb-network-recovery>','exec'))"
        )
        command = "/usr/bin/python3 -u -c " + shlex.quote(receiver)
        if action != "diagnose":
            command = "sudo -k -p " + shlex.quote(token + "_SUDO: ") + " -- " + command
        # Short lines avoid the serial terminal's canonical input line limit.
        self.port.buffer = ""
        self.at_prompt = False
        self.port.send(command + "\r")
        patterns = [r"^" + token + r"_READY$", r"^" + token + r"_SUDO: *$",
                    r"^" + re.escape(self.prompt)]
        i, _, _ = self.port.expect(patterns, timeout=15)
        if i == 1:
            if action == "diagnose":
                raise RecoveryError("Unexpected privilege request during diagnosis.")
            self.send_password("Jetson sudo password (hidden): ")
            i, _, _ = self.port.expect(patterns, timeout=15)
        if i != 0:
            raise RecoveryError("Remote Python/sudo did not start. Check Python 3 and sudo access on the Jetson; no retries attempted.")
        for line in lines:
            self.port.send(line + "\r")
            # Drain echoed input and throttle the serial upload slightly.
            self.port.read_once(0.01)
        i, match, _ = self.port.expect([r"^" + token + r"_RESULT:(\{[^\n]*\})$",
                                        r"^" + re.escape(self.prompt)], timeout=90)
        if i == 1:
            self.at_prompt = True
            raise RecoveryError("Remote helper exited without a result. No raw serial output is shown; check the console/Python environment locally.")
        result = json.loads(match.group(1))
        self.port.expect([r"^" + re.escape(self.prompt)], timeout=10)
        self.at_prompt = True
        if not result.get("ok"):
            raise RecoveryError(result.get("error", "Remote action failed."))
        return result

    def close(self):
        try:
            if self.subshell:
                if not self.at_prompt:
                    self.port.send(b"\x03")
                    self.port.expect([r"^" + re.escape(self.prompt)], timeout=3)
                self.port.send("exit\r")
                self.port.expect([self.SHELL], timeout=3)
                if self.owned_login:
                    self.port.send("exit\r")
                    self.port.expect([self.LOGIN], timeout=5)
            elif self.owned_login:
                print("Note: login succeeded but the helper shell did not start. Reconnect locally and log out if needed.")
        except (OSError, RecoveryError):
            print("Note: could not confirm console logout. Reconnect locally and log out if needed.")
        finally:
            self.port.close()


def host_command(args):
    return subprocess.run(args, text=True, capture_output=True, timeout=5).stdout


def check_port_available(device):
    """TIOCEXCL blocks new opens, not all pre-existing readers. Check those too."""
    result = subprocess.run(["/usr/sbin/lsof", "-t", device], text=True,
                            capture_output=True, timeout=5)
    if result.stdout.strip():
        raise RecoveryError("Another process has this serial port open. Close Screen/other serial software yourself, then retry. No process was terminated.")
    if result.returncode not in (0, 1) or result.stderr.strip():
        raise RecoveryError("Could not check existing serial-port users safely. Inspect with lsof before retrying.")


def mac_network_check(snapshot, wait=0):
    """Probe only the Jetson bridge IP through an identified USB interface."""
    if sys.platform != "darwin":
        return False
    addresses = snapshot.get("bridge_addresses", [])
    if not addresses:
        print("No Jetson bridge IPv4 address was reported; no host network probe performed.")
        return False
    networks = []
    for value in addresses:
        addr = ipaddress.ip_interface(value)
        if addr.version == 4 and addr.ip.is_private:
            networks.append(addr)
    deadline = time.monotonic() + wait
    while True:
        ports = host_command(["/usr/sbin/networksetup", "-listallhardwareports"])
        devices = []
        for block in ports.split("\n\n"):
            if re.search(r"Linux for Tegra|NVIDIA", block, re.I):
                m = re.search(r"^Device: (en[0-9]+)$", block, re.M)
                if m:
                    devices.append(m.group(1))
        for device in devices:
            config = host_command(["/sbin/ifconfig", device])
            ips = re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)\b", config)
            for remote in networks:
                if not any(ipaddress.ip_address(x) in remote.network for x in ips):
                    continue
                route = host_command(["/sbin/route", "-n", "get", str(remote.ip)])
                if not re.search(r"\binterface:\s*" + re.escape(device) + r"\s*$", route, re.M):
                    continue
                try:
                    with socket.create_connection((str(remote.ip), 22), timeout=2) as sock:
                        sock.settimeout(2)
                        banner = sock.recv(256)
                    if banner.startswith(b"SSH-"):
                        print("Mac USB network: " + device + " has " + ", ".join(ips))
                        print("SSH service reached at " + str(remote.ip) + ":22 over that USB interface.")
                        print("No SSH login, host-key acceptance, SSH-key setup, or Wi-Fi configuration was performed.")
                        return True
                except OSError:
                    pass
        if time.monotonic() >= deadline:
            print("Mac USB DHCP / SSH reachability is NOT yet verified. Keep DHCP automatic; inspect Linux for Tegra and renew its lease if needed.")
            print("If macOS Terminal can reach SSH but the app cannot, check the app's Local Network permission separately.")
            return False
        time.sleep(1)


def print_snapshot(s):
    for title, key in [("Device", "model"), ("L4T", "release"), ("USB package", "package"),
                       ("NCM interface", "ncm_interface"), ("Administrative UP", "admin_up"),
                       ("Bridge", "master"), ("USB service", "service"),
                       ("Classification", "classification"), ("Reason", "reason")]:
        print(title + ": " + str(s.get(key, "")))
    print("Persistent helper/drop-in: " + str(s.get("installed_helper")) + "/" + str(s.get("installed_dropin")))
    if s.get("other_dropins"):
        print("Other USB-service drop-ins (persistent installation will refuse): " + ", ".join(s["other_dropins"]))
    if s.get("host_fingerprint"):
        print("Jetson ED25519 host fingerprint (from the physical console): " + s["host_fingerprint"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--port", help="Jetson USB serial device; otherwise list /dev/cu.usbmodem* and confirm")
    parser.add_argument("--user", default="jetson", help="Jetson login username (default: jetson)")
    parser.add_argument("--list-ports", action="store_true", help="List candidate ports without opening them")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--diagnose", action="store_const", dest="action", const="diagnose", help="Inspect only (default)")
    group.add_argument("--repair", action="store_const", dest="action", const="repair", help="Repair the live NCM link only, after approval")
    group.add_argument("--install", action="store_const", dest="action", const="install", help="Repair and install a guarded boot workaround, after approval")
    group.add_argument("--uninstall", action="store_const", dest="action", const="uninstall", help="Remove this version's persistent files; leave live networking unchanged")
    parser.set_defaults(action="diagnose")
    args = parser.parse_args(argv)
    if sys.platform != "darwin":
        parser.error("This prototype's host CLI supports macOS only. Linux is used for automated tests, not physical-device operation.")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", args.user):
        parser.error("Unsupported username syntax.")
    ports = sorted(glob.glob("/dev/cu.usbmodem*"))
    if args.list_ports:
        print("\n".join(ports) if ports else "No /dev/cu.usbmodem* ports found.")
        return 0
    if not sys.stdin.isatty():
        raise RecoveryError("Run this interactively in a local Mac terminal; do not pipe a password or this script into Python.")
    device = args.port
    if device is None:
        if len(ports) != 1:
            print("Candidate ports: " + (", ".join(ports) or "none"))
            raise RecoveryError("Connect only the intended Jetson, or select its console with --port. A port is never chosen arbitrarily.")
        device = ports[0]
    if not re.fullmatch(r"/dev/cu\.[A-Za-z0-9_.-]+", device):
        raise RecoveryError("Expected a Mac /dev/cu.* serial device.")
    print("jetson-usb-network-recovery " + VERSION + " (prototype)")
    if not confirm("Open " + device + " as " + args.user + "? Confirm this is the intended Jetson's console, and close Screen/other serial programs first."):
        return 0
    check_port_available(device)
    port = SerialPort(device)
    console = Console(port, args.user)
    try:
        print("Waiting for the Jetson console (up to 20 seconds)...")
        console.login()
        print("Inspecting the Jetson; no network or service settings are being changed...")
        result = console.rpc()
        s = result["snapshot"]
        print_snapshot(s)
        if s["user"] != args.user or "jetson" not in s["model"].lower():
            raise RecoveryError("Console identity does not match the requested Jetson user/device. No configuration changes made.")
        if args.action != "diagnose":
            if args.action != "uninstall" and s["classification"] not in ("affected", "healthy"):
                raise RecoveryError("Outside this tool's repair scope. " + s["reason"])
            if args.action == "repair" and s["classification"] == "healthy":
                print("Already healthy; no changes needed.")
            else:
                descriptions = {
                    "repair": "Attach the identified NCM interface to l4tbr0 and bring it UP. This is temporary.",
                    "install": "Repair NCM now and add TWO root-owned files: a guarded helper under /usr/local/lib/jetson-usb-network-recovery/ and a 90-jetson-usb-network-recovery.conf USB-service drop-in. Vendor files stay unchanged. systemd will reload configuration, NOT restart USB.",
                    "uninstall": "Remove only this tool version's unchanged helper and drop-in. Keep the live USB link UP; reboot later to discard the runtime workaround.",
                }
                if not confirm(descriptions[args.action] + " No reboot, USB-service restart, static IP, Wi-Fi or SSH setup will be performed."):
                    return 0
                result = console.rpc(args.action, s["ncm_interface"])
                s = result["snapshot"]
                print(result["message"])
                print_snapshot(s)
        reachable = mac_network_check(s, wait=20 if args.action in ("repair", "install") else 0)
        if args.action == "install":
            print("Still required: manually reboot, reconnect USB, then run --diagnose again. A successful live repair is NOT proof of reboot persistence.")
        return 0 if reachable else 2
    finally:
        console.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nCancelled. If a change was already applied it is not silently undone; run --diagnose to inspect.", file=sys.stderr)
        sys.exit(130)
    except (RecoveryError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("Error: " + str(exc), file=sys.stderr)
        sys.exit(1)
