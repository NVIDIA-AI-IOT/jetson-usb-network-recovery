# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import shlex
import tempfile
import termios
import threading
import time
import unittest
from unittest import mock
import warnings

SCRIPT = Path(__file__).resolve().parents[1] / "jetson_usb_network_recovery.py"
spec = importlib.util.spec_from_file_location("recovery", SCRIPT)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def affected():
    return dict(model="NVIDIA Jetson Orin Nano Developer Kit", release="# R39 (release), REVISION: 2.1, GCID: 46758480",
                package="39.2.1-20260806224157", bad_branches=True, ncm_interface="usb1",
                rndis_interface="usb0", interface_exists=True, admin_up=False, master="",
                bridge_exists=True, service="active", bridge_addresses=["192.168.55.1/24"], user="jetson")


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.ns = {}
        exec(r.REMOTE_LIB, self.ns)
        self.calls = []
        self.ns["run"] = self.run_command

    def run_command(self, args, check=True):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    def test_classify_known_defect(self):
        self.assertEqual(self.ns["classify"](affected())[0], "affected")

    def test_classify_healthy(self):
        s = affected()
        s.update(master="l4tbr0", admin_up=True)
        self.assertEqual(self.ns["classify"](s)[0], "healthy")

    def test_unsupported_cases(self):
        for key, value in [("model", "NVIDIA Jetson AGX Thor"), ("package", "39.2.1-new"),
                           ("release", "# R36 (release), REVISION: 4.4,"), ("bad_branches", False),
                           ("master", "br-other"), ("admin_up", True), ("bridge_exists", False),
                           ("interface_exists", False), ("ncm_interface", "usb0"),
                           ("rndis_interface", "other"), ("service", "inactive")]:
            with self.subTest(key=key):
                s = affected()
                s[key] = value
                self.assertEqual(self.ns["classify"](s)[0], "unsupported")

    def test_repairs_actual_interface_only(self):
        s = affected()
        s.update(ncm_interface="usb8", classification="affected")
        self.assertTrue(self.ns["repair_link"](s))
        self.assertEqual(self.calls, [["ip", "link", "set", "dev", "usb8", "master", "l4tbr0"],
                                      ["ip", "link", "set", "dev", "usb8", "up"]])

    def test_healthy_noop(self):
        self.assertFalse(self.ns["repair_link"]({"classification": "healthy"}))
        self.assertEqual(self.calls, [])

    def test_second_step_failure_restores_original_link(self):
        def fail(args, check=True):
            self.calls.append(args)
            if args[-1] == "up":
                raise RuntimeError("simulated failure")
        self.ns["run"] = fail
        s = affected()
        s["classification"] = "affected"
        with self.assertRaises(RuntimeError):
            self.ns["repair_link"](s)
        self.assertEqual(self.calls[-2:], [["ip", "link", "set", "dev", "usb1", "down"],
                                          ["ip", "link", "set", "dev", "usb1", "nomaster"]])

    def test_diagnose_never_installs_or_repairs(self):
        self.ns["snapshot"] = lambda: affected()
        self.ns["repair_link"] = mock.Mock(side_effect=AssertionError("mutation"))
        self.ns["install"] = mock.Mock(side_effect=AssertionError("mutation"))
        result = self.ns["execute"]({"action": "diagnose"}, r.REMOTE_LIB)
        self.assertTrue(result["ok"])
        self.assertEqual(self.calls, [])

    def test_guard_rechecked_after_approval(self):
        s = affected()
        s["classification"] = "affected"
        self.ns["snapshot"] = lambda: s
        with mock.patch("os.geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "changed since approval"):
                self.ns["execute"]({"action": "repair", "interface": "usb2"}, r.REMOTE_LIB)
        self.assertEqual(self.calls, [])

    def test_existing_workaround_blocks_persistent_install_before_mutation(self):
        s = affected()
        s.update(classification="affected", other_dropins=["/etc/systemd/system/test.conf"])
        self.ns["snapshot"] = lambda: s
        with mock.patch("os.geteuid", return_value=0):
            with self.assertRaisesRegex(RuntimeError, "Other USB-service drop-ins"):
                self.ns["execute"]({"action": "install", "interface": "usb1"}, r.REMOTE_LIB)
        self.assertEqual(self.calls, [])

    def test_boot_rechecks_updated_package(self):
        s = affected()
        s.update(package="updated", classification="unsupported", reason="updated")
        self.ns["snapshot"] = lambda: s
        with contextlib.redirect_stdout(io.StringIO()):
            self.ns["boot_main"]()
        self.assertEqual(self.calls, [])

    def test_boot_activating_service_is_expected(self):
        s = affected()
        s.update(service="activating", classification="unsupported", reason="not active")
        self.ns["snapshot"] = lambda: s
        with contextlib.redirect_stdout(io.StringIO()):
            self.ns["boot_main"]()
        self.assertEqual(len(self.calls), 2)

    def test_payload_and_installed_helper_compile(self):
        files = self.ns["expected_files"](r.REMOTE_LIB)
        compile(files[self.ns["HELPER"]], "helper", "exec")
        dropin = files[self.ns["DROPIN"]]
        self.assertIn("ExecStartPost=-/usr/bin/python3", dropin)
        self.assertNotIn("restart", dropin)

    def test_target_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            self.ns["ROOT"] = Path(root)
            def put(name, text):
                p = self.ns["path"](name)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text)
            put("/proc/device-tree/model", "NVIDIA Jetson Orin Nano Developer Kit\0")
            put("/etc/nv_tegra_release", "# R39 (release), REVISION: 2.1, GCID: test")
            put(self.ns["START"], 'if [ ${enable_rndis} -eq 1 ]; then\n    ifname="usb0"\nfi\nif [ ${enable_ecm} -eq 1 ]; then\n    ifname="usb0"\nfi\n')
            put(self.ns["GADGET"] + "/ncm.usb0/ifname", "usb1\n")
            put(self.ns["GADGET"] + "/rndis.usb0/ifname", "usb0\n")
            put("/sys/class/net/usb1/flags", "0x1002")
            self.ns["path"]("/sys/class/net/l4tbr0/bridge").mkdir(parents=True)
            def cmd(args, check=True):
                values = {"dpkg-query": "39.2.1-20260806224157", "systemctl": "active",
                          "id": "jetson", "ssh-keygen": "256 SHA256:example (ED25519)",
                          "ip": '[{"addr_info":[{"family":"inet","local":"192.168.55.1","prefixlen":24}]}]'}
                return subprocess.CompletedProcess(args, 0, values[args[0]], "")
            self.ns["run"] = cmd
            s = self.ns["snapshot"]()
            self.assertEqual(s["classification"], "affected")
            self.assertEqual(s["bridge_addresses"], ["192.168.55.1/24"])
            # Malicious/unexpected interface text cannot escape the sysfs prefix.
            put(self.ns["GADGET"] + "/ncm.usb0/ifname", "../../etc")
            self.assertEqual(self.ns["snapshot"]()["classification"], "unsupported")


class FileTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ns = {}
        exec(r.REMOTE_LIB, self.ns)
        self.ns["ROOT"] = Path(self.temp.name)
        # Non-root test process. Privileged-directory checks are tested separately.
        self.ns["safe_parents"] = lambda p: None
        self.calls = []
        self.ns["run"] = lambda args, check=True: self.calls.append(args)
        self.files = self.ns["expected_files"](r.REMOTE_LIB)

    def install(self):
        # Ownership must be root in production; only adapt lstat's uid in this test.
        real_lstat = Path.lstat
        def root_lstat(p):
            st = real_lstat(p)
            values = list(st)
            values[4] = 0
            return os.stat_result(values)
        with mock.patch.object(Path, "lstat", root_lstat):
            self.ns["install"](self.files)

    def test_install_idempotent_and_vendor_untouched(self):
        vendor = self.ns["path"](self.ns["START"])
        vendor.parent.mkdir(parents=True)
        vendor.write_text("vendor original")
        self.install()
        self.install()
        for name, expected in self.files.items():
            self.assertEqual(self.ns["path"](name).read_text(), expected)
        self.assertEqual(vendor.read_text(), "vendor original")
        self.assertTrue(all(c == ["systemctl", "daemon-reload"] for c in self.calls))

    def test_conflicting_file_is_not_overwritten(self):
        p = self.ns["path"](self.ns["DROPIN"])
        p.parent.mkdir(parents=True)
        p.write_text("unrelated")
        with self.assertRaisesRegex(RuntimeError, "Refusing"):
            self.install()
        self.assertEqual(p.read_text(), "unrelated")
        self.assertFalse(self.ns["path"](self.ns["HELPER"]).exists())

    def test_symlink_is_not_followed(self):
        p = self.ns["path"](self.ns["HELPER"])
        p.parent.mkdir(parents=True)
        target = Path(self.temp.name) / "other"
        target.write_text("preserve")
        p.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "Refusing"):
            self.install()
        self.assertEqual(target.read_text(), "preserve")

    def test_failed_reload_removes_only_new_files(self):
        def fail(args, check=True):
            if check:
                raise RuntimeError("reload failed")
        self.ns["run"] = fail
        with self.assertRaisesRegex(RuntimeError, "reload failed"):
            self.install()
        self.assertFalse(any(self.ns["path"](n).exists() for n in self.files))

    def test_uninstall_preserves_other_dropins(self):
        self.install()
        other = self.ns["path"](self.ns["DROPIN"]).parent / "10-other.conf"
        other.write_text("preserve")
        self.ns["validate_files"] = lambda files: None  # root ownership separately covered
        removed = self.ns["uninstall"](self.files)
        self.assertEqual(set(removed), set(self.files))
        self.assertEqual(other.read_text(), "preserve")
        self.assertTrue(all(c == ["systemctl", "daemon-reload"] for c in self.calls))

    def test_real_parent_guard_rejects_writable_directory(self):
        original = {}
        exec(r.REMOTE_LIB, original)
        with self.assertRaisesRegex(RuntimeError, "Unsafe privileged directory"):
            original["safe_parents"](Path(self.temp.name) / "file")


class FakeJetson:
    """A PTY protocol peer: never runs uploaded commands or touches hardware."""
    def __init__(self, wrong_password=False, sudo=True, already_logged=False, execute_receiver=False):
        self.master, self.slave = pty.openpty()
        self.device = os.ttyname(self.slave)
        self.wrong_password = wrong_password
        self.sudo = sudo
        self.already_logged = already_logged
        self.execute_receiver = execute_receiver
        self.inputs = []
        self.commands = []
        self.error = None
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def emit(self, s):
        os.write(self.master, s.encode())

    def run(self):
        buf = b""
        stage = "initial"
        prompt = ""
        token = ""
        remaining = 0
        payload = []
        try:
            while not self.stop.is_set():
                if not select.select([self.master], [], [], .1)[0]:
                    continue
                data = os.read(self.master, 8192)
                if b"\x03" in data:
                    self.emit("\r\n" + (prompt or "jetson@unit:~$ "))
                    stage = "shell"
                    buf = b""
                    continue
                buf += data
                while b"\r" in buf:
                    raw, buf = buf.split(b"\r", 1)
                    text = raw.decode()
                    self.inputs.append(text)
                    if stage == "initial":
                        self.emit("\r\njetson@unit:~$ " if self.already_logged else "\r\nunit login: ")
                        stage = "shell" if self.already_logged else "user"
                    elif stage == "user":
                        self.emit("\r\nPassword: ")
                        stage = "password"
                    elif stage == "password":
                        if self.wrong_password:
                            self.emit("\r\nLogin incorrect\r\nunit login: ")
                            stage = "user"
                        else:
                            self.emit("\r\njetson@unit:~$ ")
                            stage = "shell"
                    elif stage == "sudo":
                        self.emit("\r\n" + token + "_READY\r\n")
                        stage = "payload"
                    elif stage == "payload":
                        payload.append(text)
                        remaining -= 1
                        self.emit(text + "\r\n")
                        if remaining == 0:
                            source = r.zlib.decompress(r.base64.b64decode("".join(payload))).decode()
                            compile(source, "transferred-payload", "exec")
                            s = affected()
                            s.update(classification="affected", reason="known bug")
                            result = {"ok": True, "snapshot": s, "message": "simulated"}
                            if self.execute_receiver:
                                # This mode is used only with a harmless stub REMOTE_LIB.
                                receiver = shlex.split(self.commands[-1])[-1]
                                proc = subprocess.run([r.sys.executable, "-u", "-c", receiver],
                                                      input="\n".join(payload) + "\n", text=True,
                                                      capture_output=True, timeout=5, check=True)
                                line = next(x for x in proc.stdout.splitlines() if x.startswith(token + "_RESULT:"))
                                result = json.loads(line.split(":", 1)[1])
                            self.emit(token + "_RESULT:" + json.dumps(result) + "\r\n" + prompt)
                            stage = "shell"
                    elif stage == "shell":
                        if "PS1=" in text:
                            prompt = re.search(r"JUNR_[0-9a-f]+> ", text).group(0)
                            self.emit(text + "\r\n" + prompt)
                        elif "base64,zlib" in text:
                            self.commands.append(text)
                            token = re.search(r"RPC_[0-9a-f]+", text).group(0)
                            remaining = int(re.search(r"range\((\d+)\)", text).group(1))
                            payload = []
                            self.emit(text + "\r\n")
                            if text.startswith("sudo") and self.sudo:
                                self.emit(token + "_SUDO: ")
                                stage = "sudo"
                            else:
                                self.emit(token + "_READY\r\n")
                                stage = "payload"
                        elif text == "exit":
                            if prompt:
                                prompt = ""
                                self.emit("exit\r\njetson@unit:~$ ")
                            else:
                                self.emit("logout\r\nunit login: ")
                                stage = "user"
        except OSError:
            pass
        except Exception as e:
            self.error = e

    def close(self):
        self.stop.set()
        self.thread.join(2)
        os.close(self.master)
        os.close(self.slave)
        if self.error:
            raise self.error


class SerialTests(unittest.TestCase):
    def connect(self, **kwargs):
        peer = FakeJetson(**kwargs)
        self.addCleanup(peer.close)
        port = r.SerialPort(peer.device)
        console = r.Console(port, "jetson", password_reader=lambda p: "sample-secret")
        self.addCleanup(console.close)
        return peer, console

    def test_login_diagnose_and_sudo_roundtrip(self):
        peer, console = self.connect()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            console.login()
            self.assertTrue(console.rpc()["ok"])
            self.assertTrue(console.rpc("repair", "usb1")["ok"])
        self.assertNotIn("sample-secret", out.getvalue())
        self.assertEqual(peer.inputs.count("sample-secret"), 2)
        self.assertFalse(peer.commands[0].startswith("sudo"))
        self.assertTrue(peer.commands[1].startswith("sudo"))
        self.assertTrue(all(len(line) < 1024 for line in peer.inputs))

    def test_existing_shell_does_not_receive_login_password(self):
        peer, console = self.connect(already_logged=True)
        with contextlib.redirect_stdout(io.StringIO()):
            console.login()
            console.rpc()
        self.assertNotIn("sample-secret", peer.inputs)
        self.assertFalse(console.owned_login)

    def test_receiver_really_decodes_and_executes_payload(self):
        peer, console = self.connect(execute_receiver=True)
        stub = "import json\ndef execute(request, source):\n    return {'ok': True, 'echo': request['action'], 'source_matches': source.startswith('import json')}\n"
        console.login()
        with mock.patch.object(r, "REMOTE_LIB", stub):
            result = console.rpc()
        self.assertEqual(result, {"ok": True, "echo": "diagnose", "source_matches": True})

    def test_preexisting_password_prompt_is_not_submitted(self):
        port = mock.Mock(buffer="unit login: jetson\nPassword: ")
        console = r.Console(port, "jetson")
        with self.assertRaisesRegex(r.RecoveryError, "already at Password"):
            console.login()
        port.send.assert_not_called()

    def test_wrong_password_stops(self):
        peer, console = self.connect(wrong_password=True)
        with self.assertRaisesRegex(r.RecoveryError, "login failed"):
            console.login()
        self.assertEqual(peer.inputs.count("sample-secret"), 1)
        self.assertEqual(peer.commands, [])

    def test_passwordless_sudo_does_not_receive_a_password(self):
        peer, console = self.connect(sudo=False)
        console.login()
        console.rpc("repair", "usb1")
        self.assertEqual(peer.inputs.count("sample-secret"), 1)

    def test_existing_serial_owner_blocks_open(self):
        result = subprocess.CompletedProcess([], 0, "1234\n", "")
        with mock.patch.object(r.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(r.RecoveryError, "Another process"):
                r.check_port_available("/dev/cu.usbmodemtest")

    def test_no_serial_owner_is_ok(self):
        result = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(r.subprocess, "run", return_value=result):
            r.check_port_available("/dev/cu.usbmodemtest")

    def test_password_prompt_change_sends_no_secret(self):
        port = mock.Mock(buffer="")
        port.read_once.return_value = "\nunit login: "
        console = r.Console(port, "jetson", password_reader=lambda p: "secret")
        with self.assertRaisesRegex(r.RecoveryError, "expired or changed"):
            console.send_password("password: ")
        port.send.assert_not_called()

    def test_password_reader_failure_sends_nothing_to_jetson(self):
        port = mock.Mock(buffer="")
        reader = mock.Mock(side_effect=r.RecoveryError("cannot read hidden input"))
        console = r.Console(port, "jetson", password_reader=reader)
        with self.assertRaises(r.RecoveryError):
            console.send_password("Password: ")
        port.send.assert_not_called()

    def test_timeout_does_not_print_raw_buffer(self):
        peer, console = self.connect()
        console.port.buffer = "secret should never be printed"
        with self.assertRaises(r.RecoveryError) as caught:
            console.port.expect([r"NEVER_MATCH"], timeout=.05)
        self.assertNotIn("secret should", str(caught.exception))

    def test_getpass_warning_is_error(self):
        tty = mock.MagicMock()
        tty.__enter__.return_value.isatty.return_value = True
        def warn(*args, **kwargs):
            warnings.warn("cannot hide", r.getpass.GetPassWarning)
            return "secret"
        with mock.patch("builtins.open", return_value=tty), mock.patch.object(r.getpass, "getpass", side_effect=warn):
            with self.assertRaisesRegex(r.RecoveryError, "securely read"):
                r.hidden_password("Password: ")


class PasswordTerminalTests(unittest.TestCase):
    """Exercise /dev/tty and real echo control, not a mocked password reader."""

    IMPORT_SCRIPT = (
        "import importlib.util\n"
        "spec = importlib.util.spec_from_file_location('recovery', " + repr(str(SCRIPT)) + ")\n"
        "r = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(r)\n"
    )

    def terminal_child(self, body):
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        code = (
            "import fcntl, termios\n"
            "fcntl.ioctl(0, termios.TIOCSCTTY, 0)\n"
            + self.IMPORT_SCRIPT
            + "before = termios.tcgetattr(0)\n"
            + body
            + "\nassert termios.tcgetattr(0) == before\n"
            + "print('TERMINAL_RESTORED', flush=True)\n"
        )
        proc = subprocess.Popen([r.sys.executable, "-u", "-c", code],
                                stdin=slave, stdout=slave, stderr=slave,
                                start_new_session=True)
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
        self.addCleanup(cleanup)
        return proc, master, slave

    def read_until(self, fd, marker):
        output = b""
        deadline = time.monotonic() + 5
        while marker not in output:
            if time.monotonic() >= deadline:
                self.fail("Terminal marker missing: " + repr(marker) + "; output: " + repr(output))
            if select.select([fd], [], [], .1)[0]:
                output += os.read(fd, 8192)
        return output

    def test_real_terminal_password_is_hidden_and_echo_restored(self):
        proc, master, slave = self.terminal_child(
            "value = r.hidden_password('TEST_PASSWORD: ')\n"
            "assert value == 'test-only-password'\n"
        )
        output = self.read_until(master, b"TEST_PASSWORD: ")
        self.assertFalse(termios.tcgetattr(slave)[3] & termios.ECHO)
        os.write(master, b"test-only-password\n")
        output += self.read_until(master, b"TERMINAL_RESTORED")
        self.assertEqual(proc.wait(timeout=5), 0)
        self.assertTrue(termios.tcgetattr(slave)[3] & termios.ECHO)
        self.assertNotIn(b"test-only-password", output)

    def test_end_of_input_fails_cleanly_and_restores_terminal(self):
        proc, master, slave = self.terminal_child(
            "try:\n"
            "    r.hidden_password('TEST_PASSWORD: ')\n"
            "except r.RecoveryError:\n"
            "    print('INPUT_REFUSED', flush=True)\n"
            "else:\n"
            "    raise AssertionError('EOF accepted')\n"
        )
        output = self.read_until(master, b"TEST_PASSWORD: ")
        os.write(master, termios.tcgetattr(slave)[6][termios.VEOF])
        output += self.read_until(master, b"TERMINAL_RESTORED")
        self.assertEqual(proc.wait(timeout=5), 0)
        self.assertIn(b"INPUT_REFUSED", output)
        self.assertNotIn(b"Traceback", output)

    def test_interrupt_restores_terminal(self):
        proc, master, slave = self.terminal_child(
            "try:\n"
            "    r.hidden_password('TEST_PASSWORD: ')\n"
            "except KeyboardInterrupt:\n"
            "    print('INPUT_CANCELLED', flush=True)\n"
            "else:\n"
            "    raise AssertionError('interrupt accepted')\n"
        )
        output = self.read_until(master, b"TEST_PASSWORD: ")
        os.write(master, termios.tcgetattr(slave)[6][termios.VINTR])
        output += self.read_until(master, b"TERMINAL_RESTORED")
        self.assertEqual(proc.wait(timeout=5), 0)
        self.assertIn(b"INPUT_CANCELLED", output)

    def test_no_controlling_terminal_refuses_piped_password(self):
        code = self.IMPORT_SCRIPT + (
            "try:\n"
            "    r.hidden_password('TEST_PASSWORD: ')\n"
            "except r.RecoveryError:\n"
            "    print('INPUT_REFUSED')\n"
            "else:\n"
            "    raise AssertionError('piped password accepted')\n"
        )
        proc = subprocess.run([r.sys.executable, "-u", "-c", code],
                              input="test-only-password\n", text=True,
                              capture_output=True, start_new_session=True, timeout=5)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "INPUT_REFUSED")
        self.assertNotIn("test-only-password", proc.stdout + proc.stderr)

    def test_echo_control_failure_never_reads_visible_input(self):
        proc, master, _ = self.terminal_child(
            "from unittest import mock\n"
            "with mock.patch.object(r.getpass.termios, 'tcsetattr', side_effect=termios.error(25, 'simulated echo-control failure')), mock.patch.object(r.getpass, '_raw_input') as read_input:\n"
            "    try:\n"
            "        r.hidden_password('TEST_PASSWORD: ')\n"
            "    except r.RecoveryError:\n"
            "        print('INPUT_REFUSED', flush=True)\n"
            "    else:\n"
            "        raise AssertionError('echo-control failure ignored')\n"
            "    read_input.assert_not_called()\n"
        )
        output = self.read_until(master, b"TERMINAL_RESTORED")
        self.assertEqual(proc.wait(timeout=5), 0)
        self.assertIn(b"INPUT_REFUSED", output)
        self.assertNotIn(b"TEST_PASSWORD", output)


class MacProbeTests(unittest.TestCase):
    def check(self, route="en7", config="inet 192.168.55.100", banner=b"SSH-2.0-OpenSSH\r\n"):
        s = affected()
        def host(args):
            if "networksetup" in args[0]:
                return "Hardware Port: Linux for Tegra\nDevice: en7\nEthernet Address: test\n\n"
            if "ifconfig" in args[0]:
                return config
            return "interface: " + route + "\n"
        sock = mock.MagicMock()
        sock.__enter__.return_value.recv.return_value = banner
        with mock.patch.object(r.sys, "platform", "darwin"), mock.patch.object(r, "host_command", side_effect=host), mock.patch.object(r.socket, "create_connection", return_value=sock) as connect, contextlib.redirect_stdout(io.StringIO()):
            result = r.mac_network_check(s)
        return result, connect

    def test_verified_usb_route(self):
        result, connect = self.check()
        self.assertTrue(result)
        connect.assert_called_once()

    def test_never_probe_wrong_route(self):
        result, connect = self.check(route="en0")
        self.assertFalse(result)
        connect.assert_not_called()

    def test_never_probe_without_matching_ipv4(self):
        result, connect = self.check(config="inet6 fe80::1")
        self.assertFalse(result)
        connect.assert_not_called()

    def test_non_ssh_listener_is_not_success(self):
        self.assertFalse(self.check(banner=b"HTTP/1.1")[0])


if __name__ == "__main__":
    unittest.main()
