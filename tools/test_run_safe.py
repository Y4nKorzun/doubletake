from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pty
import selectors
import socket
import subprocess
import sys
import tempfile
import termios
import unittest
from unittest import mock
import uuid

import run_safe


class LaunchPolicyTests(unittest.TestCase):
    def test_receiver_must_be_an_explicit_private_lan_address(self):
        self.assertEqual(run_safe.receiver_address("192.168.1.67"), "192.168.1.67")
        for value in ("127.0.0.1", "169.254.1.1", "0.0.0.0", "1.1.1.1", "192.0.2.1", "224.0.0.1", "Mac.local", "::1"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                run_safe.receiver_address(value)

    def test_changed_binary_or_source_cannot_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / "bin").mkdir()
            binary = repo / "bin/doubletake"
            binary.write_bytes(b"verified source build")
            binary.chmod(0o700)
            receipt = repo / "bin/build-info.json"
            record = {"sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "source_sha256": "source", "go_version": "go1.27.2", "cgo_enabled": False}
            receipt.write_text(json.dumps(record))
            receipt.chmod(0o600)
            with mock.patch("run_safe.source_digest", return_value="source"):
                self.assertEqual(run_safe.verified_binary(repo), binary)
                binary.write_bytes(b"modified artifact")
                with self.assertRaises(RuntimeError):
                    run_safe.verified_binary(repo)
            binary.write_bytes(b"verified source build")
            with mock.patch("run_safe.source_digest", return_value="new source"), self.assertRaises(RuntimeError):
                run_safe.verified_binary(repo)

    def test_unsafe_private_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real")
            with self.assertRaises(RuntimeError):
                run_safe.private_directory(root / "link")

    def test_host_helpers_never_inherit_code_injection_environment(self):
        with mock.patch.dict(os.environ, {"LD_PRELOAD": "/tmp/inject.so", "PYTHONPATH": "/tmp", "PATH": "/tmp", "DBUS_SESSION_BUS_ADDRESS": "unix:abstract=untrusted"}):
            clean = run_safe.host_environment()
        self.assertNotIn("LD_PRELOAD", clean)
        self.assertNotIn("PYTHONPATH", clean)
        self.assertEqual(clean["PATH"], "/usr/bin")
        self.assertEqual(clean["DBUS_SESSION_BUS_ADDRESS"], f"unix:path=/run/user/{os.getuid()}/bus")

    def test_unverifiable_scope_cleanup_is_reported(self):
        process = mock.Mock()
        process.poll.return_value = 0
        with mock.patch("run_safe.subprocess.run", side_effect=[None, None, None, subprocess.CalledProcessError(1, "systemctl")]):
            with self.assertRaises(run_safe.ScopeCleanupError):
                run_safe.stop_scope(process, "doubletake-check-owned")

    def test_terminal_echo_restored_after_interrupted_input(self):
        master, slave = pty.openpty()
        try:
            before = termios.tcgetattr(slave)
            script = r'''
import sys, termios
sys.path.insert(0, sys.argv[1])
import run_safe
try:
    with run_safe.restore_terminal():
        settings = termios.tcgetattr(0)
        settings[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, settings)
        raise InterruptedError("simulate killed credential reader")
except InterruptedError:
    pass
'''
            subprocess.run([sys.executable, "-I", "-B", "-c", script, str(Path(run_safe.__file__).parent)], stdin=slave, check=True, env=run_safe.host_environment(), timeout=5)
            self.assertEqual(termios.tcgetattr(slave), before)
        finally:
            os.close(master)
            os.close(slave)


class RealSandboxTests(unittest.TestCase):
    def test_stop_scope_terminates_separate_session_before_temporary_cleanup(self):
        probe = r'''
import json, os, signal, subprocess, sys
signal.signal(signal.SIGTERM, signal.SIG_IGN)
child_code = """
import json, os, pathlib, signal
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path('/tmp/descendant-owned').write_text('active descendant\\n')
print(json.dumps({'pid': os.getpid(), 'sid': os.getsid(0), 'ignores_term': signal.getsignal(signal.SIGTERM) == signal.SIG_IGN}), flush=True)
while True:
    signal.pause()
"""
child = subprocess.Popen(['/usr/bin/python3', '-I', '-c', child_code], stdout=subprocess.PIPE, text=True, start_new_session=True)
ready = json.loads(child.stdout.readline())
assert ready['sid'] != os.getsid(0), 'descendant did not leave the parent session'
assert ready['ignores_term'], 'descendant does not ignore SIGTERM'
print(json.dumps({'separate_session': True, 'ignores_term': True}), flush=True)
while True:
    signal.pause()
'''
        owned_directory = None
        with tempfile.TemporaryDirectory(prefix="dt-stop-", dir=run_safe.disk_temporary_root()) as directory:
            owned_directory = Path(directory)
            config = run_safe.private_directory(owned_directory / "config")
            unit = "doubletake-stop-" + uuid.uuid4().hex[:12]
            with run_safe.portal_proxy(owned_directory) as bus:
                command = run_safe.limited_command(run_safe.sandbox_command(Path(sys.executable).resolve(), owned_directory, config, bus, ["-c", probe]), unit)
                process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, env=run_safe.host_environment())
                control_group = None
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(10), "sandbox descendant did not become ready")
                    line = process.stdout.readline()
                    if not line:
                        self.fail("sandbox failed: " + process.stderr.read())
                    self.assertEqual(json.loads(line), {"separate_session": True, "ignores_term": True})
                    control_group = subprocess.check_output(["/usr/bin/systemctl", "--user", "show", unit + ".scope", "--property=ControlGroup", "--value"], text=True, env=run_safe.host_environment()).strip()
                    self.assertTrue(control_group)
                    cgroup = Path("/sys/fs/cgroup") / control_group.lstrip("/")
                    self.assertGreaterEqual(len((cgroup / "cgroup.procs").read_text().split()), 3)
                    self.assertTrue((owned_directory / "tmp/descendant-owned").is_file())

                    run_safe.stop_scope(process, unit)

                    self.assertIsNotNone(process.poll(), "scope supervisor survived stop_scope")
                    try:
                        remaining = (cgroup / "cgroup.procs").read_text().strip()
                    except FileNotFoundError:
                        remaining = ""
                    self.assertEqual(remaining, "", "scope still contains processes before temporary cleanup")
                    self.assertTrue(owned_directory.exists(), "temporary data was removed before verifying process shutdown")
                    self.assertTrue((owned_directory / "tmp/descendant-owned").exists())
                finally:
                    run_safe.stop_scope(process, unit)
                    for stream in (process.stdout, process.stderr):
                        stream.close()
        self.assertFalse(owned_directory.exists(), "owned temporary data was not cleaned after shutdown")

    def test_kernel_filesystem_bus_and_resource_boundaries(self):
        probe = r'''
import errno, json, os, pathlib, socket, subprocess, sys
home, uid = sys.argv[1], os.getuid()
assert not pathlib.Path(home).exists(), "host home is exposed"
for name in ("pipewire-0", "pulse/native", "wayland-1"):
    assert not pathlib.Path(f"/run/user/{uid}/{name}").exists(), name
assert not pathlib.Path("/dev/dri").exists(), "GPU device is exposed"
assert "DISPLAY" not in os.environ and "WAYLAND_DISPLAY" not in os.environ
status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)
assert status["NoNewPrivs"].strip() == "1"
assert int(status["CapEff"].strip(), 16) == 0
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as ipc:
    try:
        ipc.connect("\0" + sys.argv[2])
    except OSError as error:
        assert error.errno == errno.EPERM, error
    else:
        raise AssertionError("host abstract desktop sockets are reachable")
base = ["/usr/bin/gdbus", "call", "--session"]
allowed = subprocess.run(base + ["--dest", "org.freedesktop.portal.Desktop", "--object-path", "/org/freedesktop/portal/desktop", "--method", "org.freedesktop.DBus.Properties.Get", "org.freedesktop.portal.ScreenCast", "version"], capture_output=True, text=True, timeout=5)
assert allowed.returncode == 0, allowed.stderr
blocked = subprocess.run(base + ["--dest", "org.freedesktop.secrets", "--object-path", "/org/freedesktop/secrets", "--method", "org.freedesktop.DBus.Peer.Ping"], capture_output=True, text=True, timeout=5)
assert blocked.returncode != 0, "secret service is reachable"
blocked_portal = subprocess.run(base + ["--dest", "org.freedesktop.portal.Desktop", "--object-path", "/org/freedesktop/portal/desktop", "--method", "org.freedesktop.portal.Secret.RetrieveSecret"], capture_output=True, text=True, timeout=5)
assert blocked_portal.returncode != 0 and "AccessDenied" in blocked_portal.stderr, blocked_portal.stderr
print(json.dumps({"private_home": True, "no_audio_or_wayland_sockets": True, "no_gpu": True, "no_new_privileges": True, "abstract_desktop_ipc_denied": True, "portal_query": allowed.stdout.strip(), "secret_service_denied": True, "non_screencast_portal_denied": True}), flush=True)
sys.stdin.readline()
'''
        with tempfile.TemporaryDirectory(prefix="dt-check-", dir=run_safe.disk_temporary_root()) as directory:
            root = Path(directory)
            config = run_safe.private_directory(root / "config")
            unit = "doubletake-check-" + uuid.uuid4().hex[:12]
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, run_safe.portal_proxy(root) as bus:
                abstract_name = "doubletake-check-" + uuid.uuid4().hex
                listener.bind("\0" + abstract_name)
                listener.listen(1)
                command = run_safe.limited_command(run_safe.sandbox_command(Path(sys.executable).resolve(), root, config, bus, ["-c", probe, str(Path.home()), abstract_name]), unit)
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True, env=run_safe.host_environment())
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        self.assertTrue(selector.select(10), "sandbox did not report its boundaries")
                    line = process.stdout.readline()
                    if not line:
                        self.fail("sandbox failed: " + process.stderr.read())
                    report = json.loads(line)
                    self.assertTrue(report["secret_service_denied"])
                    control_group = subprocess.check_output(["/usr/bin/systemctl", "--user", "show", unit + ".scope", "--property=ControlGroup", "--value"], text=True, env=run_safe.host_environment()).strip()
                    self.assertTrue(control_group)
                    cgroup = Path("/sys/fs/cgroup") / control_group.lstrip("/")
                    self.assertEqual((cgroup / "memory.max").read_text().strip(), str(run_safe.MEMORY_MAX))
                    self.assertEqual((cgroup / "pids.max").read_text().strip(), str(run_safe.TASKS_MAX))
                    quota, period = map(int, (cgroup / "cpu.max").read_text().split())
                    self.assertEqual(quota, period * 2)
                    self.assertTrue((cgroup / "cgroup.procs").read_text().strip())
                    process.stdin.write("\n")
                    process.stdin.flush()
                    self.assertEqual(process.wait(timeout=5), 0)
                finally:
                    run_safe.stop_scope(process, unit)
                    for stream in (process.stdin, process.stdout, process.stderr):
                        stream.close()


if __name__ == "__main__":
    unittest.main()
