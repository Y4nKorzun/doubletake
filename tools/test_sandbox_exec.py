import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

import sandbox_exec


class SandboxExecTests(unittest.TestCase):
    def mocked_libc(self, syscall_results, prctl_result=0):
        library = Mock()
        library.syscall.side_effect = syscall_results
        library.prctl.return_value = prctl_result
        return library

    def test_missing_or_old_landlock_never_executes_payload(self):
        for name, results in [("missing", [-1]), ("old ABI", [5])]:
            with self.subTest(name=name):
                library = self.mocked_libc(results)
                with patch.object(sandbox_exec.platform, "machine", return_value="x86_64"), patch.object(sandbox_exec.ctypes, "CDLL", return_value=library), patch.object(sandbox_exec.ctypes, "get_errno", return_value=errno.ENOSYS), patch.object(sandbox_exec.os, "execv") as execute:
                    with self.assertRaises((OSError, RuntimeError)):
                        sandbox_exec.main(["/app/payload"])
                execute.assert_not_called()

    def test_unsupported_architecture_never_uses_syscall_numbers(self):
        with patch.object(sandbox_exec.platform, "machine", return_value="aarch64"), patch.object(sandbox_exec.ctypes, "CDLL") as library:
            with self.assertRaisesRegex(RuntimeError, "Linux x86_64"):
                sandbox_exec.confine_desktop_ipc()
        library.assert_not_called()

    def test_no_new_privileges_failure_never_creates_ruleset(self):
        library = self.mocked_libc([6], prctl_result=-1)
        with patch.object(sandbox_exec.ctypes, "CDLL", return_value=library), patch.object(sandbox_exec.ctypes, "get_errno", return_value=errno.EPERM):
            with self.assertRaisesRegex(OSError, "no-new-privileges"):
                sandbox_exec.confine_desktop_ipc()
        self.assertEqual(library.syscall.call_count, 1)

    def test_ruleset_creation_and_enforcement_fail_closed(self):
        for name, results, closes in [
            ("creation", [6, -1], []),
            ("enforcement", [6, 17, -1], [17]),
        ]:
            with self.subTest(name=name):
                library = self.mocked_libc(results)
                with patch.object(sandbox_exec.ctypes, "CDLL", return_value=library), patch.object(sandbox_exec.ctypes, "get_errno", return_value=errno.EACCES), patch.object(sandbox_exec.os, "close") as close, patch.object(sandbox_exec.os, "execv") as execute:
                    with self.assertRaises(OSError):
                        sandbox_exec.main(["/app/payload"])
                execute.assert_not_called()
                self.assertEqual([call.args[0] for call in close.call_args_list], closes)

    def test_both_ipc_scopes_are_enforced_before_exec(self):
        library = self.mocked_libc([10, 17, 0])
        order = []
        results = iter([10, 17, 0])

        def syscall(*arguments):
            order.append(("syscall", arguments))
            return next(results)

        def prctl(*arguments):
            order.append(("prctl", arguments))
            return 0

        def execute(*arguments):
            order.append(("exec", arguments))
            raise SystemExit(0)

        library.syscall.side_effect = syscall
        library.prctl.side_effect = prctl
        with patch.object(sandbox_exec.ctypes, "CDLL", return_value=library), patch.object(sandbox_exec.os, "close") as close, patch.object(sandbox_exec.os, "execv", side_effect=execute):
            with self.assertRaises(SystemExit):
                sandbox_exec.main(["/app/payload", "--argument"])
        close.assert_called_once_with(17)
        self.assertEqual([item[0] for item in order], ["syscall", "prctl", "syscall", "syscall", "exec"])
        ruleset = library.syscall.call_args_list[1].args[1]._obj
        self.assertEqual(ctypes.sizeof(ruleset), 24)
        self.assertEqual((ruleset.handled_access_fs, ruleset.handled_access_net, ruleset.scoped), (0, 0, 3))
        self.assertEqual(order[-1][1], ("/app/payload", ["/app/payload", "--argument"]))

    def test_relative_or_missing_payload_is_rejected(self):
        for arguments in [[], ["relative-command"]]:
            with self.subTest(arguments=arguments), patch.object(sandbox_exec, "confine_desktop_ipc") as confine:
                with self.assertRaisesRegex(RuntimeError, "absolute"):
                    sandbox_exec.main(arguments)
                confine.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux" and platform.machine() == "x86_64", "Linux x86_64 confinement required")
    def test_native_scope_blocks_host_abstract_ipc_and_signals_but_allows_portal_transport(self):
        bootstrap = Path(__file__).with_name("sandbox_exec.py").resolve()
        abstract_name = "\0doubletake-landlock-" + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix="ll-") as directory, socket.socket(socket.AF_UNIX) as abstract_server, socket.socket(socket.AF_UNIX) as filesystem_server, socket.socket(socket.AF_INET) as inet_server:
            filesystem_name = str(Path(directory) / "bus")
            abstract_server.bind(abstract_name)
            abstract_server.listen(1)
            filesystem_server.bind(filesystem_name)
            filesystem_server.listen(1)
            inet_server.bind(("127.0.0.1", 0))
            inet_server.listen(1)
            child = """
import json, os, socket, sys
abstract_name, filesystem_name, inet_port, parent_pid = sys.argv[1:]
result = {}
with socket.socket(socket.AF_UNIX) as connection:
    try:
        connection.connect('\\0' + abstract_name)
        result['abstract_errno'] = 0
    except OSError as error:
        result['abstract_errno'] = error.errno
with socket.socket(socket.AF_UNIX) as connection:
    connection.connect(filesystem_name)
    connection.sendall(b'portal-transport')
    result['filesystem_allowed'] = True
with socket.create_connection(('127.0.0.1', int(inet_port)), timeout=2) as connection:
    connection.sendall(b'inet-transport')
    result['inet_allowed'] = True
try:
    os.kill(int(parent_pid), 0)
    result['host_signal_errno'] = 0
except OSError as error:
    result['host_signal_errno'] = error.errno
os.kill(os.getpid(), 0)
result['self_signal_allowed'] = True
with open('/proc/self/status') as status:
    result['no_new_privileges'] = next(int(line.split()[1]) for line in status if line.startswith('NoNewPrivs:'))
print(json.dumps(result))
"""
            completed = subprocess.run(
                [sys.executable, "-I", str(bootstrap), sys.executable, "-I", "-c", child, abstract_name[1:], filesystem_name, str(inet_server.getsockname()[1]), str(os.getpid())],
                env={"PATH": "/usr/bin", "LANG": "C.UTF-8"}, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertEqual(result, {
                "abstract_errno": errno.EPERM,
                "filesystem_allowed": True,
                "inet_allowed": True,
                "host_signal_errno": errno.EPERM,
                "self_signal_allowed": True,
                "no_new_privileges": 1,
            })
            filesystem_server.settimeout(2)
            with filesystem_server.accept()[0] as connection:
                self.assertEqual(connection.recv(64), b"portal-transport")
            inet_server.settimeout(2)
            with inet_server.accept()[0] as connection:
                self.assertEqual(connection.recv(64), b"inet-transport")


if __name__ == "__main__":
    unittest.main()
