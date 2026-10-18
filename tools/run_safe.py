#!/usr/bin/python3 -I
"""Run the pinned sender with portal-only screen access and private state."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import termios
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_safe import source_digest, temporary_parent


MEMORY_MAX = 768 * 1024 * 1024
TASKS_MAX = 96
CACHED_PROXY_SHA256 = "ef6d831025ac3e88439e894037d531f047a761cf26bb5067da715e411e430541"
PRIVATE_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
PORTAL_RULES = (
    "--filter",
    "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.ScreenCast.*@/org/freedesktop/portal/desktop",
    "--call=org.freedesktop.portal.Desktop=org.freedesktop.DBus.Properties.Get@/org/freedesktop/portal/desktop",
    "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.Close@/org/freedesktop/portal/desktop/request/*",
    "--call=org.freedesktop.portal.Desktop=org.freedesktop.portal.Session.Close@/org/freedesktop/portal/desktop/session/*",
    "--broadcast=org.freedesktop.portal.Desktop=org.freedesktop.portal.Request.Response@/org/freedesktop/portal/desktop/request/*",
)


def private_directory(directory: Path) -> Path:
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError(f"private directory has unsafe ownership or type: {directory}")
    directory.chmod(0o700)
    return directory


def disk_temporary_root() -> Path:
    return temporary_parent()


def host_environment() -> dict[str, str]:
    runtime = f"/run/user/{os.getuid()}"
    return {
        "PATH": "/usr/bin", "HOME": str(Path.home()), "LANG": "C.UTF-8",
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={runtime}/bus",
    }


class LaunchInterrupted(BaseException):
    def __init__(self, signum: int):
        self.signum = signum


class ScopeCleanupError(RuntimeError):
    pass


@contextlib.contextmanager
def termination_signals():
    signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {signum: signal.getsignal(signum) for signum in signals}

    def interrupt(signum, frame):
        for item in signals:
            signal.signal(item, signal.SIG_IGN)
        raise LaunchInterrupted(signum)

    try:
        for signum in signals:
            signal.signal(signum, interrupt)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


@contextlib.contextmanager
def restore_terminal():
    settings = termios.tcgetattr(0) if os.isatty(0) else None
    try:
        yield
    finally:
        if settings is not None:
            termios.tcsetattr(0, termios.TCSANOW, settings)


def stop_scope(process: subprocess.Popen, unit: str) -> None:
    # The bwrap payload creates another session; terminate its whole cgroup.
    scope = unit + ".scope"
    for operation in (
        ["kill", "--kill-whom=all", "--signal=SIGTERM", scope],
        ["stop", scope],
        ["kill", "--kill-whom=all", "--signal=SIGKILL", scope],
    ):
        try:
            subprocess.run(
                ["/usr/bin/systemctl", "--user", *operation], env=host_environment(),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=3, check=False,
            )
        except subprocess.TimeoutExpired:
            continue
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
    try:
        state = subprocess.run(
            ["/usr/bin/systemctl", "--user", "show", scope, "--property=ActiveState", "--property=ControlGroup"],
            env=host_environment(), stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=3, check=True,
        )
        properties = dict(line.split("=", 1) for line in state.stdout.splitlines() if "=" in line)
        group = properties.get("ControlGroup", "")
        if group:
            relative = Path(group.lstrip("/"))
            if ".." in relative.parts:
                raise ScopeCleanupError("unexpected resource-group path")
            members = Path("/sys/fs/cgroup") / relative / "cgroup.procs"
            if members.exists() and members.read_text().strip():
                raise ScopeCleanupError("sender process group has not stopped")
        elif properties.get("ActiveState") not in {"inactive", "failed"}:
            raise ScopeCleanupError("sender process-group cleanup could not be established")
    except (OSError, subprocess.SubprocessError) as error:
        raise ScopeCleanupError("cannot verify sender process-group cleanup") from error


def verified_binary(repo: Path) -> Path:
    binary = repo / "bin/doubletake"
    receipt_file = repo / "bin/build-info.json"
    for candidate in (binary, receipt_file):
        info = candidate.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise RuntimeError(f"unsafe build artifact: {candidate}")
    if receipt_file.stat().st_size > 8192:
        raise RuntimeError("invalid build receipt size")
    receipt = json.loads(receipt_file.read_text())
    with binary.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    if (
        receipt.get("sha256") != digest
        or receipt.get("go_version") != "go1.27.2"
        or receipt.get("cgo_enabled") is not False
        or receipt.get("source_sha256") != source_digest(repo)
    ):
        raise RuntimeError("binary or source differs from verified build; run tools/build_safe.py")
    return binary


def proxy_binary() -> Path:
    system = Path("/usr/bin/xdg-dbus-proxy")
    candidate = system if system.exists() else Path.home() / ".cache/development-tools/xdg-dbus-proxy-0.1.9"
    info = candidate.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022 or not os.access(candidate, os.X_OK):
        raise RuntimeError("xdg-dbus-proxy is required; no unfiltered D-Bus fallback is allowed")
    if candidate == system:
        if info.st_uid != 0:
            raise RuntimeError("system D-Bus proxy is not root-owned")
    else:
        with candidate.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        if info.st_uid != os.getuid() or digest != CACHED_PROXY_SHA256:
            raise RuntimeError("cached D-Bus proxy differs from the verified distro package")
    return candidate


@contextlib.contextmanager
def portal_proxy(run_root: Path):
    runtime = Path(f"/run/user/{os.getuid()}")
    bus = runtime / "bus"
    if not stat.S_ISSOCK(bus.stat().st_mode):
        raise RuntimeError("a local user-session D-Bus socket is required")
    endpoint = run_root / "bus"
    parent_sync, child_sync = socket.socketpair()
    process = None
    try:
        process = subprocess.Popen(
            [str(proxy_binary()), f"--fd={child_sync.fileno()}", f"unix:path={bus}", str(endpoint), *PORTAL_RULES],
            pass_fds=(child_sync.fileno(),),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=host_environment(),
        )
        child_sync.close()
        parent_sync.settimeout(5)
        if parent_sync.recv(1) != b"x" or not endpoint.is_socket():
            raise RuntimeError("portal D-Bus proxy did not become ready")
        yield endpoint
    finally:
        parent_sync.close()
        child_sync.close()
        if process is not None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired as error:
                        raise ScopeCleanupError("portal proxy did not stop") from error


def sandbox_command(binary: Path, run_root: Path, config: Path, bus: Path, arguments: list[str]) -> list[str]:
    uid, gid = os.getuid(), os.getgid()
    for name in ("home", "tmp", "cache"):
        private_directory(run_root / name)
    (run_root / "passwd").write_text(f"doubletake:x:{uid}:{gid}::/home/doubletake:/usr/bin/nologin\n")
    (run_root / "group").write_text(f"doubletake:x:{gid}:\n")
    command = [
        "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--share-net", "--die-with-parent", "--new-session",
        "--disable-userns", "--cap-drop", "ALL", "--hostname", "doubletake",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
        "--proc", "/proc", "--dev", "/dev", "--dir", "/etc",
        "--ro-bind", str(run_root / "passwd"), "/etc/passwd",
        "--ro-bind", str(run_root / "group"), "/etc/group",
        "--dir", "/app", "--ro-bind", str(binary), "/app/doubletake",
        "--ro-bind", str(Path(__file__).resolve().with_name("sandbox_exec.py")), "/app/sandbox_exec.py",
        "--bind", str(run_root / "home"), "/home/doubletake",
        "--bind", str(run_root / "tmp"), "/tmp",
        "--bind", str(config), "/state/config",
        "--bind", str(run_root / "cache"), "/state/cache",
        "--dir", f"/run/user/{uid}", "--ro-bind", str(bus), f"/run/user/{uid}/bus",
        "--chdir", "/home/doubletake", "--clearenv",
    ]
    environment = {
        "PATH": "/usr/bin", "HOME": "/home/doubletake", "LANG": "C.UTF-8",
        "XDG_CONFIG_HOME": "/state/config", "XDG_CACHE_HOME": "/state/cache",
        "XDG_RUNTIME_DIR": f"/run/user/{uid}", "XDG_SESSION_TYPE": "wayland", "TMPDIR": "/tmp",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus",
        "GST_PLUGIN_SYSTEM_PATH_1_0": "/usr/lib/gstreamer-1.0",
        "GST_PLUGIN_PATH_1_0": "", "GOMAXPROCS": "2", "GOMEMLIMIT": "512MiB",
    }
    for key, value in environment.items():
        command.extend(("--setenv", key, value))
    command.extend(("--", "/usr/bin/python3", "-I", "/app/sandbox_exec.py", "/app/doubletake", *arguments))
    return command


def limited_command(command: list[str], unit: str) -> list[str]:
    return [
        "/usr/bin/systemd-run", "--user", "--scope", "--quiet", f"--unit={unit}",
        f"--property=MemoryMax={MEMORY_MAX}", "--property=MemorySwapMax=128M",
        f"--property=TasksMax={TASKS_MAX}", "--property=CPUQuota=200%", "--", *command,
    ]


def receiver_address(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise argparse.ArgumentTypeError("specify the receiver's numeric LAN IPv4 address") from error
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise argparse.ArgumentTypeError("only a private LAN receiver address is allowed")
    return str(address)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receiver", type=receiver_address)
    parser.add_argument("--pair", action="store_true", help="explicitly pair using the code shown on this receiver")
    parser.add_argument("--synthetic", action="store_true", help="send generated test video instead of capturing a screen")
    options = parser.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))
    repo = Path(__file__).resolve().parent.parent
    binary = verified_binary(repo)
    config = private_directory(Path.home() / ".local/share/doubletake-safe/config")
    arguments = ["-target", options.receiver, "-portal-only", "-no-audio", "-hwaccel", "none", "-video-codec", "h264", "-fps", "30", "-port-range", "60000-60010"]
    if options.pair:
        arguments.append("-pair")
    if options.synthetic:
        arguments.append("-test")
    unit = "doubletake-safe-" + uuid.uuid4().hex[:12]
    process = None
    try:
        with termination_signals(), restore_terminal():
            run_root = Path(tempfile.mkdtemp(prefix="dt-", dir=disk_temporary_root()))
            cleanup_permitted = True
            try:
                with portal_proxy(run_root) as bus:
                    command = limited_command(sandbox_command(binary, run_root, config, bus, arguments), unit)
                    try:
                        cleanup_permitted = False
                        process = subprocess.Popen(command, start_new_session=True, env=host_environment())
                        return process.wait()
                    finally:
                        if process is not None:
                            stop_scope(process, unit)
                        cleanup_permitted = True
            except ScopeCleanupError:
                cleanup_permitted = False
                raise
            finally:
                if cleanup_permitted:
                    shutil.rmtree(run_root)
                else:
                    print(f"Preserved active run directory: {run_root}", file=sys.stderr)
    except LaunchInterrupted as error:
        return 128 + error.signum


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Safe launch refused: {error}")
