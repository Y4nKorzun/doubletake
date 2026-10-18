#!/usr/bin/python3 -I
"""Build the hardened sender with a pinned Go toolchain and a source receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile


GO_VERSION = "go1.27.2"
SOURCE_SUFFIXES = {".go", ".s", ".S", ".h", ".syso"}
ROOT_OUTPUT_DIRS = {".git", "bin", "artifacts"}
EMBED_DIRECTIVE = re.compile(rb"(?m)^[ \t]*//go:embed(?:[ \t]|$)")
DISK_FILESYSTEMS = {
    "bcachefs", "btrfs", "ext2", "ext3", "ext4", "f2fs", "ntfs", "ntfs3", "xfs", "zfs",
}


def source_digest(repo: Path) -> str:
    """Hash current compiler inputs, including ignored sources and embedded assets."""
    repo = Path(repo).resolve()
    sources: set[Path] = set()
    embedded_packages: set[Path] = set()
    for current, directories, names in os.walk(repo, followlinks=False):
        directory = Path(current)
        if directory == repo:
            directories[:] = [name for name in directories if name not in ROOT_OUTPUT_DIRS]
        for name in directories:
            if (directory / name).is_symlink():
                raise RuntimeError(f"refusing symlinked source directory: {(directory / name).relative_to(repo)}")
        for name in names:
            path = directory / name
            if path.suffix not in SOURCE_SUFFIXES and name not in {"go.mod", "go.sum"}:
                continue
            validate_source_file(repo, path)
            sources.add(path)
            if path.suffix == ".go" and EMBED_DIRECTIVE.search(path.read_bytes()):
                if directory == repo:
                    raise RuntimeError("root-package embedding requires review of excluded build-output directories")
                embedded_packages.add(directory)
    # Hash every regular file below an embedding package, a conservative
    # superset of all its possible Go embed patterns (including all: patterns).
    for package in embedded_packages:
        for current, directories, names in os.walk(package, followlinks=False):
            directory = Path(current)
            for name in directories:
                if (directory / name).is_symlink():
                    raise RuntimeError(f"refusing symlinked embedded directory: {(directory / name).relative_to(repo)}")
            for name in names:
                path = directory / name
                validate_source_file(repo, path)
                sources.add(path)
    digest = hashlib.sha256()
    for path in sorted(sources, key=lambda source: os.fsencode(source.relative_to(repo).as_posix())):
        raw_path = os.fsencode(path.relative_to(repo).as_posix())
        contents = path.read_bytes()
        digest.update(len(raw_path).to_bytes(8, "big"))
        digest.update(raw_path)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def validate_source_file(repo: Path, path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError(f"refusing symlinked source input: {path.relative_to(repo)}")
    if not path.resolve().is_relative_to(repo) or not path.is_file():
        raise RuntimeError(f"source input is not a regular repository file: {path.relative_to(repo)}")


def git_revision(repo: Path, env: dict[str, str]) -> str:
    clean_env = {name: value for name, value in env.items() if not name.startswith("GIT_")}
    clean_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull, "GIT_OPTIONAL_LOCKS": "0"})
    result = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}", "rev-parse", "HEAD"],
        cwd=repo, env=clean_env, check=True, capture_output=True, text=True,
    )
    commit = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise RuntimeError("Git returned an invalid commit identity")
    return commit


def is_disk_backed(path: Path) -> bool:
    result = subprocess.run(
        ["/usr/bin/findmnt", "--json", "--target", str(path), "--output", "FSTYPE,SOURCE"],
        env={"LANG": "C.UTF-8", "LC_ALL": "C"},
        check=True, capture_output=True, text=True, timeout=10,
    )
    mounts = json.loads(result.stdout).get("filesystems", [])
    if len(mounts) != 1:
        raise RuntimeError(f"cannot establish temporary-directory mount: {path}")
    mount = mounts[0]
    source = mount.get("source", "")
    return mount.get("fstype") in DISK_FILESYSTEMS and not source.startswith(("/dev/zram", "/dev/ram"))


def temporary_parent() -> Path:
    if "TMPDIR" in os.environ:
        configured_value = os.environ["TMPDIR"]
        configured = Path(configured_value)
        if not configured_value or not configured.is_absolute():
            raise RuntimeError("configured TMPDIR must be an existing absolute directory")
        configured = configured.resolve(strict=True)
        if not configured.is_dir() or not os.access(configured, os.W_OK | os.X_OK):
            raise RuntimeError("configured TMPDIR must be a writable directory")
        if not is_disk_backed(configured):
            raise RuntimeError(f"configured TMPDIR is not verified disk-backed: {configured}")
        return configured
    configured = Path(tempfile.gettempdir()).resolve()
    if is_disk_backed(configured):
        return configured
    fallback = Path.home() / ".cache" / "development-tmp"
    fallback.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not is_disk_backed(fallback):
        raise RuntimeError(f"temporary storage is not verified disk-backed: {fallback}")
    return fallback


def build_environment(run_tmp: Path) -> dict[str, str]:
    cache = Path.home() / ".cache" / "doubletake"
    modules = cache / "go-mod"
    builds = cache / "go-build"
    modules.mkdir(mode=0o700, parents=True, exist_ok=True)
    builds.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Do not inherit GOENV, compiler overrides, preload libraries, or credentials.
    return {
        "HOME": str(Path.home()),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "TMPDIR": str(run_tmp),
        "CGO_ENABLED": "0",
        "GOENV": "off",
        "GOWORK": "off",
        "GOTOOLCHAIN": "local",
        "GOFLAGS": "-mod=readonly",
        "GOVCS": "*:off",
        "GOPROXY": "https://proxy.golang.org",
        "GOSUMDB": "sum.golang.org",
        "GOPRIVATE": "",
        "GONOPROXY": "",
        "GONOSUMDB": "",
        "GOMODCACHE": str(modules),
        "GOCACHE": str(builds),
        "GOMAXPROCS": "2",
        "GOMEMLIMIT": "640MiB",
    }


def verified_go(path: Path, env: dict[str, str]) -> Path:
    path = path.expanduser().resolve(strict=True)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"Go SDK executable unavailable: {path}")
    result = subprocess.run(
        [str(path), "version"], env=env, check=True, capture_output=True, text=True, timeout=10,
    )
    if not re.fullmatch(r"go version go1\.27\.2 linux/[a-z0-9]+\n?", result.stdout):
        raise RuntimeError(f"exact {GO_VERSION} Linux SDK required; received {result.stdout.strip()!r}")
    return path


def install_artifact(source: Path, destination: Path, mode: int) -> None:
    with tempfile.NamedTemporaryFile(prefix=".doubletake-", dir=destination.parent, delete=False) as output:
        temporary = Path(output.name)
        try:
            with source.open("rb") as input_file:
                shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), mode)
            output.close()
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)


def run_build(command: list[str], repo: Path, env: dict[str, str]) -> None:
    process = subprocess.Popen(command, cwd=repo, env=env, start_new_session=True)
    try:
        status = process.wait(timeout=300)
    except BaseException:
        # Cancel compiler children before the owned scratch directory is removed.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        raise
    if status:
        raise subprocess.CalledProcessError(status, command)


def build(repo: Path, go: Path) -> dict[str, object]:
    repo = repo.resolve()
    parent = temporary_parent()
    with tempfile.TemporaryDirectory(prefix="doubletake-build-", dir=parent) as run_tmp:
        scratch = Path(run_tmp)
        env = build_environment(scratch)
        go = verified_go(go, env)
        before = source_digest(repo)
        executable = scratch / "doubletake"
        run_build(
            [str(go), "build", "-p", "2", "-trimpath", "-buildvcs=false", "-o", str(executable), "./cmd/doubletake"],
            repo, env,
        )
        if source_digest(repo) != before:
            raise RuntimeError("Go sources changed during the build; output was not installed")
        commit = git_revision(repo, env)
        receipt = {
            "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "go_version": GO_VERSION,
            "source_sha256": before,
            "git_commit": commit,
            "cgo_enabled": False,
        }
        output_dir = repo / "bin"
        if output_dir.is_symlink():
            raise RuntimeError("refusing symlinked binary output directory")
        output_dir.mkdir(mode=0o700, exist_ok=True)
        receipt_source = scratch / "build-info.json"
        receipt_source.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        install_artifact(executable, output_dir / "doubletake", 0o700)
        install_artifact(receipt_source, output_dir / "build-info.json", 0o600)
        return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--go", type=Path,
        default=Path.home() / ".cache" / "development-tools" / "go1.27.2" / "bin" / "go",
        help="path to the already verified, exact Go 1.27.2 SDK executable (never downloaded)",
    )
    args = parser.parse_args()
    try:
        receipt = build(Path(__file__).resolve().parents[1], args.go)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"safe build failed: {error}", file=sys.stderr)
        return 1
    print(f"built bin/doubletake ({receipt['sha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
