import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import build_safe


class BuildSafeTests(unittest.TestCase):
    def test_digest_covers_current_untracked_and_tracked_go_sources(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-source-") as directory:
            repo = Path(directory)
            (repo / "go.mod").write_bytes(b"module example\n")
            (repo / "tracked.go").write_bytes(b"package example\n")
            (repo / "new.go").write_bytes(b"package example // new\n")
            (repo / "notes.md").write_bytes(b"not compiled")
            expected = hashlib.sha256()
            for name in ["go.mod", "new.go", "tracked.go"]:
                contents = (repo / name).read_bytes()
                expected.update(len(name.encode()).to_bytes(8, "big") + name.encode())
                expected.update(len(contents).to_bytes(8, "big") + contents)
            original = build_safe.source_digest(repo)
            self.assertEqual(original, expected.hexdigest())
            (repo / "notes.md").write_bytes(b"changed documentation")
            self.assertEqual(build_safe.source_digest(repo), original)
            (repo / "new.go").write_bytes(b"package example // changed\n")
            self.assertNotEqual(build_safe.source_digest(repo), original)

    def test_digest_frames_binary_file_boundaries(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-binary-") as directory:
            repo = Path(directory)
            first, second = repo / "a.syso", repo / "b.syso"
            first.write_bytes(b"one")
            second.write_bytes(b"two" + b"b.syso\0" + b"three")
            before = build_safe.source_digest(repo)
            first.write_bytes(b"one" + b"b.syso\0" + b"two")
            second.write_bytes(b"three")
            self.assertNotEqual(build_safe.source_digest(repo), before)

    def test_digest_refuses_symlinked_go_source(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-source-") as directory:
            repo = Path(directory)
            (repo / "target.go").write_text("package example\n")
            (repo / "link.go").symlink_to("target.go")
            with self.assertRaisesRegex(RuntimeError, "symlinked"):
                build_safe.source_digest(repo)

    def test_digest_covers_ignored_go_assembly_and_linker_objects(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-inputs-") as directory:
            repo = Path(directory)
            (repo / ".gitignore").write_text("ignored.go\n*.s\n*.S\n*.h\n*.syso\n")
            baseline = build_safe.source_digest(repo)
            for name in ["ignored.go", "assembly.s", "assembly.S", "header.h", "object.syso"]:
                with self.subTest(name=name):
                    path = repo / name
                    path.write_bytes(b"initial")
                    current = build_safe.source_digest(repo)
                    self.assertNotEqual(current, baseline)
                    path.write_bytes(b"changed")
                    self.assertNotEqual(build_safe.source_digest(repo), current)
                    path.unlink()
                    self.assertEqual(build_safe.source_digest(repo), baseline)

    def test_digest_covers_arbitrary_ignored_embedded_assets(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-embed-") as directory:
            repo = Path(directory)
            package = repo / "internal" / "assets"
            package.mkdir(parents=True)
            (package / "assets.go").write_bytes(b'package assets\nimport "embed"\n//go:embed all:data\nvar Files embed.FS\n')
            assets = package / "data"
            assets.mkdir()
            (repo / ".gitignore").write_text("internal/assets/data\n")
            original = build_safe.source_digest(repo)
            resource = assets / ".hidden.asset"
            resource.write_bytes(b"initial asset")
            added = build_safe.source_digest(repo)
            self.assertNotEqual(added, original)
            resource.write_bytes(b"changed asset")
            self.assertNotEqual(build_safe.source_digest(repo), added)
            resource.unlink()
            self.assertEqual(build_safe.source_digest(repo), original)
            resource.symlink_to(package / "assets.go")
            with self.assertRaisesRegex(RuntimeError, "symlinked"):
                build_safe.source_digest(repo)

    def test_digest_rejects_symlinked_source_directories(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-source-") as directory:
            repo = Path(directory)
            actual = repo / "actual"
            actual.mkdir()
            (actual / "input.go").write_text("package actual\n")
            (repo / "linked").symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symlinked source directory"):
                build_safe.source_digest(repo)

    def test_git_revision_cannot_inherit_executable_git_configuration(self):
        commit = "a" * 40
        env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "malicious-hook", "GIT_DIR": "/foreign", "GIT_WORK_TREE": "/foreign", "GIT_TRACE": "/foreign"}
        with patch.object(build_safe.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, commit + "\n")) as run:
            self.assertEqual(build_safe.git_revision(Path("/repo"), env), commit)
        args, kwargs = run.call_args
        self.assertIn("core.fsmonitor=false", args[0])
        self.assertIn("core.hooksPath=" + os.devnull, args[0])
        clean_env = kwargs["env"]
        self.assertEqual(clean_env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(clean_env["GIT_CONFIG_SYSTEM"], os.devnull)
        self.assertEqual(clean_env["GIT_CONFIG_NOSYSTEM"], "1")
        for key in env:
            if key.startswith("GIT_"):
                self.assertNotIn(key, clean_env)

    def test_mount_detection_rejects_ram_and_unidentified_storage(self):
        for fstype, source, expected in [("tmpfs", "tmpfs", False), ("btrfs", "/dev/nvme0n1", True), ("ext4", "/dev/zram0", False), ("overlay", "overlay", False)]:
            with self.subTest(fstype=fstype, source=source):
                result = subprocess.CompletedProcess([], 0, json.dumps({"filesystems": [{"fstype": fstype, "source": source}]}))
                with patch.object(build_safe.subprocess, "run", return_value=result):
                    self.assertEqual(build_safe.is_disk_backed(Path("/temporary")), expected)

    def test_configured_disk_temp_directory_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-configured-") as directory:
            with patch.dict(os.environ, {"TMPDIR": directory}), patch.object(build_safe, "is_disk_backed", return_value=True):
                self.assertEqual(build_safe.temporary_parent(), Path(directory).resolve())

    def test_explicit_memory_tmpdir_is_refused_without_fallback(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-configured-") as directory:
            with patch.dict(os.environ, {"TMPDIR": directory}), patch.object(build_safe, "is_disk_backed", return_value=False) as check:
                with self.assertRaisesRegex(RuntimeError, "configured TMPDIR is not verified disk-backed"):
                    build_safe.temporary_parent()
                check.assert_called_once_with(Path(directory).resolve())

    def test_invalid_explicit_tmpdir_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-configured-") as directory:
            for value in ["", "relative/path", str(Path(directory) / "missing")]:
                with self.subTest(value=value), patch.dict(os.environ, {"TMPDIR": value}):
                    with self.assertRaises((OSError, RuntimeError)):
                        build_safe.temporary_parent()

    def test_mount_detection_does_not_inherit_executable_overrides(self):
        result = subprocess.CompletedProcess([], 0, json.dumps({"filesystems": [{"fstype": "btrfs", "source": "/dev/nvme0n1"}]}))
        with patch.dict(os.environ, {"PATH": "/malicious", "LD_PRELOAD": "/malicious.so", "LIBMOUNT_FSTAB": "/malicious"}), patch.object(build_safe.subprocess, "run", return_value=result) as run:
            self.assertTrue(build_safe.is_disk_backed(Path("/directory")))
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "/usr/bin/findmnt")
        self.assertEqual(kwargs["env"], {"LANG": "C.UTF-8", "LC_ALL": "C"})

    def test_memory_temp_directory_falls_back_to_verified_disk(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-home-") as directory:
            home = Path(directory)
            with patch.dict(os.environ, {}, clear=True), patch.object(build_safe.Path, "home", return_value=home), patch.object(build_safe.tempfile, "gettempdir", return_value="/memory"), patch.object(build_safe, "is_disk_backed", side_effect=[False, True]) as check:
                self.assertEqual(build_safe.temporary_parent(), home / ".cache" / "development-tmp")
                self.assertEqual(check.call_count, 2)

    def test_build_environment_discards_external_toolchain_overrides(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-home-") as directory:
            with patch.object(build_safe.Path, "home", return_value=Path(directory)), patch.dict(os.environ, {"GOFLAGS": "-toolexec=untrusted", "GOTOOLCHAIN": "auto", "LD_PRELOAD": "/untrusted.so", "DOUBLETAKE_PASSWORD": "secret"}):
                env = build_safe.build_environment(Path(directory) / "run")
            self.assertEqual(env["GOFLAGS"], "-mod=readonly")
            self.assertEqual(env["GOTOOLCHAIN"], "local")
            self.assertEqual(env["GOVCS"], "*:off")
            self.assertEqual(env["CGO_ENABLED"], "0")
            self.assertNotIn("LD_PRELOAD", env)
            self.assertNotIn("DOUBLETAKE_PASSWORD", env)

    def test_sdk_requires_exact_version(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-sdk-") as directory:
            sdk = Path(directory) / "go"
            sdk.write_text("placeholder")
            sdk.chmod(0o700)
            for version, accepted in [("go version go1.27.2 linux/amd64\n", True), ("go version go1.27.1 linux/amd64\n", False), ("go version go1.27.2 darwin/arm64\n", False), ("go version go1.27.20 linux/amd64\n", False)]:
                with self.subTest(version=version), patch.object(build_safe.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, version)):
                    if accepted:
                        self.assertEqual(build_safe.verified_go(sdk, {}), sdk)
                    else:
                        with self.assertRaises(RuntimeError):
                            build_safe.verified_go(sdk, {})

    def test_changing_sources_does_not_install_output_and_cleans_scratch(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-builder-") as directory:
            root = Path(directory)
            repo = root / "repo"
            repo.mkdir()
            with patch.object(build_safe, "temporary_parent", return_value=root), patch.object(build_safe, "build_environment", return_value={}), patch.object(build_safe, "verified_go", return_value=Path("/pinned/go")), patch.object(build_safe, "source_digest", side_effect=["before", "after"]), patch.object(build_safe, "run_build"):
                with self.assertRaisesRegex(RuntimeError, "sources changed"):
                    build_safe.build(repo, Path("/pinned/go"))
            self.assertFalse((repo / "bin").exists())
            self.assertEqual(list(root.iterdir()), [repo])

    def test_install_is_atomic_owner_only_and_cleans_temporary_output(self):
        with tempfile.TemporaryDirectory(prefix="doubletake-artifact-") as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"verified-binary")
            destination = root / "binary"
            destination.write_bytes(b"old-binary")
            build_safe.install_artifact(source, destination, 0o700)
            self.assertEqual(destination.read_bytes(), b"verified-binary")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertEqual({path.name for path in root.iterdir()}, {"source", "binary"})


if __name__ == "__main__":
    unittest.main()
