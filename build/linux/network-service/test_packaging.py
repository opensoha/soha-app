import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import manage
import stage
import version_receipt
from verify_companion import verify_companion


class FakePlatform:
    def __init__(self):
        self.current = {"LoadState": "not-found", "ActiveState": "inactive", "MainPID": "0", "DropInPaths": ""}
        self.calls = []
        self.supported = True
        self.foreign = False
        self.cleanup_error = False
        self.package_version = "0.2.0"

    def available(self):
        if not self.supported:
            raise RuntimeError("unsupported systemd/NetworkManager")

    def info(self):
        return dict(self.current)

    def process(self, pid, binary):
        if self.foreign or pid != 123:
            raise RuntimeError("external process")

    def version(self, _):
        return {"name": "soha-app-service", "version": self.package_version}

    def command(self, *args):
        self.calls.append(args)
        if args[0] == "enable":
            self.current.update(LoadState="loaded", ActiveState="active", MainPID="123", FragmentPath="/" + manage.UNIT_PATH)
        elif args[0] in ("stop", "disable"):
            self.current.update(ActiveState="inactive", MainPID="0")

    def remove_profile(self, profile_id, pid):
        if self.cleanup_error:
            raise RuntimeError("cleanup pending")
        self.calls.append(("remove_profile", profile_id, pid))

    def ready(self, pid):
        if pid != 123:
            raise RuntimeError("untrusted peer")
        self.calls.append(("ready", pid))


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.platform = FakePlatform()
        self.manager = manage.Manager(self.root, os.geteuid(), self.platform)
        state = self.manager.mkdir(manage.STATE, 0o700)
        self.credentials = {}
        for name in ("control-ca.pem", "control-cert.pem", "control-key.pem"):
            path = state / name
            path.write_text("existing private provisioning material")
            path.chmod(0o600)
            self.credentials[name] = path.read_bytes()
        self.config = {"allowedUserUid": 1000, "stateDirectory": "/" + manage.STATE,
                       "controlCaFile": "/" + manage.STATE + "/control-ca.pem",
                       "controlCertFile": "/" + manage.STATE + "/control-cert.pem",
                       "controlKeyFile": "/" + manage.STATE + "/control-key.pem"}
        self.config_path = state / "service.json"
        self.config_path.write_text(json.dumps(self.config))
        self.config_path.chmod(0o600)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        source = Path(__file__).parent
        for name in (manage.UNIT, "manage.py", "service.example.json"):
            shutil.copyfile(source / name, self.assets / name)
        (self.assets / "soha-app-service").write_bytes(b"owned service fixture")
        self.manifest = {"kind": "opensoha-linux-network-service-assets-v1", "version": "0.2.0", "files": {
            name: manage.digest(self.assets / name) for name in (manage.UNIT, "manage.py", "service.example.json", "soha-app-service")}}
        (self.assets / "manifest.json").write_text(json.dumps(self.manifest))

    def install(self):
        self.manager.install(self.assets)

    def interrupt_write(self, relative, after=False):
        write = self.manager.write

        def interrupted(path, payload, mode):
            if path != relative or after:
                write(path, payload, mode)
            if path == relative:
                raise OSError("interrupted install")

        with mock.patch.object(self.manager, "write", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "interrupted install"):
                self.install()
        self.manager = manage.Manager(self.root, os.geteuid(), self.platform)

    def selections(self):
        path = self.root / manage.STATE / "eap-state.json"
        path.write_text(json.dumps({"version": 1, "selections": [{"profile": {"id": "profile-1"}}]}))
        path.chmod(0o600)

    def assert_credentials_preserved(self):
        for name, expected in self.credentials.items():
            self.assertEqual((self.root / manage.STATE / name).read_bytes(), expected)
        self.assertEqual(json.loads(self.config_path.read_text()), self.config)

    def test_install_upgrade_uninstall_preserves_provisioning(self):
        self.install()
        self.selections()
        self.install()
        self.assertNotIn(("remove_profile", "profile-1", 123), self.platform.calls)
        self.manager.uninstall()
        self.assertIn(("remove_profile", "profile-1", 123), self.platform.calls)
        self.assertFalse((self.root / manage.BINARY).exists())
        self.assertFalse((self.root / manage.UNIT_PATH).exists())
        self.assertTrue((self.root / manage.STATE / "eap-state.json").exists())
        self.assert_credentials_preserved()

    def test_interrupted_first_install_resumes_only_owned_files(self):
        self.interrupt_write(manage.UNIT_PATH)
        binary = self.root / manage.BINARY
        journal = self.root / manage.PENDING_INSTALL
        self.assertFalse((self.root / manage.RECEIPT).exists())
        self.assertTrue(journal.is_file())
        self.assertEqual(manage.strict_json(journal)["previous"], None)
        self.assertFalse((self.root / manage.UNIT_PATH).exists())
        with self.assertRaisesRegex(RuntimeError, "before uninstalling"):
            self.manager.uninstall()
        owned = binary.read_bytes()
        binary.write_bytes(b"unexpected file")
        with self.assertRaisesRegex(RuntimeError, "files drifted"):
            self.install()
        self.assertEqual(self.platform.calls, [])
        self.assertEqual(binary.read_bytes(), b"unexpected file")
        binary.write_bytes(owned)
        self.install()
        self.assertFalse(journal.exists())
        self.assertEqual(self.manager.receipt()["files"], self.manager.installed_files())
        self.assert_credentials_preserved()

    def test_interrupted_upgrade_accepts_only_same_package_and_finishes_receipt(self):
        self.install()
        self.selections()
        old_receipt = self.manager.receipt()
        old_unit = (self.root / manage.UNIT_PATH).read_bytes()
        binary = self.assets / "soha-app-service"
        binary.write_bytes(b"verified upgrade service")
        (self.assets / manage.UNIT).write_bytes(old_unit + b"\n# updated unit\n")
        self.manifest["version"] = self.platform.package_version = "0.2.1"
        for name in (manage.UNIT, "soha-app-service"):
            self.manifest["files"][name] = manage.digest(self.assets / name)
        (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
        self.interrupt_write(manage.UNIT_PATH)
        self.assertEqual(self.manager.receipt(), old_receipt)
        self.assertEqual((self.root / manage.BINARY).read_bytes(), binary.read_bytes())
        self.assertEqual((self.root / manage.UNIT_PATH).read_bytes(), old_unit)
        calls = list(self.platform.calls)
        self.manifest["version"] = self.platform.package_version = "0.2.2"
        (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(RuntimeError, "same verified package 0.2.1"):
            self.install()
        self.assertEqual(self.platform.calls, calls)
        self.manifest["version"] = self.platform.package_version = "0.2.1"
        (self.assets / "manifest.json").write_text(json.dumps(self.manifest))
        self.interrupt_write(manage.RECEIPT, after=True)
        self.assertEqual(self.manager.receipt()["packageVersion"], "0.2.1")
        self.assertTrue((self.root / manage.PENDING_INSTALL).is_file())
        self.install()
        self.assertFalse((self.root / manage.PENDING_INSTALL).exists())
        self.assertNotIn(("remove_profile", "profile-1", 123), self.platform.calls)
        self.manager.uninstall()
        self.assertIn(("remove_profile", "profile-1", 123), self.platform.calls)
        self.assert_credentials_preserved()

    def test_unconfigured_package_does_not_activate_a_service(self):
        self.assertEqual(self.platform.calls, [])
        self.assertFalse((self.root / manage.BINARY).exists())

    def test_install_rejects_unsupported_unknown_unit_or_bad_version(self):
        for mode in ("unsupported", "external", "version"):
            with self.subTest(mode=mode):
                self.platform.supported = mode != "unsupported"
                self.platform.current["LoadState"] = "loaded" if mode == "external" else "not-found"
                self.platform.package_version = "wrong" if mode == "version" else "0.2.0"
                with self.assertRaises(RuntimeError):
                    self.install()
                self.assertFalse((self.root / manage.BINARY).exists())
        self.assert_credentials_preserved()

    def test_installed_file_config_dropin_and_process_drift_are_preserved(self):
        self.install()
        binary = self.root / manage.BINARY
        original = binary.read_bytes()
        for mode in ("binary", "configuration", "dropin", "process"):
            with self.subTest(mode=mode):
                if mode == "binary":
                    binary.write_bytes(b"external replacement")
                if mode == "configuration":
                    self.config_path.write_text(json.dumps({**self.config, "allowedUserUid": 2000}))
                self.platform.current["DropInPaths"] = "/etc/systemd/system/external.conf" if mode == "dropin" else ""
                self.platform.foreign = mode == "process"
                calls = list(self.platform.calls)
                with self.assertRaises(RuntimeError):
                    self.install()
                self.assertEqual(self.platform.calls, calls)
                if mode == "binary":
                    self.assertEqual(binary.read_bytes(), b"external replacement")
                    binary.write_bytes(original)
                self.config_path.write_text(json.dumps(self.config))
        self.assert_credentials_preserved()

    def test_uninstall_preserves_files_when_cleanup_cannot_complete(self):
        self.install()
        self.selections()
        self.platform.current.update(MainPID="0", ActiveState="inactive")
        with self.assertRaises(RuntimeError):
            self.manager.uninstall()
        self.assertTrue((self.root / manage.BINARY).exists())
        self.platform.current.update(MainPID="123", ActiveState="active")
        self.platform.cleanup_error = True
        with self.assertRaises(RuntimeError):
            self.manager.uninstall()
        self.assertTrue((self.root / manage.UNIT_PATH).exists())
        self.assert_credentials_preserved()

    def test_unowned_path_symlink_and_packaged_drift_are_rejected(self):
        key = self.root / manage.STATE / "control-key.pem"
        key.unlink()
        key.symlink_to(self.root / manage.STATE / "control-ca.pem")
        with self.assertRaises(RuntimeError):
            self.install()
        key.unlink()
        key.write_bytes(self.credentials["control-key.pem"])
        key.chmod(0o600)
        (self.assets / manage.UNIT).write_text("external unit")
        with self.assertRaises(RuntimeError):
            self.install()
        self.assertFalse((self.root / manage.BINARY).exists())

    def test_companion_version_checksum_and_existing_output_guard(self):
        config = self.root / "nfpm.yaml"
        config.write_text('version: "0.2.0"\n')
        output = self.root / "staged"
        companion = self.root / "companion.tar.gz"
        binary = self.assets / "soha-app-service"
        with mock.patch.object(stage, "build_version", return_value="0.2.0"):
            stage.stage(binary, self.assets, output, config, companion, binary)
            verify_companion(companion, "0.2.0")
            stage.stage(binary, self.assets, output, config, companion, binary)
            with self.assertRaises(ValueError):
                verify_companion(companion, "0.2.1")
            (output / "manage.py").write_text("external edit")
            with self.assertRaises(ValueError):
                stage.stage(binary, self.assets, output, config, companion, binary)
            self.assertEqual((output / "manage.py").read_text(), "external edit")
        with mock.patch.object(stage, "build_version", return_value="0.2.1"):
            with self.assertRaises(ValueError):
                stage.stage(binary, self.assets, self.root / "wrong-version", config, self.root / "wrong.tar.gz", binary)

    def test_source_linked_version_receipt_rejects_changed_binary_and_wrong_app_version(self):
        config = self.root / "package.yaml"
        config.write_text('version: "0.2.0"\n')
        binary = self.assets / "soha-app-service"
        version_receipt.record(binary, "service", config, "-X main.serviceVersion=0.2.0")
        self.assertEqual(stage.build_version(binary, "main.serviceVersion"), "0.2.0")
        binary.write_bytes(b"different executable")
        with self.assertRaises(ValueError):
            stage.build_version(binary, "main.serviceVersion")
        with self.assertRaises(ValueError):
            version_receipt.record(binary, "app", config, "-X main.appBuildVersion=0.2.1")
        with self.assertRaises(ValueError):
            version_receipt.record(binary, "app", config, "-X main.appBuildVersion=0.2.0!")
        with self.assertRaises(ValueError):
            version_receipt.record(binary, "app", config, "-X=main.appBuildVersion=0.2.0 -X main.appBuildVersion=0.2.1")
        version_receipt.record(binary, "app", config, "-X=main.appBuildVersion=0.2.1 -X main.appBuildVersion=0.2.0")
        self.assertEqual(stage.build_version(binary, "main.appBuildVersion"), "0.2.0")

    def test_cross_image_release_flags_only_affect_linux(self):
        root = Path(__file__).parents[3]
        dockerfile = (root / "build/docker/Dockerfile.cross").read_text()
        block = dockerfile.split('EXT=""', 1)[1].split('TAGS="production"', 1)[0]
        for platform, flags, expected in [("linux", "", "-s -w"), ("linux", "-X main.appBuildVersion=0.3.0", "-s -w -X main.appBuildVersion=0.3.0"),
                                           ("windows", "-X main.appBuildVersion=0.3.0", "-s -w -H windowsgui"), ("darwin", "-X main.appBuildVersion=0.3.0", "-s -w")]:
            result = subprocess.run(["/bin/sh", "-c", block + '\nprintf \'%s\' "$LDFLAGS"'], check=True, text=True,
                                    stdout=subprocess.PIPE, env={**os.environ, "GOOS": platform, "RELEASE_LDFLAGS": flags})
            self.assertEqual(result.stdout, expected)
        taskfile = (root / "build/linux/Taskfile.yml").read_text()
        self.assertIn("SOHA_LINUX_RELEASE_FLAGS_V1", taskfile)
        self.assertIn("--network none", taskfile)
        self.assertIn('-e RELEASE_LDFLAGS="{{.RELEASE_LDFLAGS}}"', taskfile)

    def test_linux_only_image_rejects_other_platforms_without_changing_default(self):
        root = Path(__file__).parents[3]
        dockerfile = (root / "build/docker/Dockerfile.cross").read_text()
        self.assertIn("ARG SOHA_CROSS_TARGET=all", dockerfile)
        self.assertIn("Linux-only builder: Zig is not required", dockerfile)
        self.assertIn("Linux-only builder: macOS SDK is not required", dockerfile)
        self.assertIn('sha256sum -c -', dockerfile)
        prologue = dockerfile.split("COPY <<'SCRIPT' /usr/local/bin/build.sh\n", 1)[1].split('case "${OS}-${ARCH}"', 1)[0]
        for target in ("all", "linux"):
            for platform in ("linux", "windows", "darwin"):
                result = subprocess.run(["/bin/sh", "-c", prologue + "\nprintf accepted", "build.sh", platform, "amd64"],
                                        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        env={**os.environ, "SOHA_CROSS_TARGET": target})
                self.assertEqual(result.returncode == 0, target == "all" or platform == "linux")

    def test_ipc_rejects_non_root_or_wrong_process_before_send(self):
        for uid, pid in ((1000, 123), (0, 456)):
            connection = mock.MagicMock()
            connection.__enter__.return_value = connection
            connection.getsockopt.return_value = struct.pack("3i", pid, uid, 0)
            with mock.patch.object(manage.socket, "socket", return_value=connection), mock.patch.object(manage.socket, "SO_PEERCRED", 17, create=True):
                with self.assertRaises(RuntimeError):
                    manage.Platform().remove_profile("profile-1", 123)
            connection.sendall.assert_not_called()


if __name__ == "__main__":
    unittest.main()
