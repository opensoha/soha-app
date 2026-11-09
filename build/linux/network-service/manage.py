#!/usr/bin/env python3
"""Explicit administrator installation; package installation never enables this service."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid

UNIT = "soha-app-network.service"
STATE = "var/lib/opensoha/network-service"
BINARY = "usr/libexec/opensoha/soha-app-service"
UNIT_PATH = "etc/systemd/system/" + UNIT
RECEIPT = STATE + "/install-receipt.json"
PENDING_INSTALL = STATE + "/install-pending.json"
INSTALL_MODES = {BINARY: 0o755, UNIT_PATH: 0o644}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def strict_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RuntimeError("Duplicate JSON field")
            result[key] = value
        return result
    if path.stat().st_size > 262144:
        raise RuntimeError("Oversized service metadata")
    return json.loads(path.read_text(), object_pairs_hook=pairs)


class Platform:
    def command(self, *args):
        return subprocess.run(["/usr/bin/systemctl", *args], check=True, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout

    def available(self):
        if not Path("/run/systemd/system").is_dir():
            raise RuntimeError("Unsupported: systemd is required; use a supported systemd/NetworkManager installation")
        if "ActiveState=active" not in self.command("show", "NetworkManager.service", "--property=ActiveState"):
            raise RuntimeError("Unsupported: an active NetworkManager service is required")

    def info(self):
        result = subprocess.run(["/usr/bin/systemctl", "show", UNIT,
                                 "--property=LoadState,ActiveState,FragmentPath,DropInPaths,MainPID"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if result.returncode and info.get("LoadState") != "not-found":
            raise RuntimeError("Cannot inspect the systemd unit")
        return info

    def process(self, pid, binary):
        proc = Path("/proc") / str(pid)
        if proc.stat().st_uid != 0 or (proc / "exe").resolve() != binary:
            raise RuntimeError("The active unit process does not own the managed executable")
        if digest(proc / "exe") != digest(binary):
            raise RuntimeError("Active service executable identity changed")

    def version(self, binary):
        result = subprocess.run([str(binary), "version"], check=True, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return json.loads(result.stdout)

    def ipc(self, action, admission, pid):
        request_id = str(uuid.uuid4())
        request = {"version": 1, "requestId": request_id, "action": action}
        if admission is not None:
            request["admission"] = admission
        raw = json.dumps(request).encode()
        def read_exact(connection, size):
            data = b""
            while len(data) < size:
                part = connection.recv(size - len(data))
                if not part:
                    raise RuntimeError("Incomplete admission IPC response")
                data += part
            return data
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(120)
            connection.connect("/run/opensoha/network-service.sock")
            peer_pid, peer_uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_uid != 0 or peer_pid != pid:
                raise RuntimeError("Admission IPC peer is not the verified root service")
            connection.sendall(struct.pack(">I", len(raw)) + raw)
            length = struct.unpack(">I", read_exact(connection, 4))[0]
            if not 0 < length <= 1048576:
                raise RuntimeError("Invalid admission IPC frame")
            response = json.loads(read_exact(connection, length))
            if response.get("version") != 1 or response.get("requestId") != request_id or response.get("ok") is not True:
                raise RuntimeError("Admission IPC action failed; preserve service and inspect its status")
            return response.get("admission", {})

    def remove_profile(self, profile_id, pid):
        self.ipc("admission_remove", {"profileId": profile_id}, pid)

    def ready(self, pid):
        deadline = time.monotonic() + 10
        while True:
            try:
                status = self.ipc("admission_status", None, pid)
                if status.get("supported") is not True:
                    raise RuntimeError("Native admission unavailable: inspect NetworkManager version, supplicant methods and service privileges")
                return
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("Service IPC did not become ready; inspect systemctl status")
                time.sleep(0.1)


class Manager:
    def __init__(self, root=Path("/"), owner=0, platform=None):
        self.root, self.owner, self.platform = root, owner, platform or Platform()

    def path(self, relative):
        return self.root / relative

    def protected(self, path, secret=False):
        current = path
        while current != self.root:
            entry = current.lstat()
            if entry.st_uid != self.owner or stat.S_ISLNK(entry.st_mode) or entry.st_mode & 0o022:
                raise RuntimeError("Service path ownership, permissions or symlink changed")
            if current == path and secret and entry.st_mode & 0o077:
                raise RuntimeError("Service secret path is accessible by another user")
            if current == path and not (stat.S_ISREG(entry.st_mode) or stat.S_ISDIR(entry.st_mode)):
                raise RuntimeError("Service path is not a regular file or directory")
            if current.parent == current:
                raise RuntimeError("Service path escaped installation root")
            current = current.parent

    def mkdir(self, relative, mode):
        path = self.path(relative)
        if not path.exists():
            self.mkdir(str(Path(relative).parent), 0o755)
            path.mkdir(mode=mode)
            sync_directory(path.parent)
        self.protected(path, secret=mode == 0o700)
        return path

    def write(self, relative, payload, mode):
        path = self.path(relative)
        self.protected(path.parent)
        fd, temporary = tempfile.mkstemp(prefix=".soha-install-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), mode)
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            sync_directory(path.parent)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def configuration(self):
        path = self.path(STATE + "/service.json")
        self.protected(path, True)
        config = strict_json(path)
        uid = config.get("allowedUserUid")
        if (type(uid) is not int or not 0 < uid <= 2147483647 or config.get("allowedUserSid") or
                config.get("stateDirectory") != "/" + STATE or config.get("mihomoControllerUrl") or
                config.get("mihomoControllerSecretFile") or config.get("wireGuardExecutable")):
            raise RuntimeError("Linux admission requires an explicit desktop UID and protected admission-only configuration")
        for key in ("controlCaFile", "controlCertFile", "controlKeyFile", "ingestCaFile", "ingestCertFile", "ingestKeyFile"):
            value = config.get(key)
            if key.startswith("control") and not value:
                raise RuntimeError("Control mTLS files must be provisioned first")
            if value:
                if str(Path(value).parent) != "/" + STATE:
                    raise RuntimeError("Credentials must be files in the protected service state directory")
                self.protected(self.path(value.lstrip("/")), True)
        token = config.get("enrollmentTokenFile")
        if token:
            if str(Path(token).parent) != "/" + STATE:
                raise RuntimeError("Enrollment token path escaped service state directory")
            token_path = self.path(token.lstrip("/"))
            if token_path.exists():
                self.protected(token_path, True)
        return digest(path)

    def metadata(self, relative):
        path = self.path(relative)
        if not os.path.lexists(path):
            return None
        self.protected(path, True)
        value = strict_json(path)
        if not isinstance(value, dict):
            raise RuntimeError("Invalid service installation metadata")
        return value

    @staticmethod
    def validate_receipt(receipt):
        if (not isinstance(receipt, dict) or set(receipt) != {"version", "packageVersion", "configSha256", "files"} or
                type(receipt["version"]) is not int or receipt["version"] != 1 or
                not isinstance(receipt["packageVersion"], str) or
                not re.fullmatch(r"[A-Za-z0-9._+-]+", receipt["packageVersion"]) or
                not isinstance(receipt["files"], dict) or set(receipt["files"]) != set(INSTALL_MODES)):
            raise RuntimeError("Invalid service installation receipt")
        for expected in [receipt["configSha256"], *receipt["files"].values()]:
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise RuntimeError("Invalid service installation checksum")

    def receipt(self):
        receipt = self.metadata(RECEIPT)
        if receipt is not None:
            self.validate_receipt(receipt)
        return receipt

    def installed_files(self):
        files = {}
        for relative, mode in INSTALL_MODES.items():
            target = self.path(relative)
            if not os.path.lexists(target):
                files[relative] = None
                continue
            self.protected(target)
            entry = target.lstat()
            if not stat.S_ISREG(entry.st_mode) or stat.S_IMODE(entry.st_mode) != mode:
                raise RuntimeError("Installed service or unit mode drifted")
            files[relative] = digest(target)
        return files

    def pending_install(self, receipt, files, config_hash):
        pending = self.metadata(PENDING_INSTALL)
        if pending is None:
            return None
        if set(pending) != {"version", "previous", "target"} or type(pending["version"]) is not int or pending["version"] != 1:
            raise RuntimeError("Invalid pending service installation")
        previous, target = pending["previous"], pending["target"]
        self.validate_receipt(target)
        if previous is not None:
            self.validate_receipt(previous)
        if target["configSha256"] != config_hash or previous is not None and previous["configSha256"] != config_hash:
            raise RuntimeError("Administrator configuration drifted during installation")
        if receipt != previous and (receipt != target or files != target["files"]):
            raise RuntimeError("Service installation receipt drifted during installation")
        old_files = previous["files"] if previous is not None else {}
        if any(value not in (old_files.get(path), target["files"][path]) for path, value in files.items()):
            raise RuntimeError("Service files drifted during installation; preserving them")
        return pending

    def owned_unit(self, installed, allow_unloaded=False):
        info = self.platform.info()
        if info.get("DropInPaths"):
            raise RuntimeError("External systemd drop-ins were preserved")
        if info.get("LoadState") == "not-found":
            if installed and not allow_unloaded:
                raise RuntimeError("The recorded service unit is missing from systemd")
            if int(info.get("MainPID", "0")) != 0 or info.get("ActiveState") not in ("inactive", "failed"):
                raise RuntimeError("The missing unit has an unresolved service process")
            return info
        if not installed or info.get("LoadState") != "loaded" or info.get("FragmentPath") != "/" + UNIT_PATH:
            raise RuntimeError("An external service owns the unit name")
        pid = int(info.get("MainPID", "0"))
        if pid:
            self.platform.process(pid, self.path(BINARY))
        elif info.get("ActiveState") not in ("inactive", "failed"):
            raise RuntimeError("Service transition in progress; retry after it settles")
        return info

    def cleanup_admission(self, info):
        state_path = self.path(STATE + "/eap-state.json")
        if not state_path.exists():
            return
        self.protected(state_path, True)
        state = strict_json(state_path)
        selections = state.get("selections", [])
        if state.get("version") != 1 or not isinstance(selections, list) or len(selections) > 8:
            raise RuntimeError("Invalid admission recovery state")
        if not selections:
            return
        pid = int(info.get("MainPID", "0"))
        if not pid:
            raise RuntimeError("Managed admission remains: start the verified service and remove profiles in the App before retrying")
        for selection in selections:
            profile_id = selection.get("profile", {}).get("id", "")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", profile_id):
                raise RuntimeError("Invalid managed admission identity")
            self.platform.remove_profile(profile_id, pid)

    def install(self, assets):
        self.platform.available()
        config_hash = self.configuration()
        receipt = self.receipt()
        files = self.installed_files()
        pending = self.pending_install(receipt, files, config_hash)
        if pending is None:
            if receipt:
                if receipt["configSha256"] != config_hash:
                    raise RuntimeError("Administrator configuration drifted; explicit recovery is required")
                if files != receipt["files"]:
                    raise RuntimeError("Installed service or unit drifted; refusing replacement")
            elif any(value is not None for value in files.values()):
                raise RuntimeError("Unowned installation file already exists")
        info = self.owned_unit(files[UNIT_PATH] is not None, allow_unloaded=pending is not None)
        for name in ("manifest.json", "soha-app-service", UNIT, "manage.py", "service.example.json"):
            self.protected(assets / name)
        manifest = strict_json(assets / "manifest.json")
        if manifest.get("kind") != "opensoha-linux-network-service-assets-v1" or set(manifest.get("files", {})) != {"soha-app-service", UNIT, "manage.py", "service.example.json"} or not re.fullmatch(r"[A-Za-z0-9._+-]+", manifest.get("version", "")):
            raise RuntimeError("Invalid packaged service manifest")
        for name, expected in manifest["files"].items():
            if digest(assets / name) != expected:
                raise RuntimeError("Packaged service assets changed")
        version = self.platform.version(assets / "soha-app-service")
        if version.get("name") != "soha-app-service" or version.get("version") != manifest["version"]:
            raise RuntimeError("Packaged service version does not match the App package")
        new_receipt = {"version": 1, "packageVersion": manifest["version"], "configSha256": config_hash,
                       "files": {BINARY: manifest["files"]["soha-app-service"], UNIT_PATH: manifest["files"][UNIT]}}
        self.validate_receipt(new_receipt)
        if pending is not None and pending["target"] != new_receipt:
            raise RuntimeError("Resume installation using the same verified package " + pending["target"]["packageVersion"])
        payloads = {BINARY: (assets / "soha-app-service").read_bytes(), UNIT_PATH: (assets / UNIT).read_bytes()}
        if any(hashlib.sha256(payload).hexdigest() != new_receipt["files"][path] for path, payload in payloads.items()):
            raise RuntimeError("Packaged service assets changed during verification")
        if pending is None:
            pending = {"version": 1, "previous": receipt, "target": new_receipt}
            # Preserve the previous receipt until both files and service readiness are confirmed.
            self.write(PENDING_INSTALL, (json.dumps(pending) + "\n").encode(), 0o600)
        if info.get("LoadState") == "loaded":
            self.platform.command("stop", UNIT)
            stopped = self.owned_unit(True, allow_unloaded=True)
            if int(stopped.get("MainPID", "0")) != 0:
                raise RuntimeError("Service process has not stopped")
        self.mkdir("usr/libexec/opensoha", 0o755)
        self.mkdir("etc/systemd/system", 0o755)
        files = self.installed_files()
        if self.pending_install(self.receipt(), files, self.configuration()) != pending:
            raise RuntimeError("Pending service installation changed before writing files")
        for relative, payload in payloads.items():
            if files[relative] != new_receipt["files"][relative]:
                self.write(relative, payload, INSTALL_MODES[relative])
        if self.installed_files() != new_receipt["files"] or self.configuration() != config_hash:
            raise RuntimeError("Installed service or configuration changed before activation")
        self.platform.command("daemon-reload")
        self.platform.command("enable", "--now", UNIT)
        current = self.owned_unit(True)
        if current.get("ActiveState") != "active" or int(current.get("MainPID", "0")) <= 0:
            raise RuntimeError("Service did not start; use systemctl status and rerun the same verified installation")
        self.platform.ready(int(current["MainPID"]))
        files = self.installed_files()
        if files != new_receipt["files"] or self.pending_install(self.receipt(), files, self.configuration()) != pending:
            raise RuntimeError("Pending service installation changed before committing the receipt")
        self.write(RECEIPT, (json.dumps(new_receipt) + "\n").encode(), 0o600)
        journal = self.path(PENDING_INSTALL)
        journal.unlink()
        sync_directory(journal.parent)

    def uninstall(self):
        receipt = self.receipt()
        files = self.installed_files()
        if os.path.lexists(self.path(PENDING_INSTALL)):
            pending = self.pending_install(receipt, files, self.configuration())
            raise RuntimeError("Resume installation using the same verified package " + pending["target"]["packageVersion"] + " before uninstalling")
        if files != (receipt["files"] if receipt else dict.fromkeys(INSTALL_MODES)):
            raise RuntimeError("Installed service or unit drifted; refusing removal")
        info = self.owned_unit(receipt is not None)
        if not receipt:
            return
        if receipt.get("configSha256") != self.configuration():
            raise RuntimeError("Configuration drifted; refusing automatic cleanup")
        self.cleanup_admission(info)
        self.platform.command("disable", "--now", UNIT)
        if int(self.platform.info().get("MainPID", "0")) != 0:
            raise RuntimeError("Service process has not stopped")
        for relative, expected in receipt["files"].items():
            path = self.path(relative)
            self.protected(path)
            if digest(path) != expected:
                raise RuntimeError("Installed file changed during removal")
        for relative in receipt["files"]:
            self.path(relative).unlink()
        self.path(RECEIPT).unlink()
        self.platform.command("daemon-reload")
        # Never delete service.json, enrollment identity, keys, state directories or unrelated profiles.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "uninstall"))
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("Explicit root authorization on Linux is required; ordinary App launch never installs this service")
    manager = Manager()
    if args.action == "uninstall" and not any(os.path.lexists(manager.path(path)) for path in (RECEIPT, PENDING_INSTALL)):
        if any(os.path.lexists(manager.path(path)) for path in INSTALL_MODES):
            raise RuntimeError("Unowned service files were preserved")
        return
    manager.mkdir(STATE, 0o700)
    manager.protected(Path("/usr/bin/systemctl"))
    lock_path = manager.path(STATE + "/install.lock")
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "r+") as lock:
        manager.protected(lock_path, True)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "install":
            manager.install(Path(__file__).resolve().parent)
        else:
            manager.uninstall()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("Soha network service: " + str(error), file=sys.stderr)
        sys.exit(1)
