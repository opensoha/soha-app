#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile


def verify_companion(path, version=None):
    names = {"manage.py", "soha-app-network.service", "service.example.json", "soha-app-service"}
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if {m.name for m in members} != {"network-service/" + n for n in names | {"manifest.json"}} or len(members) != 5:
            raise ValueError("Companion has unexpected or missing members")
        values = {}
        for member in members:
            if not member.isfile() or member.size > 128 * 1024 * 1024:
                raise ValueError("Companion member is not a bounded regular file")
            values[Path(member.name).name] = archive.extractfile(member).read()
        manifest = json.loads(values["manifest.json"])
        if (manifest.get("kind") != "opensoha-linux-network-service-assets-v1" or set(manifest.get("files", {})) != names or
                version is not None and manifest.get("version") != version):
            raise ValueError("Companion version or identity does not match the package")
        for name, expected in manifest["files"].items():
            if hashlib.sha256(values[name]).hexdigest() != expected:
                raise ValueError("Companion checksum mismatch")
        return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("companion", type=Path)
    parser.add_argument("--package-config", type=Path, required=True)
    parser.add_argument("--assets", type=Path)
    args = parser.parse_args()
    match = re.search(r'^version: "([A-Za-z0-9._+-]+)"$', args.package_config.read_text(), re.MULTILINE)
    if not match:
        raise SystemExit("Cannot determine package version")
    manifest = verify_companion(args.companion, match.group(1))
    if args.assets:
        if args.assets.is_symlink() or json.loads((args.assets / "manifest.json").read_text()) != manifest:
            raise SystemExit("Staged assets differ from the companion")
        for name, expected in manifest["files"].items():
            target = args.assets / name
            if not target.is_file() or target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != expected:
                raise SystemExit("Staged asset checksum mismatch")
