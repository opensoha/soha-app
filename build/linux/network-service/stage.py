#!/usr/bin/env python3
"""Assemble the Linux service companion from the same package version as nfpm."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tarfile
from verify_companion import verify_companion


def build_version(binary, key):
    receipt = Path(str(binary) + ".version.json")
    if receipt.exists():
        value = json.loads(receipt.read_text())
        expected_kind = "service" if key == "main.serviceVersion" else "app"
        if (receipt.is_symlink() or value.get("kind") != "opensoha-linux-build-version-v1" or value.get("buildKind") != expected_kind or
                value.get("binary") != str(binary.resolve()) or value.get("sha256") != hashlib.sha256(binary.read_bytes()).hexdigest()):
            raise ValueError("Build version receipt does not match the binary")
        source = value.get("versionSource", {})
        symbols = {"main.serviceVersion"} if expected_kind == "service" else {"main.appBuildVersion", "main.fallbackAppVersion"}
        if source.get("symbol") not in symbols or source.get("value") != value.get("version") or source.get("kind") not in ({"linker-X"} if expected_kind == "service" else {"linker-X", "source-default"}):
            raise ValueError("Build version receipt has no matching source/linker evidence")
        return value.get("version")
    raise ValueError("Build version receipt missing; rebuild using the Linux Tasks")


def stage(binary, source, output, package_config, companion, app_binary):
    match = re.search(r'^version: "([A-Za-z0-9._+-]+)"$', package_config.read_text(), re.MULTILINE)
    if not match:
        raise ValueError("Cannot determine Linux package version")
    version = match.group(1)
    if build_version(binary, "main.serviceVersion") != version:
        raise ValueError("Service build version differs from the package")
    app_version = build_version(app_binary, "main.appBuildVersion")
    if app_version != version:
        raise ValueError("App build version differs from the package")
    if not binary.is_file() or binary.is_symlink():
        raise ValueError("Linux service binary is missing")
    names = {"manage.py", "soha-app-network.service", "service.example.json", "soha-app-service"}
    if companion.is_symlink():
        raise ValueError("Refusing a symlink companion")
    prior_companion = verify_companion(companion) if companion.exists() else None
    if prior_companion is not None and not output.exists():
        raise ValueError("Unowned companion already exists")
    if output.is_symlink():
        raise ValueError("Refusing a symlink asset directory")
    if output.exists():
        manifest = json.loads((output / "manifest.json").read_text())
        if manifest.get("kind") != "opensoha-linux-network-service-assets-v1" or set(manifest.get("files", {})) != names or {p.name for p in output.iterdir()} != names | {"manifest.json"}:
            raise ValueError("Existing assets are not owned by this build")
        if prior_companion is not None and prior_companion != manifest:
            raise ValueError("Existing companion differs from its owned asset directory")
        for name, expected in manifest["files"].items():
            target = output / name
            if target.is_symlink() or hashlib.sha256(target.read_bytes()).hexdigest() != expected:
                raise ValueError("Existing asset drifted; preserve and review it before rebuilding")
        for name in names | {"manifest.json"}:
            (output / name).unlink()
        output.rmdir()
    output.mkdir(parents=True)
    for name in ("manage.py", "soha-app-network.service", "service.example.json"):
        shutil.copyfile(source / name, output / name)
    shutil.copyfile(binary, output / "soha-app-service")
    (output / "soha-app-service").chmod(0o755)
    manifest = {"kind": "opensoha-linux-network-service-assets-v1", "version": match.group(1), "files": {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                for name in sorted(names)}}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    temporary = companion.with_suffix(companion.suffix + ".new")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("Companion temporary output already exists")
    try:
        with tarfile.open(temporary, "w:gz") as archive:
            for name in sorted(names | {"manifest.json"}):
                def metadata(member):
                    member.uid = member.gid = 0
                    member.uname = member.gname = "root"
                    member.mode = 0o755 if name == "soha-app-service" else 0o644
                    member.pax_headers = {}
                    return member
                archive.add(output / name, arcname="network-service/" + name, recursive=False, filter=metadata)
        verify_companion(temporary, version)
        temporary.replace(companion)
    finally:
        if temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package-config", type=Path, required=True)
    parser.add_argument("--companion", type=Path, required=True)
    parser.add_argument("--app-binary", type=Path, required=True)
    args = parser.parse_args()
    stage(args.binary, Path(__file__).resolve().parent, args.output, args.package_config, args.companion, args.app_binary)
