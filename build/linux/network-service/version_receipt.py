#!/usr/bin/env python3
"""Record the version passed by the same Task that just built this binary."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import tempfile
import os


def record(binary, kind, package_config, ldflags="", source_file=None):
    match = re.search(r'^version: "([A-Za-z0-9._+-]+)"$', package_config.read_text(), re.MULTILINE)
    if not match or not binary.is_file() or binary.is_symlink():
        raise ValueError("Cannot record a package build version")
    version = match.group(1)
    symbol = "main.appBuildVersion" if kind == "app" else "main.serviceVersion"
    tokens = shlex.split(ldflags)
    definitions = []
    for index, token in enumerate(tokens):
        if token == "-X":
            if index + 1 == len(tokens):
                raise ValueError("Incomplete linker version flag")
            definitions.append(tokens[index + 1])
        elif token.startswith("-X="):
            definitions.append(token[3:])
    values = [definition[len(symbol) + 1:] for definition in definitions if definition.startswith(symbol + "=")]
    evidence = {"kind": "linker-X", "symbol": symbol, "value": values[-1] if values else None}
    if not values and kind == "app" and source_file is not None:
        source = source_file.read_bytes()
        fallback = re.search(rb'const fallbackAppVersion = "([A-Za-z0-9._+-]+)"', source)
        if fallback:
            evidence = {"kind": "source-default", "symbol": "main.fallbackAppVersion", "value": fallback.group(1).decode(),
                        "sourceSha256": hashlib.sha256(source).hexdigest()}
    if evidence["value"] != version:
        raise ValueError("Source/linker version differs from the package")
    path = Path(str(binary) + ".version.json")
    if path.exists():
        previous = json.loads(path.read_text())
        if path.is_symlink() or previous.get("kind") != "opensoha-linux-build-version-v1" or previous.get("binary") != str(binary.resolve()):
            raise ValueError("Existing version receipt is not owned by this build")
    data = {"kind": "opensoha-linux-build-version-v1", "buildKind": kind, "binary": str(binary.resolve()),
            "version": version, "versionSource": evidence, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    fd, temporary = tempfile.mkstemp(prefix=".soha-version-", dir=binary.parent)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(data, output)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--kind", choices=("app", "service"), required=True)
    parser.add_argument("--package-config", required=True, type=Path)
    parser.add_argument("--ldflags", default="")
    parser.add_argument("--source-file", type=Path)
    args = parser.parse_args()
    record(args.binary, args.kind, args.package_config, args.ldflags, args.source_file)
