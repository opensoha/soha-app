#!/usr/bin/env bash
set -euo pipefail
demo_dir="$(cd "$(dirname "$0")" && pwd)"
app_dir="$(cd "$demo_dir/../.." && pwd)"
contracts_dir="$(cd "${TASK112_CONTRACTS_DIR:?Set TASK112_CONTRACTS_DIR to the Task122 Contracts checkout}" && pwd)"
runtime_dir="$demo_dir/runtime"
bundle="$runtime_dir/Soha Task112 Demo.app"

expected="8f2c35e8ccad20f2fb7b8b54cdd20b2b9abc71b8"
test "$(git -C "$contracts_dir" rev-parse HEAD)" = "$expected"
test -z "$(git -C "$contracts_dir" status --porcelain)"
mkdir -p "$runtime_dir" "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
test -d "$app_dir/frontend/node_modules/@opensoha/contracts" || {
  echo 'Install the App frontend dependencies for the Task122 candidate first.' >&2
  exit 1
}
cp "$app_dir/go.mod" "$runtime_dir/demo.mod"
cp "$app_dir/go.sum" "$runtime_dir/demo.sum"
cd "$app_dir"
export GOWORK=off GOTOOLCHAIN=local
go mod edit -modfile="$runtime_dir/demo.mod" "-replace=github.com/opensoha/soha-contracts=$contracts_dir"
(cd frontend && PRODUCTION=true npm run build)
env GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 MACOSX_DEPLOYMENT_TARGET=13.0 \
  CGO_CFLAGS=-mmacosx-version-min=13.0 CGO_LDFLAGS=-mmacosx-version-min=13.0 \
  go build -mod=mod -modfile="$runtime_dir/demo.mod" -tags production,task112_demo \
    -trimpath -buildvcs=false -ldflags='-w -s -X main.appBuildVersion=0.2.0-task112.demo' \
    -o "$bundle/Contents/MacOS/soha-app"
python3 - "$app_dir/build/darwin/Info.plist" "$bundle/Contents/Info.plist" <<'PY'
import plistlib
import sys
from pathlib import Path
source, dest = map(Path, sys.argv[1:])
info = plistlib.loads(source.read_bytes())
info.update(CFBundleIdentifier="com.opensoha.app.profile.task112-demo",
            CFBundleName="Soha Task112 Demo", CFBundleDisplayName="Soha Task112 Demo")
dest.write_bytes(plistlib.dumps(info))
PY
cp "$app_dir/build/darwin/icons.icns" "$bundle/Contents/Resources/"
codesign --force --deep --sign - "$bundle"
codesign --verify --deep --strict "$bundle"
