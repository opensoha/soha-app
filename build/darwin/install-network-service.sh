#!/bin/sh
set -eu

# Run with macOS administrator authorization. The optional directory contains
# an administrator-issued service.json and its TLS/enrollment files.
[ "$(id -u)" = 0 ] || { echo 'Administrator authorization is required.' >&2; exit 1; }
[ "$#" -le 1 ] || { echo 'usage: install-network-service.sh [provision-directory]' >&2; exit 2; }
resources=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
helper="$resources/../Library/Helpers/soha-app-service"
state=/var/db/opensoha/network-service
target=/Library/PrivilegedHelperTools/com.opensoha.network-service
plist=/Library/LaunchDaemons/com.opensoha.network-service.plist
[ -f "$helper" ] && [ ! -L "$helper" ] || { echo 'Bundled service is missing.' >&2; exit 1; }
/usr/bin/codesign --verify --strict "$helper"
for directory in /var/db/opensoha "$state" /var/run/opensoha /Library/PrivilegedHelperTools; do
  [ ! -L "$directory" ] || { echo 'Refusing a symlink installation directory.' >&2; exit 1; }
  if [ -e "$directory" ]; then
    [ "$(stat -f %u "$directory")" = 0 ] || { echo 'Installation directory must belong to root.' >&2; exit 1; }
    [ "$((0$(stat -f %Lp "$directory") & 022))" -eq 0 ] || { echo 'Installation directory is writable by another user.' >&2; exit 1; }
  fi
done
/usr/bin/install -d -o root -g wheel -m 755 /var/db/opensoha /var/run/opensoha /Library/PrivilegedHelperTools
/usr/bin/install -d -o root -g wheel -m 700 "$state"
if [ "$#" = 1 ]; then
  [ -f "$1/service.json" ] && [ ! -L "$1/service.json" ] || { echo 'Provisioning service.json is missing.' >&2; exit 1; }
  # Never overwrite an enrolled identity through a routine application update.
  [ ! -e "$state/service.json" ] || { echo 'A service configuration already exists; explicit administrator reprovisioning is required.' >&2; exit 1; }
  for file in service.json control-ca.pem control-cert.pem control-key.pem ingest-ca.pem ingest-cert.pem ingest-key.pem enrollment-token; do
    if [ -e "$1/$file" ]; then
      [ -f "$1/$file" ] && [ ! -L "$1/$file" ] || exit 1
      /usr/bin/install -o root -g wheel -m 600 "$1/$file" "$state/$file"
    fi
  done
fi
[ -f "$state/service.json" ] || { echo 'An administrator-issued service configuration is required.' >&2; exit 1; }
/bin/launchctl bootout system "$plist" 2>/dev/null || true
/usr/bin/install -o root -g wheel -m 755 "$helper" "$target.new"
/bin/mv -f "$target.new" "$target"
/usr/bin/install -o root -g wheel -m 644 "$resources/com.opensoha.network-service.plist" "$plist"
/bin/launchctl bootstrap system "$plist"
/bin/launchctl print system/com.opensoha.network-service
