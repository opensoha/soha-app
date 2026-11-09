#!/bin/sh
set -eu

# Package upgrades replace staged assets only; the active helper is administrator-managed.
case "${1:-remove}" in
  upgrade|1) exit 0 ;;
  remove|purge|0) /usr/bin/python3 /usr/share/soha-app/network-service/manage.py uninstall ;;
  *) echo "Unknown package removal action; service was preserved." >&2; exit 1 ;;
esac

if [ -r /sys/kernel/security/apparmor/profiles ] &&
   grep -q '^soha-app (' /sys/kernel/security/apparmor/profiles &&
   command -v apparmor_parser >/dev/null 2>&1; then
  apparmor_parser -R /etc/apparmor.d/soha-app
fi
