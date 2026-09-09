#!/bin/sh
set -eu

if [ -r /sys/kernel/security/apparmor/profiles ] &&
   grep -q '^soha-app (' /sys/kernel/security/apparmor/profiles &&
   command -v apparmor_parser >/dev/null 2>&1; then
  apparmor_parser -R /etc/apparmor.d/soha-app
fi
