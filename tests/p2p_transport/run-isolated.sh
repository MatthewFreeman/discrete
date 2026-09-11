#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != --isolated ]]; then exec unshare --net bash "$0" --isolated "$@"; fi
shift
ip link set lo up
ip address add 192.0.2.1/32 dev lo
exec "$@"