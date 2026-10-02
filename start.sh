#!/bin/bash
set -euo pipefail
# Keychain is authoritative — prefer it over any stale/inherited env token.
_kc="$(/usr/bin/security find-generic-password -s 'Claude' -a 'PFSENSE_API_KEY' -w 2>/dev/null || true)"
if [ -n "$_kc" ]; then export PFSENSE_API_KEY="$_kc"
elif [ -z "${PFSENSE_API_KEY:-}" ]; then echo "ERROR: PFSENSE_API_KEY not in env or Keychain (Claude/PFSENSE_API_KEY)" >&2; exit 1; fi
_kc="$(/usr/bin/security find-generic-password -s 'Claude' -a 'PFSENSE_PASSWORD' -w 2>/dev/null || true)"
if [ -n "$_kc" ]; then export PFSENSE_PASSWORD="$_kc"; fi
unset _kc
cd "$(dirname "$0")"
exec python3 -m src.main
