#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if go list -deps ./authz/... 2>/dev/null | grep -q '/auth/authn'; then
  echo "FAIL: authz depends on authn" >&2
  exit 1
fi
echo "OK: no authz->authn edge"
