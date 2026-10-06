#!/usr/bin/env bash
# A stand-in for uat/hub/core/bind-tenant.sh (UAT.3b) for tests/test_scripts.sh:
# same arguments; maps t<N>-admin and t<N>-reader to TENANT_ID in the fake
# Keycloak and records the binding in <state>/core/out/core.json, as the real
# one does. Logs each call to $FAKE_DIR/bind.log.
set -euo pipefail
[[ $# -eq 5 ]] || { echo "usage: bind-tenant.sh <kubeconfig> <endpoints.json> <state-dir> <1|2> <tenant_id>" >&2; exit 2; }
kube="$1" endpoints="$2" state="$3" n="$4" tid="$5"
[[ -f "$kube" && -f "$endpoints" ]] || { echo "bind-tenant.sh: kubeconfig or endpoints file missing" >&2; exit 1; }
[[ "$tid" =~ ^t_[a-z2-7]{16}$ ]] || { echo "bind-tenant.sh: not a saasapi tenant_id: $tid" >&2; exit 1; }
echo "$n $tid" >>"${FAKE_DIR:?}/bind.log"
b="$FAKE_DIR/kc-bindings.json"
[[ -s "$b" ]] || echo '{}' >"$b"
jq --arg n "$n" --arg t "$tid" '.["t" + $n + "-admin"] = $t | .["t" + $n + "-reader"] = $t' "$b" >"$b.tmp" && mv "$b.tmp" "$b"
c="$state/core/out/core.json"
jq --arg n "$n" --arg t "$tid" '.tenants[$n] = $t' "$c" >"$c.tmp" && mv "$c.tmp" "$c"
echo "bind-tenant.sh: tenant $n bound to $tid" >&2
