#!/bin/sh
set -eu

# Cloud in a Bottle injects BOTTLE_* env vars (older instances use OPENHOST_*).
APP_NAME="${BOTTLE_APP_NAME:-${OPENHOST_APP_NAME:-agent-vault}}"
ZONE="${BOTTLE_ZONE_DOMAIN:-${OPENHOST_ZONE_DOMAIN:-}}"
ROUTER_PUBLIC_URL="${BOTTLE_ROUTER_PUBLIC_URL:-${OPENHOST_ROUTER_PUBLIC_URL:-}}"
DATA_DIR="${BOTTLE_APP_DATA_DIR:-${OPENHOST_APP_DATA_DIR:-/data/app_data/$APP_NAME}}"

# Agent Vault keeps everything (SQLite db, MITM CA, CLI session) under
# $HOME/.agent-vault, so point HOME at the app's permanent data dir.
mkdir -p "$DATA_DIR"
export HOME="$DATA_DIR"
cd "$DATA_DIR"

# Public base URL of this app: used in links, invites, discovery, and as a SAN
# on MITM leaf certs. The CLI also derives the proxy host from it.
if [ -z "${AGENT_VAULT_ADDR:-}" ] && [ -n "$ZONE" ]; then
  scheme="https"
  case "$ROUTER_PUBLIC_URL" in http://*) scheme="http" ;; esac
  export AGENT_VAULT_ADDR="${scheme}://${APP_NAME}.${ZONE}"
fi

# Requests reach the API through the instance's router, so trust its
# X-Forwarded-For (otherwise every client shares one rate-limit bucket).
export AGENT_VAULT_TRUSTED_PROXIES="${AGENT_VAULT_TRUSTED_PROXIES:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,127.0.0.0/8,::1/128,fc00::/7}"
# No anonymous usage beacons from a personal instance.
export AGENT_VAULT_TELEMETRY="${AGENT_VAULT_TELEMETRY:-false}"

# Owner account the auth proxy creates on first boot and signs the bottle owner
# in with. The bottle owner's username, at the zone, like the catalog apps do.
ZONE_HOST="${ZONE%%:*}"
OWNER_USERNAME="${BOTTLE_OWNER_USERNAME:-${OPENHOST_OWNER_USERNAME:-owner}}"
export AGENT_VAULT_OWNER_EMAIL="${AGENT_VAULT_OWNER_EMAIL:-${OWNER_USERNAME}@${ZONE_HOST:-localhost}}"

echo "agent-vault: data=$DATA_DIR addr=${AGENT_VAULT_ADDR:-unset} owner=$AGENT_VAULT_OWNER_EMAIL"

# auth_proxy.py starts the Agent Vault server (API on internal port 14331, MITM
# proxy on :14322), creates the owner account on first boot, and fronts the
# API on :14321 with automatic owner sign-in.
exec python3 /app/auth_proxy.py
