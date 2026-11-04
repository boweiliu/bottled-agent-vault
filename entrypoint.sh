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

echo "agent-vault: data=$DATA_DIR addr=${AGENT_VAULT_ADDR:-unset}"

# The instance has no secret-env mechanism, so with no master password set the
# vault runs in passwordless mode (data key stored unwrapped next to the data).
# An empty line on --password-stdin selects that mode without needing a TTY.
if [ -n "${AGENT_VAULT_MASTER_PASSWORD:-}" ]; then
  exec agent-vault server --host 0.0.0.0 --port 14321 --mitm-port 14322
fi
exec agent-vault server --host 0.0.0.0 --port 14321 --mitm-port 14322 --password-stdin <<EMPTY

EMPTY
