# bottled-agent-vault

[Agent Vault](https://github.com/Infisical/agent-vault) (Infisical's open-source
credential broker for AI agents) packaged as a
[Cloud in a Bottle](https://github.com/cloud-in-a-bottle/cloud-in-a-bottle) app.

Agents never hold real API keys: you store them in Agent Vault, agents send
their HTTP(S) traffic through its proxy, and Agent Vault attaches the real
credentials on the way out.

> Upstream now recommends [Agent Vault in Infisical](https://infisical.com/docs/documentation/platform/agent-vault/overview)
> over this standalone open-source version. This bottle packages the
> standalone version (currently `0.40.2`).

## What it runs

- The Agent Vault server (release binary copied out of the official
  `infisical/agent-vault` image into an alpine base), with
  - the web UI + API on the app's HTTP port `14321`, proxied by the router
    at `https://<app>.<zone>/`
  - the MITM forward proxy on `14322`, published on the host via `[[ports]]`
    (it speaks plain HTTP `CONNECT`, which the HTTP router can't carry)
- All state (SQLite database, MITM root CA) lives in the app's permanent data
  dir, so it survives reloads and is included in the bottle's backups.

## Deploy

```
bottle app deploy https://github.com/boweiliu/bottled-agent-vault --name agent-vault --wait
```

Then, straight away, open `https://agent-vault.<your-zone>/` (owner login
required) and create the Agent Vault owner account. Registration only happens
in the browser: the register endpoint is kept behind the bottle owner login,
so nobody else can claim the instance or sign up.

## Access model

| Path | Who can reach it |
|---|---|
| Web UI (`/`, `/login`, `/manage/...`, ...) | Bottle owner only (router login), then Agent Vault's own login |
| Account creation / password reset (`/v1/auth/register`, `/v1/auth/forgot-password`, ...) | Bottle owner only |
| Agent and CLI API (`/v1/sessions`, `/v1/vaults`, `/v1/mitm`, `/discover`, ...) | Public, authenticated by Agent Vault tokens |
| MITM proxy, host port `14322` | Public, authenticated by Agent Vault tokens |

## Connecting an agent

On the agent's machine, with the `agent-vault` CLI installed:

```
agent-vault auth login --address https://agent-vault.<your-zone>
agent-vault run -- claude
```

or, for an unattended agent, create an agent token in the UI and set
`AGENT_VAULT_ADDR=https://agent-vault.<your-zone>`, `AGENT_VAULT_TOKEN`, and
`AGENT_VAULT_VAULT` before `agent-vault run`. The CLI fetches the CA and
points `HTTPS_PROXY` at `agent-vault.<your-zone>:14322`.

## Caveats

- **The proxy hop is unencrypted.** Agent Vault's proxy listener is plain
  HTTP, so the token in each `CONNECT` request crosses the network in the
  clear (the traffic inside the tunnel is TLS). `agent-vault run` uses
  short-lived vault-scoped session tokens for this, which limits the damage,
  but prefer agents on trusted networks (same host, LAN, or a VPN such as
  Tailscale).
- **Passwordless mode.** The bottle has no way to inject a secret env var, so
  the server starts without a master password: the data encryption key is
  stored unwrapped next to the data. Anyone who can read the app's data dir
  (or a backup of it) can decrypt the stored credentials.
- **Firewall.** `[[ports]]` publishes `14322` on the host but does not open a
  cloud firewall; allow inbound `14322/tcp` if your provider has one.
- Telemetry is off by default (`AGENT_VAULT_TELEMETRY=false`).

## Repo layout

- `cloudinabottle.toml` - manifest: HTTP port `14321`, public API paths, one
  `[[ports]]` entry for the proxy
- `Dockerfile` - copies the `agent-vault` binary out of the official image
- `entrypoint.sh` - points `HOME` at the app data dir, derives
  `AGENT_VAULT_ADDR` from the app name and zone, and starts the server

## License

MIT for this packaging. Agent Vault itself is MIT (see upstream).
