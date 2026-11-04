# syntax=docker/dockerfile:1
# Copy the release binary out of the official image into a plain alpine base,
# so the bottle controls the user, data dir and entrypoint (the upstream image
# runs as uid 65532 with a VOLUME at /data, which fights the bottle's mounts).
FROM docker.io/infisical/agent-vault:0.40.2 AS upstream

FROM docker.io/library/alpine:3.24

# python3 runs auth_proxy.py (stdlib only), the owner sign-in front.
RUN apk add --no-cache ca-certificates python3
COPY --from=upstream /usr/local/bin/agent-vault /usr/local/bin/agent-vault
COPY entrypoint.sh /usr/local/bin/bottle-entrypoint.sh
COPY auth_proxy.py /app/auth_proxy.py
RUN chmod +x /usr/local/bin/bottle-entrypoint.sh

# 14321 = auth proxy in front of the web UI + API (what the router forwards to).
# 14322 = MITM forward proxy (published on the host via [[ports]]).
# 14331 = Agent Vault's own API port, internal to the container.
EXPOSE 14321 14322

ENTRYPOINT ["/usr/local/bin/bottle-entrypoint.sh"]
