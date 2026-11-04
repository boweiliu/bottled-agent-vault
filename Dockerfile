# syntax=docker/dockerfile:1
# Copy the release binary out of the official image into a plain alpine base,
# so the bottle controls the user, data dir and entrypoint (the upstream image
# runs as uid 65532 with a VOLUME at /data, which fights the bottle's mounts).
FROM docker.io/infisical/agent-vault:0.40.2 AS upstream

FROM docker.io/library/alpine:3.24

RUN apk add --no-cache ca-certificates
COPY --from=upstream /usr/local/bin/agent-vault /usr/local/bin/agent-vault
COPY entrypoint.sh /usr/local/bin/bottle-entrypoint.sh
RUN chmod +x /usr/local/bin/bottle-entrypoint.sh

# 14321 = web UI + API (proxied by the router on the app subdomain).
# 14322 = MITM forward proxy (published on the host via [[ports]]).
EXPOSE 14321 14322

ENTRYPOINT ["/usr/local/bin/bottle-entrypoint.sh"]
