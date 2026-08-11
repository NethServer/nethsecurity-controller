#!/bin/sh

CONFIG_DIR=/etc/openvpn/proxy/

port=${PROXY_PORT:-8080}
ip=${PROXY_BIND_IP:-0.0.0.0}
ui_port=${UI_PORT:-3000}
api_port=${API_PORT:-5000}

# Optional environment variables for allowed IPs and public endpoints
# ALLOWED_IPS is a comma-separated list of IP/CDIRs that are allowed to access the proxy. Example: 1.2.3.0/24
# PUBLIC_ENDPOINTS is a comma-separated list of public endpoints that should be accessible. Example: /api/units/ingest
allowed_ips=${ALLOWED_IPS:-""}
public_endpoints=${PUBLIC_ENDPOINTS:-""}

# All generated files merge into one traefik config, so every router/service/middleware name must
# be unique across them. Duplicates are dropped first-wins, in alphabetical file order.
output_public_routers () {
  if [ -n "$public_endpoints" ]; then
    OLD_IFS="$IFS"
    IFS=,
    set -- $public_endpoints
    IFS="$OLD_IFS"
    for endpoint; do
      name=$(echo "$endpoint" | tr -cd '[:alnum:]')
      printf "    routerapi%s:\n" "$name"
      printf "      entryPoints:\n"
      printf "      - web\n"
      # higher than routerapi so public endpoints bypass the IP allow list
      printf "      priority: 60\n"
      printf "      middlewares:\n"
      printf "      - stripprefix-api\n"
      printf "      service: service-api\n"
      printf "      rule: PathPrefix(\`%s\`)\n" "$endpoint"
    done
  fi
}

output_middlewares_list () {
  printf "      - %s\n" "$1"
  if [ -n "$allowed_ips" ]; then
    printf "      - ipallowlist\n"
  fi
}

output_ui_middlewares_list () {
  if [ -n "$allowed_ips" ]; then
    printf "      middlewares:\n"
    printf "      - ipallowlist\n"
  fi
}

output_whitelist_middleware () {
  if [ -n "$allowed_ips" ]; then
    printf "    ipallowlist:\n"
    printf "      ipAllowList:\n"
    printf "        ipStrategy:\n"
    printf "          depth: 1\n"
    printf "        sourceRange:\n"
    OLD_IFS="$IFS"
    IFS=,
    set -- $allowed_ips
    IFS="$OLD_IFS"
    for ip; do
      printf "          - \"%s\"\n" "$ip"
    done
  fi
}

if [ ! -d "$CONFIG_DIR" ]; then
    mkdir -p "$CONFIG_DIR"
fi

cat <<EOF > /config.yaml
entryPoints:
  web:
   address: "$ip:$port"
   forwardedHeaders:
     trustedIPs:
       - "127.0.0.1/32"

accessLog: {}

providers:
  file:
    directory: $CONFIG_DIR
    watch: true

serversTransport:
  insecureSkipVerify: true

EOF

cat << EOF > "${CONFIG_DIR}api.yaml"
http:
  routers:
$(output_public_routers)
    routerapi:
      entryPoints:
      - web
      priority: 50
      middlewares:
$(output_middlewares_list stripprefix-api)
      service: service-api
      rule: PathPrefix(\`/api\`)

  services:
    service-api:
      loadBalancer:
        servers:
        - url: http://127.0.0.1:${api_port}/
        passHostHeader: true

  middlewares:
    stripprefix-api:
      stripPrefix:
        prefixes:
          - "/api"
$(output_whitelist_middleware)
EOF

# Both files used to define a middleware named "stripprefix" with different prefixes; api.yaml won
# the merge, so /ui was forwarded unstripped. Hence the -api/-ui suffixes.
# ipallowlist stays duplicated in both files: identical definitions are harmless, whereas a
# cross-file reference that failed to resolve would fail open.
cat << EOF > "${CONFIG_DIR}ui.yaml"
http:
  routers:
    routerui:
      entryPoints:
      - web
      priority: 50
      middlewares:
$(output_middlewares_list stripprefix-ui)
      service: service-ui
      rule: PathPrefix(\`/ui\`)
    routerui-root:
      entryPoints:
      - web
      # fallback for anything not claimed by the API, /ui, or a per-unit route
      priority: 1
$(output_ui_middlewares_list)
      service: service-ui
      rule: PathPrefix(\`/\`)

  services:
    service-ui:
      loadBalancer:
        servers:
        - url: http://127.0.0.1:${ui_port}/
        passHostHeader: true

  middlewares:
    stripprefix-ui:
      stripPrefix:
        prefixes:
          - "/ui"
$(output_whitelist_middleware)
EOF

exec "$@"
