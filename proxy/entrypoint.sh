#!/bin/sh

CONFIG_DIR=./etc/openvpn/proxy/

port=${PROXY_PORT:-8080}
ip=${PROXY_BIND_IP:-0.0.0.0}
ui_port=${UI_PORT:-3000}
api_port=${API_PORT:-5000}

# Optional environment variables for allowed IPs and public endpoints
# ALLOWED_IPS is a comma-separated list of IP/CDIRs that are allowed to access the proxy. Example: 1.2.3.0/24
# PUBLIC_ENDPOINTS is a comma-separated list of public endpoints that should be accessible. Example: /api/units/ingest
allowed_ips=${ALLOWED_IPS:-""}
public_endpoints=${PUBLIC_ENDPOINTS:-""}

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
      printf "      middlewares:\n"
      printf "      - stripprefix\n"
      printf "      service: service-api\n"
      printf "      rule: PathPrefix(\`%s\`)\n" "$endpoint"
    done
  fi
}

output_middlewares_list () {
  printf "      - stripprefix\n"
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

output_whiteliste_middleware () {
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
      middlewares:
$(output_middlewares_list)
      service: service-api
      rule: PathPrefix(\`/api\`)

  services:
    service-api:
      loadBalancer:
        servers:
        - url: http://127.0.0.1:${api_port}/
        passHostHeader: true

  middlewares:
    stripprefix:
      stripPrefix:
        prefixes:
          - "/api"
$(output_whiteliste_middleware)
EOF

cat << EOF > "${CONFIG_DIR}ui.yaml"
http:
  routers:
$(output_public_routers)

    routerui:
      entryPoints:
      - web
      middlewares:
$(output_middlewares_list)
      service: service-ui
      rule: PathPrefix(\`/ui\`)
    routerui-root:
      entryPoints:
      - web
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
    stripprefix:
      stripPrefix:
        prefixes:
          - "/ui"
$(output_whiteliste_middleware)
EOF

exec "$@"
