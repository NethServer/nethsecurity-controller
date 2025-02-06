#!/bin/bash
set -e

repobase="ghcr.io/nethserver"

images=()
container=$(buildah from docker.io/alpine:3.16)
ui_version="1.20.3"

trap "buildah rm ${container} ${container_api} ${container_proxy}" EXIT

echo "Installing build dependencies..."
buildah run ${container} apk add --no-cache openvpn easy-rsa

echo "Setup image"
buildah add "${container}" vpn/ip /sbin/ip
buildah add "${container}" vpn/controller-auth /usr/local/bin/controller-auth
buildah add "${container}" vpn/handle-connection /usr/local/bin/handle-connection
buildah add "${container}" vpn/handle-disconnection /usr/local/bin/handle-disconnection
buildah add "${container}" vpn/entrypoint.sh /entrypoint.sh
buildah config --entrypoint='["/entrypoint.sh"]' --cmd='["/usr/sbin/openvpn", "/etc/openvpn/server.conf"]' ${container}
buildah commit "${container}" "${repobase}/nethsecurity-vpn"
images+=("${repobase}/nethsecurity-vpn")

container_api=$(buildah from docker.io/alpine:3.20)
buildah run ${container_api} apk add --no-cache go easy-rsa openssh sqlite curl oath-toolkit-oathtool
buildah run ${container_api} mkdir /nethsecurity-api
buildah add "${container_api}" api/ /nethsecurity-api/
buildah config --workingdir /nethsecurity-api ${container_api}
buildah config --env GOOS=linux --env GOARCH=amd64 --env CGO_ENABLED=1 ${container_api}
buildah run ${container_api} go build -ldflags='-extldflags=-static' -tags sqlite_omit_load_extension
buildah run ${container_api} rm -rf root/go
buildah run ${container_api} apk del --no-cache go
buildah add "${container_api}" api/entrypoint.sh /entrypoint.sh
buildah config --entrypoint='["/entrypoint.sh"]' --cmd='["./api"]' ${container_api}
buildah commit "${container_api}" "${repobase}/nethsecurity-api"
images+=("${repobase}/nethsecurity-api")

container_proxy=$(buildah from docker.io/library/traefik:v2.6)
buildah add "${container_proxy}" proxy/entrypoint.sh /entrypoint.sh
buildah config --entrypoint='["/entrypoint.sh"]' --cmd='["/usr/local/bin/traefik", "--configFile=/config.yaml"]' ${container_proxy}
buildah commit "${container_proxy}" "${repobase}/nethsecurity-proxy"
images+=("${repobase}/nethsecurity-proxy")

container_ui=$(buildah from docker.io/alpine:3.17)
buildah run ${container_ui} apk add --no-cache lighttpd git nodejs npm
buildah run ${container_ui} git clone --depth 1 --branch ${ui_version} https://github.com/NethServer/nethsecurity-ui.git
buildah config --workingdir /nethsecurity-ui ${container_ui}
buildah run ${container_ui} sh -c "sed -i 's/standalone/controller/g' .env.production"
buildah run ${container_ui} sh -c "npm ci && npm run build"
buildah run ${container_ui} sh -c "cp -r dist/* /var/www/localhost/htdocs/"
buildah add ${container_ui} ui/entrypoint.sh /entrypoint.sh
buildah run ${container_ui} sh -c "rm -rf /nethsecurity-ui"
buildah run ${container_ui} apk del --no-cache git nodejs npm
buildah config --workingdir / ${container_ui}
buildah config --entrypoint='["/entrypoint.sh"]' ${container_ui}
buildah commit ${container_ui} "${repobase}/nethsecurity-ui"
images+=("${repobase}/nethsecurity-ui")

if [[ -n "${CI}" ]]; then
    # Set output value for Github Actions
    printf "::set-output name=images::%s\n" "${images[*]}"
else
    printf "Publish the images with:\n\n"
    for image in "${images[@]}"; do printf "  buildah push %s docker://%s:latest\n" "${image}" "${image}" ; done
    printf "\n"
fi
