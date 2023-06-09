#!/bin/bash
set -e

repobase="ghcr.io/nethserver"

images=()
container=$(buildah from docker.io/alpine:3.16)

trap "buildah rm ${container} ${container_api} ${container_proxy}" EXIT

echo "Installing build dependencies..."
buildah run ${container} apk add --no-cache openvpn easy-rsa

echo "Setup image"
buildah add "${container}" vpn/controller-auth /usr/local/bin/controller-auth
buildah add "${container}" vpn/handle-connection /usr/local/bin/handle-connection
buildah add "${container}" vpn/entrypoint.sh /entrypoint.sh
buildah config --entrypoint='["/entrypoint.sh"]' --cmd='["/usr/sbin/openvpn", "/etc/openvpn/server.conf"]' ${container}
buildah commit "${container}" "${repobase}/nethsecurity-vpn"
images+=("${repobase}/nethsecurity-vpn")

container_api=$(buildah from docker.io/alpine:3.17)
buildah run ${container_api} apk add --no-cache go easy-rsa
buildah run ${container_api} mkdir /nethsecurity-api
buildah add "${container_api}" go.mod /nethsecurity-api/
buildah add "${container_api}" go.sum /nethsecurity-api/
buildah add "${container_api}" api/ /nethsecurity-api/
buildah run ${container_api} /bin/sh -c "cd /nethsecurity-api && CGO_ENABLED=0 go build"
buildah add "${container_api}" api/entrypoint.sh /entrypoint.sh
buildah config --entrypoint='["/entrypoint.sh"]' --cmd='["./nethsecurity-api"]' ${container_api}
buildah commit "${container_api}" "${repobase}/nethsecurity-api"
images+=("${repobase}/nethsecurity-api")

container_proxy=$(buildah from docker.io/library/traefik:v2.6)
buildah add "${container_proxy}" proxy/entrypoint.sh /entrypoint.sh
buildah config --entrypoint='["/entrypoint.sh"]' --cmd='["/usr/local/bin/traefik", "--configFile=/config.yaml"]' ${container_proxy}
buildah commit "${container_proxy}" "${repobase}/nethsecurity-proxy"
images+=("${repobase}/nethsecurity-proxy")

if [[ -n "${CI}" ]]; then
    # Set output value for Github Actions
    printf "::set-output name=images::%s\n" "${images[*]}"
else
    printf "Publish the images with:\n\n"
    for image in "${images[@]}"; do printf "  buildah push %s docker://%s:latest\n" "${image}" "${image}" ; done
    printf "\n"
fi
