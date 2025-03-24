#!/bin/bash
set -e

repobase="ghcr.io/nethserver"

images=()

# VPN
podman build \
    --layers \
    --force-rm \
    --jobs 0 \
    --tag "${repobase}/nethsecurity-vpn" \
    vpn
images+=("${repobase}/nethsecurity-vpn")

# API
podman build \
    --target dist \
    --layers \
    --force-rm \
    --jobs 0 \
    --tag "${repobase}/nethsecurity-api" \
    api
images+=("${repobase}/nethsecurity-api")

# Proxy
podman build \
    --layers \
    --force-rm \
    --jobs 0 \
    --tag "${repobase}/nethsecurity-proxy" \
    proxy
images+=("${repobase}/nethsecurity-proxy")

# UI
podman build \
    --target dist \
    --layers \
    --force-rm \
    --jobs 0 \
    --tag ghcr.io/nethserver/nethsecurity-ui \
    ui
images+=("${repobase}/nethsecurity-ui")

if [[ -n "${CI}" ]]; then
    # Set output value for Github Actions
    echo "images=${images[*]}" >> "$GITHUB_OUTPUT"
else
    printf "Publish the images with:\n\n"
    for image in "${images[@]}"; do printf "  buildah push %s docker://%s:latest\n" "${image}" "${image}" ; done
    printf "\n"
fi
