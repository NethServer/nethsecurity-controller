#!/usr/bin/env bash

#
# Build local container images using buildah:
# this emulates the images built in the CI/CD pipeline and pushed to GitHub Container Registry.
#

set -euo pipefail

# ensure required commands are available
REQUIRED_CMDS=(git buildah)
for cmd in "${REQUIRED_CMDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required command '$cmd' not found. Install it and retry." >&2
        exit 1
    fi
done

# ensure we're inside a git repository and have an 'origin' remote
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Error: not inside a git repository." >&2
    exit 1
fi

if ! git remote get-url origin >/dev/null 2>&1; then
    echo "Error: git remote 'origin' not found. Please add a remote named 'origin' or run this from a clone." >&2
    exit 1
fi

# basic sanity checks for expected service directories and Containerfiles
SERVICES=(vpn api proxy ui)
missing=0
for s in "${SERVICES[@]}"; do
    if [ ! -d "$s" ]; then
        echo "Error: expected directory '$s' not found." >&2
        missing=1
        continue
    fi
    if [ ! -f "${s}/Containerfile" ]; then
        echo "Error: '${s}/Containerfile' not found." >&2
        missing=1
    fi
done

if [ "$missing" -ne 0 ]; then
    echo "Resolve the above issues and re-run the script." >&2
    exit 1
fi
# adjust if your remote is different
OWNER=$(git remote get-url origin | sed -E 's#.*[:/](.+)/(.+)(.git)?#\1#' | head -n1 | tr '[:upper:]' '[:lower:]')
# use branch name for the tag (fallback to short commit hash if detached); sanitize it
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
if [ -z "$branch" ] || [ "$branch" = "HEAD" ]; then
    branch=$(git rev-parse --short HEAD)
fi
safe_branch=$(printf '%s' "$branch" | sed 's#[^A-Za-z0-9._-]#-#g')
TAG="${safe_branch}"

# mapping: directory -> image name used in the workflow
declare -A MAP=(
  [vpn]=nethsecurity-vpn
  [api]=nethsecurity-api
  [proxy]=nethsecurity-proxy
  [ui]=nethsecurity-ui
)

for dir in "${!MAP[@]}"; do
  image="ghcr.io/${OWNER}/${MAP[$dir]}:${TAG}"
  echo "Building ${image} from ${dir}/Containerfile"
  buildah build --layers \
    --file "${dir}/Containerfile" \
    --tag "${image}" \
    "${dir}"
done

echo "Built images with tag ${TAG}. Use 'docker images' to see them."
