#!/usr/bin/env bash
# Extract the stock `hubble` CLI from the pinned Cilium image into
# ~/.cache/cradle-bdd/ (the cradle_hubble BDD feature runs it against cradle's
# Hubble-compat Observer API on hubble.sock). Override the pin with
# CILIUM_VERSION.
set -euo pipefail
VERSION=${CILIUM_VERSION:-v1.19.5}
DEST=${1:-"$HOME/.cache/cradle-bdd/hubble"}
mkdir -p "$(dirname "$DEST")"
docker pull -q "quay.io/cilium/cilium:$VERSION"
C=$(docker create "quay.io/cilium/cilium:$VERSION")
trap 'docker rm "$C" >/dev/null' EXIT
docker cp "$C:/usr/bin/hubble" "$DEST"
chmod +x "$DEST"
echo "hubble $VERSION -> $DEST"
