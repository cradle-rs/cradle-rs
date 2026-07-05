#!/usr/bin/env bash
# Extract the stock cilium-cni plugin binary from the pinned Cilium image
# into ~/.cache/cradle-bdd/ (the cradle_cilium BDD feature runs it against
# cradle's Cilium-compat agent API). Override the pin with CILIUM_VERSION.
set -euo pipefail
VERSION=${CILIUM_VERSION:-v1.19.5}
DEST=${1:-"$HOME/.cache/cradle-bdd/cilium-cni"}
mkdir -p "$(dirname "$DEST")"
docker pull -q "quay.io/cilium/cilium:$VERSION"
C=$(docker create "quay.io/cilium/cilium:$VERSION")
trap 'docker rm "$C" >/dev/null' EXIT
docker cp "$C:/opt/cni/bin/cilium-cni" "$DEST" 2>/dev/null \
    || docker cp "$C:/usr/bin/cilium-cni" "$DEST"
chmod +x "$DEST"
echo "cilium-cni $VERSION -> $DEST"
