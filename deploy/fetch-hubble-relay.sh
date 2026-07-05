#!/usr/bin/env bash
# Extract the stock `hubble-relay` binary from the pinned Hubble Relay image
# into ~/.cache/cradle-bdd/ (the cradle_hubble BDD feature runs it against
# cradle's Hubble Peer + Observer API to prove relay aggregation). Override
# the pin with CILIUM_VERSION.
set -euo pipefail
VERSION=${CILIUM_VERSION:-v1.19.5}
DEST=${1:-"$HOME/.cache/cradle-bdd/hubble-relay"}
mkdir -p "$(dirname "$DEST")"
docker pull -q "quay.io/cilium/hubble-relay:$VERSION"
C=$(docker create "quay.io/cilium/hubble-relay:$VERSION")
trap 'docker rm "$C" >/dev/null' EXIT
docker cp "$C:/usr/bin/hubble-relay" "$DEST"
chmod +x "$DEST"
echo "hubble-relay $VERSION -> $DEST"
