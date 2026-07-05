# cradle node image: the daemon (cradle), the Kubernetes controller
# (cradle-k8s), and the CNI plugin (cradle-cni) the init container installs
# onto the node. Binaries are built on the host by deploy/kind-e2e.sh:
# cradle/cradle-k8s for the host glibc (they run in THIS image), cradle-cni
# as a static musl binary (it runs on the NODE's filesystem, whatever libc
# that has).
FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY target/release/cradle /usr/local/bin/cradle
COPY target/release/cradle-k8s /usr/local/bin/cradle-k8s
COPY target/aarch64-unknown-linux-musl/release/cradle-cni /usr/local/bin/cradle-cni
