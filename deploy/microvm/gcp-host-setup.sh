#!/usr/bin/env bash
# Provision a GCP Compute Engine Host with Nested KVM Virtualization for Agent MicroVMs

set -euo pipefail

PROJECT_ID="${1:-$(gcloud config get-value project)}"
ZONE="${2:-us-central1-a}"
INSTANCE_NAME="${3:-syntropy-agent-hypervisor}"
MACHINE_TYPE="${4:-n2-standard-8}"

echo "=== Provisioning GCP Hypervisor Host ==="
echo "Project:  ${PROJECT_ID}"
echo "Zone:     ${ZONE}"
echo "Instance: ${INSTANCE_NAME}"
echo "Type:     ${MACHINE_TYPE}"

# 1. Create a custom image or instance with nested virtualization enabled
gcloud compute instances create "${INSTANCE_NAME}" \
  --project="${PROJECT_ID}" \
  --zone="${ZONE}" \
  --machine-type="${MACHINE_TYPE}" \
  --min-cpu-platform="Intel Cascade Lake" \
  --enable-nested-virtualization \
  --image-family="ubuntu-2404-lts-amd64" \
  --image-project="ubuntu-os-cloud" \
  --boot-disk-size="100GB" \
  --boot-disk-type="pd-ssd" \
  --tags="syntropy-microvm-host" \
  --metadata=startup-script='#!/bin/bash
    apt-get update
    apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils cpu-checker
    modprobe kvm_intel
    usermod -aG kvm ubuntu

    # Install Firecracker release binary
    ARCH="$(uname -m)"
    FC_VER="v1.10.1"
    curl -L "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VER}/firecracker-${FC_VER}-${ARCH}.tgz" -o /tmp/fc.tgz
    tar -xzf /tmp/fc.tgz -C /usr/local/bin --strip-components=1 "release-${FC_VER}-${ARCH}/firecracker-${FC_VER}-${ARCH}"
    ln -sf "/usr/local/bin/firecracker-${FC_VER}-${ARCH}" /usr/local/bin/firecracker
  '

# 2. Allow VNC & Websockify traffic
gcloud compute firewall-rules create allow-syntropy-vnc \
  --project="${PROJECT_ID}" \
  --allow=tcp:6080,tcp:6081,tcp:8444 \
  --target-tags="syntropy-microvm-host" \
  --description="Allow noVNC, websockify, and KasmVNC for Syntropy agents" || true

echo "[✓] GCP Hypervisor provisioned! Connect via: gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE}"
