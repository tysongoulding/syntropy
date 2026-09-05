#!/usr/bin/env bash
# ==============================================================================
# Syntropy Cloud Proxmox VE Automated LXC Deployment Script
# Run directly on Proxmox VE Host Shell (pve-shell)
# ==============================================================================
set -euo pipefail

CT_ID="${1:-$(pvesh get /cluster/nextid)}"
CT_HOSTNAME="${2:-syntropy-cloud}"
STORAGE="${3:-local-lvm}"
BRIDGE="${4:-vmbr0}"
MEMORY="${5:-2048}"
CORES="${6:-2}"
DISK_SIZE="${7:-16G}"

echo "=========================================================="
echo "🚀 Deploying Syntropy Cloud on Proxmox VE"
echo "   Container ID : ${CT_ID}"
echo "   Hostname     : ${CT_HOSTNAME}"
echo "   Storage      : ${STORAGE}"
echo "   Bridge       : ${BRIDGE}"
echo "   Memory       : ${MEMORY} MB"
echo "   Cores        : ${CORES}"
echo "   Disk         : ${DISK_SIZE}"
echo "=========================================================="

# 1. Update template cache and get latest Debian 12 LXC template
echo "📦 Updating LXC template cache..."
pveam update
TEMPLATE=$(pveam available -section system | grep "debian-12-standard" | head -n 1 | awk '{print $2}')
if [ -z "${TEMPLATE}" ]; then
    echo "❌ Error: Could not find Debian 12 LXC template in pveam."
    exit 1
fi

if ! pveam list local | grep -q "${TEMPLATE}"; then
    echo "⬇️ Downloading ${TEMPLATE} to local storage..."
    pveam download local "${TEMPLATE}"
fi

# 2. Create unprivileged LXC container with nesting enabled for Docker
echo "🔨 Creating LXC container ${CT_ID}..."
pct create "${CT_ID}" "local:vztmpl/${TEMPLATE}" \
    --hostname "${CT_HOSTNAME}" \
    --cores "${CORES}" \
    --memory "${MEMORY}" \
    --swap 512 \
    --features nesting=1,keyctl=1 \
    --net0 name=eth0,bridge="${BRIDGE}",ip=dhcp,firewall=1 \
    --rootfs "${STORAGE}:${DISK_SIZE}" \
    --unprivileged 1 \
    --onboot 1

# 3. Start container
echo "▶️ Starting container..."
pct start "${CT_ID}"

# Wait for network interface
echo "⏳ Waiting for DHCP assignment..."
sleep 5

# 4. Provision environment inside LXC container
echo "⚙️ Provisioning Docker inside container..."
pct exec "${CT_ID}" -- bash -c "
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release git git-lfs

    # Install Docker CE
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
      \$(lsb_release -cs) stable\" | tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # Deploy Syntropy Cloud services
    mkdir -p /opt/syntropy
    cat << 'EOF' > /opt/syntropy/docker-compose.yml
services:
  gateway:
    image: ghcr.io/tysongoulding/syntropy-cloud:latest
    container_name: syntropy-gateway
    restart: always
    ports:
      - "50051:50051"
    command: ["syntropy-gateway", "--bind", "0.0.0.0:50051"]
    environment:
      - RUST_LOG=info
  orchestrator:
    image: ghcr.io/tysongoulding/syntropy-cloud:latest
    container_name: syntropy-orchestrator
    restart: always
    command: ["syntropy-orchestrator", "--sprint-id", "sprint-default", "--objective", "Continuous Swarm"]
    environment:
      - RUST_LOG=info
    depends_on:
      - gateway
EOF

    # Create systemd service for auto-start
    cat << 'EOF' > /etc/systemd/system/syntropy-cloud.service
[Unit]
Description=Syntropy Cloud Docker Compose Stack
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/syntropy
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable syntropy-cloud
    systemctl start syntropy-cloud || true
"

# 5. Retrieve container IP
CT_IP=$(pct exec "${CT_ID}" -- ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')

echo "=========================================================="
echo "✅ Syntropy Cloud LXC Container Deployed Successfully!"
echo "   Container IP : ${CT_IP}"
echo "   gRPC Port    : 50051 (TCP)"
echo "   Command to attach: pct enter ${CT_ID}"
echo "=========================================================="
