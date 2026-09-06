#!/usr/bin/env bash
# High-Performance KasmVNC Alternative (WebRTC / WebP 60FPS)
# Replaces Xvfb + x11vnc + websockify with a single native modern binary.

set -euo pipefail

DISPLAY_NUM="${1:-1}"
PORT_HTTPS="${2:-8444}"
KASM_USER="${3:-box}"

echo "[+] Setting up KasmVNC on display :${DISPLAY_NUM} (WebRTC Port ${PORT_HTTPS})..."

# Ensure certificates exist (self-signed for local or agent tunnel)
CERT_DIR="/etc/kasmvnc/certs"
mkdir -p "${CERT_DIR}"
if [ ! -f "${CERT_DIR}/kasmvnc.pem" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${CERT_DIR}/kasmvnc.key" \
    -out "${CERT_DIR}/kasmvnc.pem" \
    -subj "/C=US/ST=Cloud/L=Agent/O=Syntropy/CN=localhost"
  chown -R "${KASM_USER}:${KASM_USER}" "${CERT_DIR}"
fi

# Launch KasmVNC Server
vncserver ":${DISPLAY_NUM}" \
  -geometry 1280x800 \
  -depth 24 \
  -websocketPort "${PORT_HTTPS}" \
  -cert "${CERT_DIR}/kasmvnc.pem" \
  -key "${CERT_DIR}/kasmvnc.key" \
  -interface 0.0.0.0 \
  -FrameRate=60 \
  -DynamicQualityMin=5 \
  -DynamicQualityMax=9 \
  -disableBasicAuth

echo "[✓] KasmVNC server active at https://0.0.0.0:${PORT_HTTPS}/"
