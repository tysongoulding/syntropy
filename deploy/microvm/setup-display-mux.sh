#!/usr/bin/env bash
# Turnkey Multi-Screen Headless Display & Tokenized Websockify Supervisor
# Replicates the exact display pipeline of the Grokbot cloud agent microVM.

set -euo pipefail

TOKEN_DIR="/tmp/sand-novnc-tokens.d"
LOG_DIR="/tmp/syntropy-display-logs"
PORT_PRIMARY=6080
PORT_FORK=6081

mkdir -p "${TOKEN_DIR}" "${LOG_DIR}" /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix "${TOKEN_DIR}"

echo "[+] Starting primary noVNC websockify on 0.0.0.0:${PORT_PRIMARY} (Display :1 -> 5901)..."
websockify \
  --web=/usr/share/novnc \
  --heartbeat=30 \
  "0.0.0.0:${PORT_PRIMARY}" \
  127.0.0.1:5901 \
  > "${LOG_DIR}/websockify_primary.log" 2>&1 &
PID_PRIMARY=$!

echo "[+] Starting token-multiplexed websockify on 0.0.0.0:${PORT_FORK} (Fork Displays)..."
websockify \
  --web=/usr/share/novnc \
  --heartbeat=30 \
  --token-plugin TokenFile \
  --token-source "${TOKEN_DIR}" \
  "0.0.0.0:${PORT_FORK}" \
  > "${LOG_DIR}/websockify_forks.log" 2>&1 &
PID_FORK=$!

spawn_agent_display() {
  local DISPLAY_NUM="$1"
  local AGENT_TOKEN="$2"
  local RFB_PORT=$((5900 + DISPLAY_NUM))
  local DISPLAY_STR=":${DISPLAY_NUM}"

  echo "[+] Initializing Headless Virtual Display ${DISPLAY_STR} for Agent '${AGENT_TOKEN}' (RFB Port ${RFB_PORT})..."

  # 1. Start Xvfb Virtual Framebuffer
  Xvfb "${DISPLAY_STR}" \
    -screen 0 1280x800x24 \
    -ac \
    +extension GLX \
    +render \
    -noreset \
    > "${LOG_DIR}/xvfb_${DISPLAY_NUM}.log" 2>&1 &

  # Wait for X11 socket
  for _ in {1..30}; do
    if [ -S "/tmp/.X11-unix/X${DISPLAY_NUM}" ]; then
      break
    fi
    sleep 0.1
  done

  # 2. Start lightweight window manager
  DISPLAY="${DISPLAY_STR}" openbox > /dev/null 2>&1 &

  # 3. Start x11vnc RFB daemon bound strictly to localhost
  x11vnc \
    -skip_lockkeys \
    -display "${DISPLAY_STR}" \
    -localhost \
    -nopw \
    -shared \
    -forever \
    -noxdamage \
    -rfbport "${RFB_PORT}" \
    -quiet \
    > "${LOG_DIR}/x11vnc_${DISPLAY_NUM}.log" 2>&1 &

  # 4. Register routing token in websockify directory
  echo "${AGENT_TOKEN}: 127.0.0.1:${RFB_PORT}" > "${TOKEN_DIR}/${AGENT_TOKEN}.token"

  echo "[✓] Display ${DISPLAY_STR} ready!"
  if [ "${DISPLAY_NUM}" -eq 1 ]; then
    echo "    Primary URL: http://<PROXMOX_IP>:${PORT_PRIMARY}/vnc.html?autoconnect=true&resize=remote"
  fi
  echo "    Fork Token URL: http://<PROXMOX_IP>:${PORT_FORK}/vnc.html?token=${AGENT_TOKEN}&autoconnect=true&resize=remote"
}

# Replicate the default screens observed on the microVM (:1, :4, :7)
spawn_agent_display 1 "agent-1"
spawn_agent_display 4 "agent-4"
spawn_agent_display 7 "agent-7"

echo "[✓] Multi-display environment online. Press Ctrl+C to stop."
wait "${PID_PRIMARY}" "${PID_FORK}"
