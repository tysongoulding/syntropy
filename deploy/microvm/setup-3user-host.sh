#!/usr/bin/env bash
set -euo pipefail

echo "=== Initializing Syntropy 3-User Cloud Display Mux ==="

TOKEN_DIR="/tmp/sand-novnc-tokens.d"
LOG_DIR="/tmp/syntropy-display-logs"
mkdir -p "${TOKEN_DIR}" "${LOG_DIR}" /tmp/.X11-unix
chmod 1777 /tmp/.X11-unix "${TOKEN_DIR}"

pkill -f websockify || true
pkill -f Xvfb || true
pkill -f x11vnc || true
sleep 1

# Start Primary noVNC websockify (User 1 -> Display :1 -> 5901)
websockify \
  --web=/usr/share/novnc \
  --heartbeat=30 \
  0.0.0.0:6080 \
  127.0.0.1:5901 \
  > "${LOG_DIR}/websockify_primary.log" 2>&1 &

# Start Token-multiplexed noVNC websockify (User 2 & 3 -> Displays :2, :3)
websockify \
  --web=/usr/share/novnc \
  --heartbeat=30 \
  --token-plugin TokenFile \
  --token-source "${TOKEN_DIR}" \
  0.0.0.0:6081 \
  > "${LOG_DIR}/websockify_forks.log" 2>&1 &

spawn_display() {
  local D="$1"
  local RFB=$((5900 + D))
  local TOKEN="$2"

  echo "[+] Initializing Display :${D} (RFB Port ${RFB}, Token: ${TOKEN:-none})..."
  Xvfb ":${D}" -screen 0 1280x800x24 -ac +extension GLX +render -noreset > "${LOG_DIR}/xvfb_${D}.log" 2>&1 &

  for _ in {1..30}; do
    if [ -S "/tmp/.X11-unix/X${D}" ]; then
      break
    fi
    sleep 0.1
  done

  DISPLAY=":${D}" openbox > /dev/null 2>&1 &
  x11vnc -skip_lockkeys -display ":${D}" -localhost -nopw -shared -forever -noxdamage -rfbport "${RFB}" -quiet > "${LOG_DIR}/x11vnc_${D}.log" 2>&1 &

  if [ -n "${TOKEN}" ]; then
    echo "${TOKEN}: 127.0.0.1:${RFB}" > "${TOKEN_DIR}/${TOKEN}.token"
  fi
}

spawn_display 1 ""
spawn_display 2 "user2"
spawn_display 3 "user3"

sleep 2
echo "=== Display Ports Listening ==="
ss -tulpn | grep -E '6080|6081'

echo "[✓] All 3 displays active and accessible via noVNC!"
