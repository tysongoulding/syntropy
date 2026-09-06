#!/usr/bin/env bash
# Link session SQLite databases (Cookies, Login Data) across multi-monitor Chrome profiles.
# Enables "One box, one session" across concurrent agent displays.

set -euo pipefail

PROFILE_DIR="${CHROME_USER_DATA_DIR:-$1}"
SESSION_DIR="${CHROME_SESSION_DIR:-/home/box/chrome-profile/Default}"
[ -n "${PROFILE_DIR}" ] || exit 0

DEFAULT_DIR="${PROFILE_DIR}/Default"

ensure_box_dir() {
  local dir="$1"
  mkdir -p "${dir}" 2>/dev/null || true
  if [ "$(id -u)" -eq 0 ] && [ -d "${dir}" ] && [ ! -L "${dir}" ]; then
    chown box:box "${dir}" 2>/dev/null || true
  fi
}

ensure_box_dir "${SESSION_DIR}"

if [ -L "${DEFAULT_DIR}" ]; then
  rm -f "${DEFAULT_DIR}" 2>/dev/null || true
fi
ensure_box_dir "${DEFAULT_DIR}"

SESSION_FILES=(Cookies "Login Data" "Login Data For Account")
for name in "${SESSION_FILES[@]}"; do
  target="${SESSION_DIR}/${name}"
  link="${DEFAULT_DIR}/${name}"

  # Already correctly symlinked: leave untouched
  if [ -L "${link}" ] && [ "$(readlink "${link}" 2>/dev/null)" = "${target}" ]; then
    continue
  fi

  # Safely replace with symlink
  rm -f "${link}" 2>/dev/null || true
  ln -s "${target}" "${link}" 2>/dev/null || true
done

exit 0
