#!/usr/bin/env node

import { existsSync, readFileSync, writeFileSync, mkdirSync, cpSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

export const SUPERVISOR_DIR = "/tmp/sand-supervisor";
export const AGENT_DATA_ROOT = "/home/box/sand-data";
export const HOST_DIR = "/home/box/sand-host";
export const BOX_SCRIPTS_BIN_DIR = "/usr/local/bin";

export const BOX_SCRIPTS_DENY = Object.freeze([
  "start-sand-box",
  "sand-exit-watch",
  "sand-supervisor.mjs",
  "fetch-exec-daemon",
  "sand-desktop-supervise.sh",
  "box-cgroups.sh",
  "ensure-machine-id",
  "box-xvfb",
  "box-x11vnc",
  "start-exec-daemon",
  "supervise-exec-daemon",
  "supervise-sand-supervisor",
]);

export function isScriptUpdateAllowed(scriptName) {
  const base = scriptName.split("/").pop();
  return !BOX_SCRIPTS_DENY.includes(base);
}

export function syncBoxScripts(sourceDir = join(HOST_DIR, "box-scripts"), binDir = BOX_SCRIPTS_BIN_DIR) {
  if (!existsSync(sourceDir)) return { synced: 0, rejected: 0 };
  let synced = 0;
  let rejected = 0;

  const entries = stdioReaddirSafe(sourceDir);
  for (const entry of entries) {
    if (!isScriptUpdateAllowed(entry)) {
      console.warn(`[sand-supervisor] REJECTED update to protected script: ${entry}`);
      rejected++;
      continue;
    }
    const src = join(sourceDir, entry);
    const dst = join(binDir, entry);
    try {
      cpSync(src, dst, { force: true });
      synced++;
    } catch (e) {
      console.error(`[sand-supervisor] Failed to sync ${entry}:`, e);
    }
  }
  return { synced, rejected };
}

function stdioReaddirSafe(dir) {
  try {
    const fs = await import("node:fs");
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

async function main() {
  console.log("[sand-supervisor] Supervisor initialized with protected script deny-list");
  mkdirSync(SUPERVISOR_DIR, { recursive: true });
  mkdirSync(AGENT_DATA_ROOT, { recursive: true });
  const intervalMs = Number(process.env.SAND_SUPERVISOR_TICK_MS || 5000);
  setInterval(() => {
    syncBoxScripts();
  }, intervalMs);
}

if (process.argv[1] && process.argv[1].endsWith("sand-supervisor.mjs")) {
  void main();
}
