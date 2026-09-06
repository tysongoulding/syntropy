import http from "node:http";
import { readFileSync } from "node:fs";
import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";

// Port routing configuration
export const SYNTROPY_DISPLAY_HEADER = "x-sand-display";
export const SYNTROPY_WINDOW_OWNER_HEADER = "x-sand-window-owner";
export const WINDOW_TOKEN_DIR = "/tmp/sand-window-tokens.d";
export const DEFAULT_LISTEN_PORT = 1339;
export const DEFAULT_PRIMARY_PORT = 1337;
export const DEFAULT_FORK_EXEC_BASE = 14000;

function firstHeader(raw) {
  return Array.isArray(raw) ? raw[0] : raw;
}

export function parseDisplayNumber(raw) {
  const value = firstHeader(raw);
  const num = Number.parseInt(value ?? "1", 10);
  return Number.isInteger(num) ? num : 1;
}

// Constant-time token comparison to prevent timing attacks
export function tokensMatch(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length === 0 || ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function decideWindowRoute({
  displayHeader,
  ownerHeader,
  primaryPort,
  execBase,
  lookupBoundToken,
}) {
  const display = parseDisplayNumber(displayHeader);
  if (display <= 1) return { port: primaryPort };
  const owner = firstHeader(ownerHeader);
  const bound = lookupBoundToken(display);
  if (bound === undefined || !tokensMatch(owner, bound)) {
    return {
      reject: {
        status: 403,
        message: `syntropy-window-router: forbidden (display :${display} owner-token mismatch)`,
      },
    };
  }
  return { port: execBase + display };
}

function readBoundToken(display) {
  try {
    const raw = readFileSync(`${WINDOW_TOKEN_DIR}/${display}`, "utf8").trim();
    return raw.length > 0 ? raw : undefined;
  } catch {
    return undefined;
  }
}

function main() {
  const LISTEN_PORT = Number(process.argv[2] || DEFAULT_LISTEN_PORT);
  const PRIMARY_PORT = Number(process.argv[3] || DEFAULT_PRIMARY_PORT);
  const EXEC_BASE = Number(process.argv[4] || DEFAULT_FORK_EXEC_BASE);

  const server = http.createServer((req, res) => {
    const decision = decideWindowRoute({
      displayHeader: req.headers[SYNTROPY_DISPLAY_HEADER],
      ownerHeader: req.headers[SYNTROPY_WINDOW_OWNER_HEADER],
      primaryPort: PRIMARY_PORT,
      execBase: EXEC_BASE,
      lookupBoundToken: readBoundToken,
    });
    if (decision.reject !== undefined) {
      if (!res.headersSent) {
        res.writeHead(decision.reject.status, { "content-type": "text/plain" });
      }
      res.end(decision.reject.message);
      req.resume();
      return;
    }
    const upstream = http.request(
      {
        host: "127.0.0.1",
        port: decision.port,
        method: req.method,
        path: req.url,
        headers: req.headers,
      },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
        upstreamRes.pipe(res);
      }
    );
    upstream.on("error", (err) => {
      if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
      res.end(`syntropy-window-router upstream error: ${String(err)}`);
    });
    req.pipe(upstream);
  });

  server.timeout = 0;
  server.listen(LISTEN_PORT, "0.0.0.0", () => {
    process.stdout.write(
      `syntropy-window-router listening pid=${process.pid} port=${LISTEN_PORT} primary=${PRIMARY_PORT} fork_base=${EXEC_BASE}\n`
    );
  });
}

if (
  process.argv[1] != null &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main();
}
