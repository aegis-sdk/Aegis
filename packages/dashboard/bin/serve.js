#!/usr/bin/env node

/**
 * Aegis Dashboard — zero-dependency HTTP server.
 *
 * Serves the dashboard HTML at "/" and exposes two API endpoints:
 *   GET /api/logs?file=<path>          — reads a JSONL file, returns JSON array
 *   GET /api/logs/stream?file=<path>   — SSE stream, tails the file for new entries
 *
 * Usage:
 *   aegis-dashboard --file ./aegis-audit.jsonl --port 6639
 *
 * Options:
 *   --file <path>   Default JSONL log file path
 *   --port <n>      Port to listen on (default: 6639)
 *   --help          Show help
 */

import { createServer } from "node:http";
import { readFileSync, statSync, watchFile, unwatchFile } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ── CLI argument parsing ────────────────────────────────────────────────────

const args = process.argv.slice(2);

function getFlag(name) {
  const idx = args.indexOf(name);
  if (idx === -1) return undefined;
  return args[idx + 1];
}

if (args.includes("--help") || args.includes("-h")) {
  console.log(`
  Aegis Security Dashboard

  Usage:
    aegis-dashboard [options]

  Options:
    --file <path>   Default JSONL log file path
    --port <n>      Port to listen on (default: 6639)
    --help          Show this help message

  The dashboard visualizes Aegis audit log files (.jsonl).
  Open http://localhost:<port> in your browser after starting.
`);
  process.exit(0);
}

const DEFAULT_PORT = 6639;
const port = parseInt(getFlag("--port") ?? String(DEFAULT_PORT), 10);
const defaultFile = getFlag("--file");

// ── Load dashboard HTML ─────────────────────────────────────────────────────

let dashboardHtml;
try {
  dashboardHtml = readFileSync(resolve(__dirname, "..", "dist", "index.html"), "utf-8");
} catch {
  console.error("[aegis-dashboard] Could not load dist/index.html.");
  console.error("  Run 'pnpm build' in the dashboard package first.");
  process.exit(1);
}

// Inject the default file path into the HTML if provided via CLI
if (defaultFile) {
  dashboardHtml = dashboardHtml.replace(
    "<!--AEGIS_DEFAULT_FILE-->",
    `<script>window.__AEGIS_DEFAULT_FILE__ = ${JSON.stringify(resolve(defaultFile))};</script>`,
  );
}

// ── JSONL reader ────────────────────────────────────────────────────────────

function readJsonlFile(filePath) {
  try {
    const content = readFileSync(filePath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);
    return lines.map((line, idx) => {
      try {
        return JSON.parse(line);
      } catch {
        return { _parseError: true, _line: idx + 1, _raw: line };
      }
    });
  } catch (err) {
    return { error: err.message };
  }
}

// ── Route handler ───────────────────────────────────────────────────────────

function getFilePath(url) {
  const params = new URL(url, "http://localhost").searchParams;
  const file = params.get("file") || defaultFile;
  if (!file) return null;
  return resolve(file);
}

function handleRequest(req, res) {
  const url = req.url ?? "/";
  const pathname = new URL(url, "http://localhost").pathname;

  // ── Dashboard HTML ──────────────────────────────────────────────────────
  if (pathname === "/" || pathname === "/index.html") {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
    });
    res.end(dashboardHtml);
    return;
  }

  // ── API: Read logs ──────────────────────────────────────────────────────
  if (pathname === "/api/logs") {
    const filePath = getFilePath(url);
    if (!filePath) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Missing 'file' query parameter." }));
      return;
    }

    const data = readJsonlFile(filePath);
    if (data.error) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: data.error }));
      return;
    }

    res.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache",
    });
    res.end(JSON.stringify(data));
    return;
  }

  // ── API: SSE stream (tail -f) ──────────────────────────────────────────
  if (pathname === "/api/logs/stream") {
    const filePath = getFilePath(url);
    if (!filePath) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Missing 'file' query parameter." }));
      return;
    }

    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });
    res.write(":\n\n"); // SSE comment to establish connection

    let lastSize = 0;
    try {
      const stat = statSync(filePath);
      lastSize = stat.size;
    } catch {
      // File may not exist yet — start from 0
    }

    // Send initial connected event
    res.write(`event: connected\ndata: ${JSON.stringify({ file: filePath })}\n\n`);

    const pollInterval = 1000; // 1 second

    const watcher = setInterval(() => {
      try {
        const stat = statSync(filePath);
        if (stat.size > lastSize) {
          // Read only the new bytes
          const content = readFileSync(filePath, "utf-8");
          const allBytes = Buffer.byteLength(content, "utf-8");
          // Find new content by reading lines and skipping ones we've seen
          const lines = content.trim().split("\n").filter(Boolean);

          // Approximate: re-read and send lines whose cumulative byte offset > lastSize
          // Simpler approach: track line count
          const newContent = Buffer.from(content).subarray(lastSize).toString("utf-8");
          const newLines = newContent.trim().split("\n").filter(Boolean);

          for (const line of newLines) {
            try {
              const entry = JSON.parse(line);
              res.write(`event: entry\ndata: ${JSON.stringify(entry)}\n\n`);
            } catch {
              // Skip malformed lines
            }
          }

          lastSize = allBytes;
        }
      } catch {
        // File might be temporarily unavailable during rotation
      }
    }, pollInterval);

    req.on("close", () => {
      clearInterval(watcher);
    });

    return;
  }

  // ── 404 ─────────────────────────────────────────────────────────────────
  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
}

// ── Start server ────────────────────────────────────────────────────────────

const server = createServer(handleRequest);

server.listen(port, () => {
  const fileMsg = defaultFile ? ` (default file: ${resolve(defaultFile)})` : "";
  console.log();
  console.log("  \x1b[1m\x1b[36mAegis Security Dashboard\x1b[0m");
  console.log();
  console.log(`  Local:   \x1b[4mhttp://localhost:${port}\x1b[0m${fileMsg}`);
  console.log();
  console.log("  Press Ctrl+C to stop.");
  console.log();
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`[aegis-dashboard] Port ${port} is already in use.`);
    console.error(`  Try: aegis-dashboard --port ${port + 1}`);
    process.exit(1);
  }
  throw err;
});
