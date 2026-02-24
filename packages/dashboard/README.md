# @aegis-sdk/dashboard

Standalone audit log visualization dashboard for Aegis. Zero dependencies -- serves a self-contained HTML app over a local HTTP server that reads JSONL audit log files produced by `@aegis-sdk/core`.

Part of the [Aegis.js](https://github.com/aegis-sdk/Aegis) prompt injection defense toolkit.

## Installation

```bash
npm install -g @aegis-sdk/dashboard
```

Or run without installing:

```bash
npx @aegis-sdk/dashboard
```

Requires Node.js >= 18.

## Usage

Point the dashboard at an Aegis audit log file:

```bash
aegis-dashboard --file ./aegis-audit.jsonl
```

Then open `http://localhost:6639` in your browser.

### Options

| Flag | Description |
|------|-------------|
| `--file <path>` | Default JSONL log file to load |
| `--port <n>` | Port to listen on (default: `6639`) |
| `--help` | Show help |

### Custom port

```bash
aegis-dashboard --file ./aegis-audit.jsonl --port 8080
```

### Generating audit logs

The dashboard reads JSONL files produced by the Aegis `FileTransport`. Enable file-based audit logging in your Aegis configuration:

```ts
import { Aegis, FileTransport } from "@aegis-sdk/core";

const aegis = new Aegis({
  policy: "balanced",
  audit: {
    transports: ["json-file"],
    path: "./aegis-audit.jsonl",
  },
});
```

Or with explicit `FileTransport` configuration (rotation, max size):

```ts
import { Aegis, FileTransport, AuditLog } from "@aegis-sdk/core";

const file = new FileTransport({
  path: "./aegis-audit.jsonl",
  rotate: true,
  maxSizeMB: 100,
});

const aegis = new Aegis({
  policy: "balanced",
  audit: { transports: ["json-file"] },
});
```

### API endpoints

The server exposes two endpoints for programmatic access:

- `GET /api/logs?file=<path>` -- Returns the full log file as a JSON array.
- `GET /api/logs/stream?file=<path>` -- SSE stream that tails the file for new entries in real time.

If a `--file` flag was provided at startup, the `file` query parameter is optional and defaults to that path.

## License

MIT
