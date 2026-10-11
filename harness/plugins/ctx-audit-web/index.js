/**
 * Host half of the CTX-Audit web surface.
 *
 * Two jobs:
 *   1. the CTX-Audit MCP server row — pure configuration, it lives in this
 *      bundle's `cordis.patch.yml`;
 *   2. a small read-only JSON endpoint the browser half reads.
 *
 * The endpoint exists because a plugin page renders in a slot and cannot touch
 * the filesystem; the page must not be served as its own HTML document either
 * (an iframe would lose the host theme and locale). Serving JSON from a route
 * the plugin owns is the sanctioned shape — `ctx.webServer.register` hands the
 * handler the full `node:http` response, and the shipped Web app only owns the
 * request paths nobody claimed plus the fallback seat.
 *
 * The endpoint is deliberately narrow: configuration echo, a workspace path, and
 * a bounded directory listing. It never returns file contents, and the web
 * server binds loopback only (the launcher rejects `--host 0.0.0.0`).
 */
import { existsSync, readdirSync, statSync } from 'node:fs';
import { isAbsolute, join, resolve } from 'node:path';

/**
 * `webServer` is optional: declaring it keeps this plugin inactive in profiles
 * without an HTTP carrier instead of throwing during activation.
 */
export const inject = ['webServer'];

/** Route prefix owned by this plugin, under the origin root. */
const API_PREFIX = '/ctx-audit/api';

/** Upper bound on the directory listing, so a huge workspace cannot flood the page. */
const MAX_ARTIFACTS = 30;

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(payload);
}

/**
 * Bounded, read-only inventory of one directory. Absent or unreadable
 * directories are reported as `null` so the page can distinguish "nothing yet"
 * from "not there".
 */
function inventory(dir) {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .slice(0, MAX_ARTIFACTS)
      .map((entry) => {
        const row = { name: entry.name, kind: entry.isDirectory() ? 'dir' : 'file' };
        try {
          const stat = statSync(join(dir, entry.name));
          row.bytes = stat.isFile() ? stat.size : null;
          row.mtime = stat.mtime.toISOString();
        } catch {
          row.bytes = null;
          row.mtime = null;
        }
        return row;
      });
  } catch {
    return null;
  }
}

export function apply(ctx, config = {}) {
  const workspace = resolve(config.workspace ?? process.cwd());
  const artifactsDir = join(workspace, '.ctx-audit');
  const mcpCommand = config.mcpCommand ?? 'ctx-audit';
  const mcpCommandAbsolute = isAbsolute(mcpCommand);
  const mcpCommandFound = mcpCommandAbsolute ? existsSync(mcpCommand) : null;

  ctx.effect(() =>
    ctx.webServer.register({
      kind: 'prefix',
      path: API_PREFIX,
      handler(req, res) {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { error: 'method_not_allowed' });
          return;
        }
        const pathname = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
        if (pathname !== `${API_PREFIX}/status`) {
          sendJson(res, 404, { error: 'not_found' });
          return;
        }
        sendJson(res, 200, {
          mcp: {
            serverName: config.serverName ?? 'ctxaudit',
            transport: 'stdio',
            command: mcpCommand,
            // `null` means "a bare command name, resolved through PATH at spawn
            // time" — not knowable from here, so the page must not claim either way.
            commandFound: mcpCommandFound,
            toolNamePrefix: `mcp__${config.serverName ?? 'ctxaudit'}__*`,
          },
          workspace,
          artifactsDir,
          artifacts: inventory(artifactsDir),
          artifactLimit: MAX_ARTIFACTS,
          generatedAt: new Date().toISOString(),
        });
      },
    }),
  );
}
