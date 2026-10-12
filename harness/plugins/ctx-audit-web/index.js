/**
 * Host half of the CTX-Audit web surface.
 *
 * Jobs:
 *   1. the CTX-Audit MCP server row — pure configuration, in this bundle's
 *      `cordis.patch.yml`;
 *   2. a small read-only HTTP API the browser half renders as a control panel.
 *
 * The API exists because a plugin page renders in a slot and cannot touch the
 * filesystem; the page must not be its own HTML document either (an iframe would
 * lose the host theme and locale). `ctx.webServer.register` hands the handler
 * the full `node:http` response, and the shipped Web app owns only the paths
 * nobody claimed plus the fallback seat, so a plugin route is the sanctioned
 * shape.
 *
 * Endpoints (all GET/HEAD, all under the prefix this plugin owns):
 *   /ctx-audit/api/status   MCP row echo, workspace, bounded `.ctx-audit/` listing
 *   /ctx-audit/api/engine   live MCP handshake: server info + tool surface (cached)
 *   /ctx-audit/api/logs     tail of one log file inside `.ctx-audit/`
 *   /ctx-audit/api/roadmap  the roadmap document shipped in this bundle
 *
 * Deliberate limits: no file contents except the named log tail, every listing
 * bounded, no arbitrary paths accepted (log files come from an enumeration), and
 * the web server binds loopback only (the launcher rejects `--host 0.0.0.0`).
 */
import { spawn } from 'node:child_process';
import { closeSync, existsSync, openSync, readFileSync, readSync, readdirSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * `webServer` is optional: declaring it keeps this plugin inactive in profiles
 * without an HTTP carrier instead of throwing during activation.
 */
export const inject = ['webServer'];

/** Route prefix owned by this plugin, under the origin root. */
const API_PREFIX = '/ctx-audit/api';

/** Upper bound on the directory listing, so a huge workspace cannot flood the page. */
const MAX_ARTIFACTS = 30;
/** Upper bound on log files offered, and on the tail a caller may request. */
const MAX_LOG_FILES = 5;
const MAX_LOG_LINES = 500;
const MAX_LOG_BYTES = 256 * 1024;
/** The handshake is a diagnostic, not a hot path: cache it, and bound it. */
const ENGINE_TTL_MS = 5 * 60 * 1000;
const ENGINE_TIMEOUT_MS = 6000;

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(payload);
}

/**
 * Bounded, read-only inventory of one directory. An absent or unreadable
 * directory is reported as `null` so the page can tell "nothing yet" from
 * "not there".
 */
function inventory(dir) {
  try {
    const entries = readdirSync(dir, { withFileTypes: true });
    const rows = entries.slice(0, MAX_ARTIFACTS).map((entry) => {
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
    const counts = { files: 0, dirs: 0, bytes: 0 };
    for (const entry of entries) {
      if (entry.isDirectory()) {
        counts.dirs += 1;
        continue;
      }
      counts.files += 1;
      try {
        counts.bytes += statSync(join(dir, entry.name)).size;
      } catch {
        /* unreadable entry: leave the total as counted so far */
      }
    }
    return { rows, counts, truncated: entries.length > MAX_ARTIFACTS, total: entries.length };
  } catch {
    return null;
  }
}

/** Log files offered by `/logs`, newest first. Names only — never paths. */
function listLogs(dir) {
  try {
    return readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.toLowerCase().endsWith('.log'))
      .map((entry) => {
        try {
          const stat = statSync(join(dir, entry.name));
          return { name: entry.name, bytes: stat.size, mtime: stat.mtime.toISOString() };
        } catch {
          return { name: entry.name, bytes: null, mtime: null };
        }
      })
      .sort((a, b) => String(b.mtime).localeCompare(String(a.mtime)))
      .slice(0, MAX_LOG_FILES);
  } catch {
    return [];
  }
}

/**
 * Tail one file without reading it whole: read at most the last
 * {@link MAX_LOG_BYTES} bytes and report whether the head was cut off.
 */
function tailFile(path, maxLines) {
  const stat = statSync(path);
  const start = Math.max(0, stat.size - MAX_LOG_BYTES);
  const length = stat.size - start;
  if (length === 0) return { lines: [], truncated: false, bytes: 0 };
  const fd = openSync(path, 'r');
  try {
    const buffer = Buffer.alloc(length);
    readSync(fd, buffer, 0, length, start);
    let text = buffer.toString('utf8');
    // A read that started mid-file may begin inside a multi-byte character or a
    // line; drop everything before the first newline in that case.
    if (start > 0) {
      const firstBreak = text.indexOf('\n');
      text = firstBreak >= 0 ? text.slice(firstBreak + 1) : text;
    }
    const all = text.split(/\r?\n/);
    if (all.length && all[all.length - 1] === '') all.pop();
    const lines = all.slice(-maxLines);
    return { lines, truncated: start > 0 || all.length > lines.length, bytes: stat.size };
  } finally {
    closeSync(fd);
  }
}

/**
 * One real MCP handshake over stdio: `initialize`, then `tools/list`. This is a
 * diagnostic surface, so every failure mode resolves to a message the panel can
 * show instead of throwing into the request.
 */
function probeEngine(command, cwd, timeoutMs) {
  return new Promise((resolveProbe) => {
    let child;
    try {
      child = spawn(command, ['mcp'], { cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    } catch (error) {
      resolveProbe({ ok: false, error: `spawn_failed: ${String((error && error.message) || error)}` });
      return;
    }

    let settled = false;
    let buffer = '';
    let stderr = '';
    let serverInfo = null;
    let protocolVersion = null;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill();
      } catch {
        /* already gone */
      }
      resolveProbe(result);
    };

    const timer = setTimeout(() => finish({ ok: false, error: 'timeout', stderr: stderr.trim() }), timeoutMs);

    const write = (payload) => {
      try {
        child.stdin.write(`${JSON.stringify(payload)}\n`);
      } catch {
        /* the child died between reads; the exit/error handler reports it */
      }
    };

    child.on('error', (error) => finish({ ok: false, error: `spawn_error: ${String(error.message || error)}` }));
    child.on('exit', (code) => finish({ ok: false, error: `exited_early: ${code}`, stderr: stderr.trim() }));

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      let index = buffer.indexOf('\n');
      while (index >= 0) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        index = buffer.indexOf('\n');
        if (!line) continue;
        let message;
        try {
          message = JSON.parse(line);
        } catch {
          continue;
        }
        if (message.id === 1 && message.result) {
          serverInfo = message.result.serverInfo || null;
          protocolVersion = message.result.protocolVersion || null;
          write({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
          write({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
        } else if (message.id === 1 && message.error) {
          finish({ ok: false, error: `initialize_error: ${JSON.stringify(message.error)}` });
        } else if (message.id === 2) {
          if (message.error) {
            finish({ ok: false, error: `tools_list_error: ${JSON.stringify(message.error)}` });
            return;
          }
          const tools = ((message.result && message.result.tools) || []).map((tool) => ({
            name: String(tool.name || ''),
            description: String(tool.description || ''),
          }));
          finish({ ok: true, serverInfo, protocolVersion, tools, toolCount: tools.length });
        }
      }
    });

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      if (stderr.length < 2000) stderr += chunk;
    });

    write({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'ctx-audit-web', version: '0.2.0' },
      },
    });
  });
}

/** Directory names never worth walking when looking for targets. */
const TARGET_SKIP_DIRS = new Set(['node_modules', '.git', 'target', 'dist', 'build', 'out', 'vendor']);

/** Markers that make a directory look like a project worth auditing. */
const PROJECT_MARKERS = [
  '.git',
  'package.json',
  'Cargo.toml',
  'go.mod',
  'pom.xml',
  'build.gradle',
  'pyproject.toml',
  'setup.py',
  'composer.json',
  'CMakeLists.txt',
];

/** The engine answers tool calls with a one-line summary followed by the JSON payload. */
function parseToolPayload(text) {
  const start = text.indexOf('{');
  if (start < 0) return null;
  try {
    return JSON.parse(text.slice(start));
  } catch {
    return null;
  }
}

/**
 * Discover candidate targets under `root`: a directory counts when it carries a
 * `.ctx-audit/` evidence directory or looks like a project. Evidence counts are
 * computed only where evidence exists, so a directory full of sources cannot make
 * this walk expensive.
 */
function discoverTargets(root, maxEntries) {
  const found = [];
  const visit = (dir, depth) => {
    if (found.length >= maxEntries) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (found.length >= maxEntries) return;
      if (!entry.isDirectory() || TARGET_SKIP_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
      const path = join(dir, entry.name);
      let hasAudit = false;
      let files = 0;
      let bytes = 0;
      let logs = 0;
      let newest = null;
      const auditDir = join(path, '.ctx-audit');
      try {
        hasAudit = statSync(auditDir).isDirectory();
      } catch {
        hasAudit = false;
      }
      if (hasAudit) {
        try {
          for (const item of readdirSync(auditDir, { withFileTypes: true })) {
            if (!item.isFile()) continue;
            files += 1;
            try {
              const stat = statSync(join(auditDir, item.name));
              bytes += stat.size;
              const stamp = stat.mtime.toISOString();
              if (!newest || stamp > newest) newest = stamp;
              if (item.name.toLowerCase().endsWith('.log')) logs += 1;
            } catch {
              /* unreadable entry: keep the totals gathered so far */
            }
          }
        } catch {
          /* raced with a removal */
        }
      }
      const isProject = PROJECT_MARKERS.some((marker) => existsSync(join(path, marker)));
      if (hasAudit || isProject) {
        found.push({ name: entry.name, path, hasAudit, isProject, files, bytes, logs, newest });
      }
      if (depth < 2) visit(path, depth + 1);
    }
  };
  visit(root, 1);
  return found;
}

/**
 * One MCP handshake plus a single `tools/call` of `get_project_index`, run with
 * `cwd` set to the selected target so the engine answers about THAT project.
 *
 * Kept apart from the handshake-only probe on purpose: a slow index build must
 * never cost us the tool catalogue.
 */
function probeProject(command, cwd, timeoutMs) {
  return new Promise((resolveProbe) => {
    const started = Date.now();
    let child;
    try {
      child = spawn(command, ['mcp'], { cwd, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    } catch (error) {
      resolveProbe({ ok: false, error: `spawn_failed: ${String((error && error.message) || error)}` });
      return;
    }

    let settled = false;
    let buffer = '';
    let stderr = '';
    const timeline = {};

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.kill();
      } catch {
        /* already gone */
      }
      resolveProbe({ ...result, ms: Date.now() - started, timeline });
    };

    const timer = setTimeout(() => finish({ ok: false, error: 'timeout', stderr: stderr.trim().slice(0, 400) }), timeoutMs);

    const write = (payload) => {
      try {
        child.stdin.write(`${JSON.stringify(payload)}\n`);
      } catch {
        /* the exit handler reports it */
      }
    };

    child.on('error', (error) => finish({ ok: false, error: `spawn_error: ${String(error.message || error)}` }));
    child.on('exit', (code) => finish({ ok: false, error: `exited_early: ${code}`, stderr: stderr.trim().slice(0, 400) }));

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      if (stderr.length < 2000) stderr += chunk;
    });

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      let index = buffer.indexOf('\n');
      while (index >= 0) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        index = buffer.indexOf('\n');
        if (!line) continue;
        let message;
        try {
          message = JSON.parse(line);
        } catch {
          continue;
        }
        if (message.id === 1 && message.result) {
          timeline.initialize = Date.now() - started;
          write({ jsonrpc: '2.0', method: 'notifications/initialized', params: {} });
          write({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'get_project_index', arguments: {} } });
        } else if (message.id === 1 && message.error) {
          finish({ ok: false, error: `initialize_error: ${JSON.stringify(message.error)}` });
        } else if (message.id === 2) {
          timeline.tool = Date.now() - started;
          if (message.error) {
            finish({ ok: false, error: `tool_error: ${JSON.stringify(message.error)}` });
            return;
          }
          const text = ((message.result && message.result.content) || [])
            .map((block) => (block && typeof block.text === 'string' ? block.text : ''))
            .join('\n');
          const summary = (text.match(/get_project_index:\s*(\d+)\s*files/i) || [])[1];
          const payload = parseToolPayload(text);
          const data = payload && payload.data ? payload.data : payload;
          const capabilities = (data && data.capabilities) || {};
          const context = (data && data.build_context) || {};
          finish({
            ok: true,
            isError: Boolean(message.result && message.result.isError),
            filesScanned: summary ? Number(summary) : null,
            analysisBacked: capabilities.analysis_backed ?? null,
            primaryLanguages: capabilities.present_primary ?? null,
            heuristicLanguages: capabilities.heuristic_only_present ?? null,
            buildConfidence: context.confidence ?? null,
            buildNote: context.note ?? null,
            cacheHitSource: (data && data.cache && data.cache.hit_source) || null,
            indexBuildId: (data && data.build_id) || null,
            payloadAvailable: Boolean(data),
          });
        }
      }
    });

    write({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'ctx-audit-web', version: '0.3.0' },
      },
    });
  });
}


const PROJECT_TIMEOUT_MS = 30000;

/** Read a UTF-8 text file with a hard size cap, so a huge artifact cannot be pulled in by accident. */
function readTextFile(path, maxBytes) {
  const stat = statSync(path);
  if (!stat.isFile()) throw new Error('not a regular file');
  if (stat.size > maxBytes) throw new Error(`file exceeds the read cap (${stat.size} > ${maxBytes} bytes)`);
  return readFileSync(path, 'utf8');
}

/** Display label for a path: relative when it lives under the workspace, absolute otherwise. */
function relativeTo(root, path) {
  const label = relative(root, path);
  return label.startsWith('..') ? path : label;
}

export function apply(ctx, config = {}) {
  const workspace = resolve(config.workspace ?? process.cwd());
  const artifactsDir = join(workspace, '.ctx-audit');
  const mcpCommand = config.mcpCommand ?? 'ctx-audit';
  const mcpCommandAbsolute = isAbsolute(mcpCommand);
  const mcpCommandFound = mcpCommandAbsolute ? existsSync(mcpCommand) : null;
  // ── target selection ──────────────────────────────────────────────────────
  // Everything path-based on this panel is relative to the SELECTED target, not
  // to the process working directory: pointing a control panel at the engine's
  // own checkout is never what a user means.
  // ── roadmap ───────────────────────────────────────────────────────────────
  // The forward-looking plan is a document someone edits; the live items are
  // derived from this repository's own records on every request, so the card is
  // not a frozen snapshot any more.
  const planPath = resolve(config.roadmapPath ?? join(workspace, 'harness-private', 'roadmap.json'));

  function planDocument() {
    const candidates = [planPath, fileURLToPath(new URL('./roadmap.json', import.meta.url))];
    for (const candidate of candidates) {
      try {
        const parsed = JSON.parse(readTextFile(candidate, 1024 * 1024));
        let mtime = null;
        try {
          mtime = statSync(candidate).mtime.toISOString();
        } catch {
          mtime = null;
        }
        const ageDays = mtime ? Math.floor((Date.now() - new Date(mtime).getTime()) / 86400000) : null;
        return { source: relativeTo(workspace, candidate), mtime, ageDays, items: parsed.items || [] };
      } catch {
        /* try the next candidate */
      }
    }
    return { source: null, mtime: null, ageDays: null, items: [], error: 'no roadmap document found' };
  }

  /** Count table rows under the first heading whose title contains `heading`. */
  function countRowsIn(text, heading) {
    let current = null;
    let count = 0;
    for (const line of text.split(/\r?\n/)) {
      const match = line.match(/^##\s+(.+?)\s*$/);
      if (match) {
        current = match[1];
        continue;
      }
      if (current && current.includes(heading) && line.startsWith('| ')) count += 1;
    }
    return count;
  }

  /** Live items: each one is read from a real local record, and skipped if absent. */
  function derivedItems() {
    const items = [];
    try {
      const text = readTextFile(
        resolve(config.defectRegister ?? join(workspace, 'docs', 'CTX-Audit-C-问题总登记.md')),
        2 * 1024 * 1024,
      );
      const fixed = (text.match(/^\|\s*\*{0,2}A\d+/gm) || []).length;
      const pending = (text.match(/^\|\s*\*{0,2}B\d+/gm) || []).length;
      if (fixed || pending) {
        items.push({
          area: '质量',
          title: `缺陷登记：已修 ${fixed} / 待修 ${pending}`,
          status: pending > 0 ? 'active' : 'done',
          note: '实时统计自私有问题总登记',
        });
      }
    } catch {
      /* no register in this deployment */
    }
    try {
      const text = readTextFile(
        resolve(config.ledgerRegistry ?? join(workspace, 'docs', 'audit-rounds', 'projects-registry.md')),
        4 * 1024 * 1024,
      );
      const inFlight = countRowsIn(text, '在跑');
      items.push({
        area: '台账',
        title: `在跑 / 遗留 ${inFlight} 项`,
        status: inFlight > 0 ? 'active' : 'done',
        note: '实时统计自共享项目库',
      });
    } catch {
      /* no ledger in this deployment */
    }
    try {
      const text = readTextFile(resolve(config.changelog ?? join(workspace, 'CHANGELOG.md')), 8 * 1024 * 1024);
      const unreleased = text.split(/^## /m)[1] || '';
      const bullets = (unreleased.match(/^- \*\*/gm) || []).length;
      items.push({
        area: '引擎',
        title: `未发布改动 ${bullets} 条`,
        status: bullets > 0 ? 'active' : 'planned',
        note: '实时统计自 CHANGELOG 的 Unreleased 段',
      });
    } catch {
      /* no changelog in this deployment */
    }
    return items;
  }

  function roadmapReport() {
    const plan = planDocument();
    return { ...plan, derived: derivedItems(), generatedAt: new Date().toISOString() };
  }

  const targetsRoot = resolve(config.targetsRoot ?? dirname(workspace));
  const allowedRoots = (Array.isArray(config.allowedRoots) && config.allowedRoots.length
    ? config.allowedRoots
    : [workspace, targetsRoot]
  ).map((root) => resolve(root));

  /** Resolve and validate `?target=`; an invalid or out-of-root path is refused. */
  const selectTarget = (url) => {
    const requested = url.searchParams.get('target');
    const candidate = resolve(requested || workspace);
    let stat = null;
    try {
      stat = statSync(candidate);
    } catch {
      return { ok: false, error: 'target does not exist', path: candidate };
    }
    if (!stat.isDirectory()) return { ok: false, error: 'target is not a directory', path: candidate };
    const inside = allowedRoots.some(
      (root) => candidate === root || candidate.startsWith(root + sep) || candidate.startsWith(`${root}/`),
    );
    if (!inside) return { ok: false, error: 'target is outside the allowed roots', path: candidate, allowedRoots };
    return {
      ok: true,
      path: candidate,
      artifactsDir: join(candidate, '.ctx-audit'),
      isProject: PROJECT_MARKERS.some((marker) => existsSync(join(candidate, marker))),
    };
  };

  const projectCache = new Map();
  const projectInFlight = new Map();

  async function projectReport(targetPath, refresh) {
    const now = Date.now();
    const hit = projectCache.get(targetPath);
    if (!refresh && hit && now - hit.at < ENGINE_TTL_MS) {
      return { ...hit.result, cached: true, checkedAt: new Date(hit.at).toISOString() };
    }
    let flight = projectInFlight.get(targetPath);
    if (!flight) {
      flight = probeProject(mcpCommand, targetPath, PROJECT_TIMEOUT_MS).then((result) => {
        projectCache.set(targetPath, { at: Date.now(), result });
        projectInFlight.delete(targetPath);
        return result;
      });
      projectInFlight.set(targetPath, flight);
    }
    const result = await flight;
    return { ...result, cached: false, checkedAt: new Date().toISOString() };
  }



  // The roadmap is shipped next to this module and served verbatim.
  let roadmap;
  try {
    roadmap = JSON.parse(
      readFileSync(fileURLToPath(new URL('./roadmap.json', import.meta.url)), 'utf8'),
    );
  } catch (error) {
    roadmap = { error: `roadmap_unavailable: ${String((error && error.message) || error)}`, items: [] };
  }

  let engineCache = null;
  let engineInFlight = null;

  async function engineReport(refresh) {
    const now = Date.now();
    if (!refresh && engineCache && now - engineCache.at < ENGINE_TTL_MS) {
      return { ...engineCache.result, cached: true, checkedAt: new Date(engineCache.at).toISOString() };
    }
    if (!engineInFlight) {
      engineInFlight = probeEngine(mcpCommand, workspace, ENGINE_TIMEOUT_MS).then((result) => {
        engineCache = { at: Date.now(), result };
        engineInFlight = null;
        return result;
      });
    }
    const result = await engineInFlight;
    return { ...result, cached: false, checkedAt: new Date().toISOString() };
  }

  ctx.effect(() =>
    ctx.webServer.register({
      kind: 'prefix',
      path: API_PREFIX,
      async handler(req, res) {
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          sendJson(res, 405, { error: 'method_not_allowed' });
          return;
        }
        const url = new URL(req.url ?? '/', 'http://127.0.0.1');
        const route = url.pathname;
        // Every path-based read follows the SELECTED target, not the process
        // working directory; an explicit but invalid target is refused.
        const selection = selectTarget(url);
        if (!selection.ok && url.searchParams.has('target')) {
          sendJson(res, 400, { error: selection.error, target: selection.path, allowedRoots });
          return;
        }

        if (route === `${API_PREFIX}/status`) {
          const listing = inventory(selection.artifactsDir);
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
            target: selection.path,
            targetIsProject: Boolean(selection.isProject),
            artifactsDir: selection.artifactsDir,
            artifacts: listing ? listing.rows : null,
            counts: listing ? listing.counts : null,
            listingTruncated: listing ? listing.truncated : null,
            artifactsTotal: listing ? listing.total : null,
            artifactLimit: MAX_ARTIFACTS,
            logs: { files: listLogs(selection.artifactsDir), maxLines: MAX_LOG_LINES },
            generatedAt: new Date().toISOString(),
          });
          return;
        }

        if (route === `${API_PREFIX}/engine`) {
          const refresh = url.searchParams.get('refresh') === '1';
          sendJson(res, 200, await engineReport(refresh));
          return;
        }

        if (route === `${API_PREFIX}/logs`) {
          const files = listLogs(selection.artifactsDir);
          const requested = url.searchParams.get('file');
          const name = requested || (files[0] && files[0].name) || null;
          // Only names from the enumeration are readable, so a crafted `file`
          // value cannot walk out of the directory.
          if (!name || !files.some((entry) => entry.name === name)) {
            sendJson(res, 200, { files, file: null, lines: [], truncated: false, error: files.length ? 'unknown_log_file' : 'no_log_files' });
            return;
          }
          const requestedLines = Number.parseInt(url.searchParams.get('lines') ?? '', 10);
          const maxLines = Number.isFinite(requestedLines)
            ? Math.min(Math.max(requestedLines, 1), MAX_LOG_LINES)
            : 200;
          try {
            const tail = tailFile(join(selection.artifactsDir, name), maxLines);
            sendJson(res, 200, { files, file: name, ...tail, maxLines });
          } catch (error) {
            sendJson(res, 200, { files, file: name, lines: [], truncated: false, error: `read_failed: ${String((error && error.message) || error)}` });
          }
          return;
        }

        if (route === `${API_PREFIX}/presets`) {
          // The preset registry is a HOST service. Read it optionally instead of
          // declaring it in `inject`, so this plugin still activates in a profile
          // that has no registry row (in that case the card says so).
          let registry = null;
          try {
            registry = ctx.get('agentPresets');
          } catch (error) {
            registry = null;
          }
          if (!registry) {
            sendJson(res, 200, { available: false, reason: 'agentPresets service is not mounted' });
            return;
          }
          try {
            const rows =
              typeof registry.remoteExportList === 'function'
                ? await registry.remoteExportList()
                : await registry.list();
            const list = Array.isArray(rows) ? rows : (rows && rows.presets) || [];
            sendJson(res, 200, {
              available: true,
              presets: list.map((row) => ({
                id: row.id,
                name: row.name ?? null,
                description: row.description ?? null,
                isDefault: Boolean(row.isDefault),
                broken: row.broken ?? null,
              })),
            });
          } catch (error) {
            sendJson(res, 200, { available: true, error: String((error && error.message) || error) });
          }
          return;
        }

        if (route === `${API_PREFIX}/targets`) {
          const list = discoverTargets(targetsRoot, config.maxTargets ?? 60);
          list.sort((a, b) => {
            if (a.hasAudit !== b.hasAudit) return a.hasAudit ? -1 : 1;
            return String(b.newest || '').localeCompare(String(a.newest || ''));
          });
          sendJson(res, 200, {
            root: targetsRoot,
            workspace,
            allowedRoots,
            targets: list,
          });
          return;
        }

        if (route === `${API_PREFIX}/project`) {
          if (!selection.ok) {
            sendJson(res, 400, { ok: false, error: selection.error, target: selection.path });
            return;
          }
          const value = await projectReport(selection.path, url.searchParams.get('refresh') === '1');
          sendJson(res, 200, { target: selection.path, ...value });
          return;
        }

        if (route === `${API_PREFIX}/roadmap`) {
          sendJson(res, 200, roadmapReport());
          return;
        }

        sendJson(res, 404, { error: 'not_found' });
      },
    }),
  );
}
