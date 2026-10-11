/**
 * Browser half of the CTX-Audit web surface — the control panel.
 *
 * A page in this Harness is not a URL route: it is a keyed entry in the layout's
 * `main` slot, selected by the sidebar entry that shares its panel id. So this
 * plugin registers two slots with one shared id:
 *
 *   - `main` (keyed)              the panel itself;
 *   - `sidebar.panellist` (list)  the navigation entry that selects it.
 *
 * Data comes from the host half's read-only endpoints rather than from the
 * session: a `main` key other than the reserved `conversation` gets no Session
 * binding, and the panel must render before any agent exists.
 *
 * Contract notes, from the installed plugin-development skill:
 *   - the loader id equals the package name;
 *   - React comes from the browser module table, so `require('react')` is the
 *     only import a plain-JS client half needs;
 *   - a Harness Client package must NOT be imported as a module;
 *     `dsh.client.inject` entries only order activation;
 *   - registrations go through `ctx.slots.inject`, because the owning slot may
 *     not be declared yet when this plugin loads;
 *   - no DOM writes outside the component and no append to `document.body`;
 *   - styles use host theme tokens with fallbacks, and component-local CSS is
 *     rendered as part of the component so unmounting removes it.
 */
window.__ModuleLoader__.load({
  id: '@local/ctx-audit-web',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useCallback, useEffect, useMemo, useState } = React;

    /** Shared by the sidebar entry and the panel it selects. */
    const PANEL_ID = 'ctx-audit';

    /** Owned by the host half of this same bundle. */
    const API = '/ctx-audit/api';

    const CSS = `
.caw-root{color:var(--dsw-alias-text-primary,inherit);font-size:var(--dsw-alias-font-size-body,13px);line-height:1.55}
.caw-head{display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap;padding:16px 20px 12px;border-bottom:1px solid var(--dsw-alias-border-secondary,rgba(128,128,128,.25));position:sticky;top:0;background:var(--dsw-alias-bg-primary,transparent);z-index:2}
.caw-title{margin:0;font-size:17px;font-weight:650;letter-spacing:.2px}
.caw-sub{margin:2px 0 0;opacity:.62;font-size:12px}
.caw-spacer{flex:1}
.caw-pills{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.caw-pill{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--dsw-alias-border-secondary,rgba(128,128,128,.3));border-radius:999px;padding:2px 9px;font-size:11.5px;white-space:nowrap}
.caw-ok{color:var(--dsw-alias-state-success,#1a7f37)}
.caw-bad{color:var(--dsw-alias-state-danger,#b42318)}
.caw-btn{border:1px solid var(--dsw-alias-border-secondary,rgba(128,128,128,.35));background:transparent;color:inherit;border-radius:7px;padding:3px 10px;font-size:12px;cursor:pointer;transition:background .12s ease}
.caw-btn:hover:not(:disabled){background:var(--dsw-alias-bg-tertiary,rgba(128,128,128,.12))}
.caw-btn:disabled{opacity:.5;cursor:default}
.caw-body{padding:14px 20px 20px;display:flex;flex-direction:column;gap:14px}
.caw-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:10px}
.caw-stat{border:1px solid var(--dsw-alias-border-secondary,rgba(128,128,128,.28));border-radius:10px;padding:9px 12px;background:var(--dsw-alias-bg-secondary,rgba(128,128,128,.05))}
.caw-stat-v{font-size:19px;font-weight:650;font-variant-numeric:tabular-nums;letter-spacing:.2px}
.caw-stat-l{font-size:11.5px;opacity:.62;margin-top:1px}
.caw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:12px;align-items:start}
.caw-card{border:1px solid var(--dsw-alias-border-secondary,rgba(128,128,128,.28));border-radius:10px;background:var(--dsw-alias-bg-secondary,rgba(128,128,128,.045));overflow:hidden}
.caw-card-h{display:flex;align-items:center;gap:8px;padding:9px 12px;border-bottom:1px solid var(--dsw-alias-border-secondary,rgba(128,128,128,.2))}
.caw-card-t{font-weight:620;font-size:12.5px}
.caw-card-b{padding:9px 12px}
.caw-row{display:flex;gap:8px;padding:2.5px 0;align-items:baseline}
.caw-k{opacity:.6;min-width:74px;flex:none;font-size:12px}
.caw-v{overflow-wrap:anywhere;min-width:0}
.caw-code{font-family:var(--dsw-alias-font-family-mono,ui-monospace,Menlo,monospace);font-size:11.5px}
.caw-muted{opacity:.58;font-size:11.5px}
.caw-scroll{max-height:236px;overflow:auto;scrollbar-width:thin}
.caw-scroll::-webkit-scrollbar{width:8px;height:8px}
.caw-scroll::-webkit-scrollbar-thumb{background:var(--dsw-alias-border-secondary,rgba(128,128,128,.4));border-radius:8px}
.caw-item{display:flex;gap:8px;align-items:baseline;padding:3px 2px;border-bottom:1px dashed var(--dsw-alias-border-secondary,rgba(128,128,128,.18))}
.caw-item:last-child{border-bottom:none}
.caw-item:hover{background:var(--dsw-alias-bg-tertiary,rgba(128,128,128,.09))}
.caw-name{flex:1;min-width:0;overflow-wrap:anywhere;font-family:var(--dsw-alias-font-family-mono,ui-monospace,monospace);font-size:11.5px}
.caw-log{font-family:var(--dsw-alias-font-family-mono,ui-monospace,monospace);font-size:11.5px;white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.caw-logline{padding:1px 0}
.caw-logline:hover{background:var(--dsw-alias-bg-tertiary,rgba(128,128,128,.1))}
.caw-sel{border:1px solid var(--dsw-alias-border-secondary,rgba(128,128,128,.35));background:transparent;color:inherit;border-radius:6px;padding:2px 6px;font-size:11.5px;max-width:190px}
.caw-road{display:flex;gap:9px;padding:7px 2px;border-bottom:1px dashed var(--dsw-alias-border-secondary,rgba(128,128,128,.18))}
.caw-road:last-child{border-bottom:none}
.caw-dot{width:7px;height:7px;border-radius:50%;margin-top:5px;flex:none;background:var(--dsw-alias-text-secondary,#888)}
.caw-dot-done{background:var(--dsw-alias-state-success,#1a7f37)}
.caw-dot-active{background:var(--dsw-alias-state-info,#0969da)}
.caw-dot-planned{background:var(--dsw-alias-state-warning,#9a6700)}
.caw-dot-decision{background:var(--dsw-alias-state-danger,#b42318)}
.caw-tool{padding:4px 2px;border-bottom:1px dashed var(--dsw-alias-border-secondary,rgba(128,128,128,.18))}
.caw-tool:last-child{border-bottom:none}
.caw-tool-n{font-family:var(--dsw-alias-font-family-mono,ui-monospace,monospace);font-size:11.5px}
.caw-tool-d{opacity:.66;font-size:11.5px;margin-top:1px}
.caw-foot{display:flex;gap:10px;flex-wrap:wrap;opacity:.55;font-size:11px;padding-top:2px}
.caw-skel{border-radius:6px;background:linear-gradient(90deg,var(--dsw-alias-bg-tertiary,rgba(128,128,128,.12)) 25%,var(--dsw-alias-bg-secondary,rgba(128,128,128,.06)) 37%,var(--dsw-alias-bg-tertiary,rgba(128,128,128,.12)) 63%);background-size:400% 100%;animation:caw-shim 1.3s ease-in-out infinite;height:11px;margin:4px 0}
@keyframes caw-shim{0%{background-position:100% 0}100%{background-position:0 0}}
.caw-err{color:var(--dsw-alias-state-danger,#b42318);font-size:12px}
`;

    async function getJson(url, signal) {
      const res = await fetch(url, { headers: { accept: 'application/json' }, signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    }

    function fmtBytes(n) {
      if (typeof n !== 'number' || !Number.isFinite(n)) return '—';
      if (n < 1024) return `${n} B`;
      if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
      if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
      return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
    }

    function fmtTime(iso) {
      if (!iso) return '—';
      const d = new Date(iso);
      return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
    }

    function fmtAgo(iso) {
      if (!iso) return '';
      const then = new Date(iso).getTime();
      if (Number.isNaN(then)) return '';
      const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
      if (secs < 60) return `${secs} 秒前`;
      if (secs < 3600) return `${Math.round(secs / 60)} 分钟前`;
      if (secs < 86400) return `${Math.round(secs / 3600)} 小时前`;
      return `${Math.round(secs / 86400)} 天前`;
    }

    /** One resource's async state: loading → ready | error (refreshing keeps the old data). */
    function useResource(url, deps) {
      const [state, setState] = useState({ phase: 'loading' });
      useEffect(() => {
        let alive = true;
        const controller = new AbortController();
        setState((prev) => (prev.phase === 'ready' ? { phase: 'refreshing', data: prev.data } : { phase: 'loading' }));
        getJson(url, controller.signal)
          .then((data) => {
            if (alive) setState({ phase: 'ready', data });
          })
          .catch((error) => {
            if (!alive || (error && error.name === 'AbortError')) return;
            setState({ phase: 'error', message: String((error && error.message) || error) });
          });
        return () => {
          alive = false;
          controller.abort();
        };
        // The URL string already encodes every input, so it is the dependency.
        // eslint-disable-next-line react-hooks/exhaustive-deps
      }, deps);
      return state;
    }

    function Pill({ tone, children }) {
      return h('span', { className: `caw-pill ${tone || ''}` }, children);
    }

    function Card({ title, extra, children }) {
      return h('section', { className: 'caw-card' }, [
        h('div', { key: 'h', className: 'caw-card-h' }, [
          h('div', { key: 't', className: 'caw-card-t' }, title),
          h('div', { key: 's', className: 'caw-spacer' }),
          extra || null,
        ]),
        h('div', { key: 'b', className: 'caw-card-b' }, children),
      ]);
    }

    function Row({ label, children }) {
      return h('div', { className: 'caw-row' }, [
        h('div', { key: 'k', className: 'caw-k' }, label),
        h('div', { key: 'v', className: 'caw-v' }, children),
      ]);
    }

    function Skeleton({ rows = 3 }) {
      return h(
        'div',
        null,
        Array.from({ length: rows }, (_, i) =>
          h('div', { key: i, className: 'caw-skel', style: { width: `${92 - i * 13}%` } }),
        ),
      );
    }

    function Empty({ children }) {
      return h('div', { className: 'caw-muted' }, children);
    }

    function ErrorLine({ message }) {
      return h('div', { className: 'caw-err' }, message);
    }

    function StatusCard({ status }) {
      let body;
      if (status.phase === 'loading') body = h(Skeleton, { rows: 6 });
      else if (status.phase === 'error') body = h(ErrorLine, { message: `读取失败：${status.message}` });
      else {
        const d = status.data || {};
        const mcp = d.mcp || {};
        const found = mcp.commandFound;
        body = [
          h(Row, { key: 'name', label: 'serverName' }, h('code', { className: 'caw-code' }, mcp.serverName || '—')),
          h(Row, { key: 'tr', label: '传输' }, h('code', { className: 'caw-code' }, mcp.transport || '—')),
          h(Row, { key: 'cmd', label: '命令' }, h('code', { className: 'caw-code' }, mcp.command || '—')),
          h(
            Row,
            { key: 'found', label: '二进制' },
            found === true
              ? h('span', { className: 'caw-ok' }, '已找到')
              : found === false
                ? h('span', { className: 'caw-bad' }, '未找到（MCP 行会启动失败）')
                : h('span', { className: 'caw-muted' }, '裸命令名，经 PATH 解析'),
          ),
          h(Row, { key: 'pfx', label: '工具前缀' }, h('code', { className: 'caw-code' }, mcp.toolNamePrefix || '—')),
          h(Row, { key: 'dir', label: '证据目录' }, h('code', { className: 'caw-code' }, d.artifactsDir || '—')),
        ];
      }
      return h(Card, { title: 'MCP 配置', extra: h('span', { key: 'x', className: 'caw-muted' }, '来自 profile patch') }, body);
    }

    function EngineCard({ engine, onReprobe }) {
      const extra = h(
        'button',
        { className: 'caw-btn', type: 'button', onClick: onReprobe, disabled: engine.phase === 'loading' },
        engine.phase === 'loading' ? '探测中…' : '重新探测',
      );
      let body;
      if (engine.phase === 'loading') body = h(Skeleton, { rows: 4 });
      else if (engine.phase === 'error') body = h(ErrorLine, { message: `读取失败：${engine.message}` });
      else {
        const d = engine.data || {};
        if (!d.ok) {
          body = [
            h(Row, { key: 'st', label: '状态' }, h('span', { className: 'caw-bad' }, d.error || '握手失败')),
            d.stderr ? h('div', { key: 'err', className: 'caw-err caw-code' }, String(d.stderr).slice(0, 400)) : null,
          ];
        } else {
          const tools = d.tools || [];
          body = [
            h(
              Row,
              { key: 'srv', label: '服务端' },
              h(
                'code',
                { className: 'caw-code' },
                `${(d.serverInfo && d.serverInfo.name) || '?'} ${(d.serverInfo && d.serverInfo.version) || ''}`.trim(),
              ),
            ),
            h(Row, { key: 'proto', label: '协议' }, h('code', { className: 'caw-code' }, d.protocolVersion || '—')),
            h(
              Row,
              { key: 'n', label: '工具数' },
              `${d.toolCount}${d.cached ? '（缓存）' : ''}${d.checkedAt ? ` · ${fmtAgo(d.checkedAt)}` : ''}`,
            ),
            h(
              'div',
              { key: 'tools', className: 'caw-scroll', style: { marginTop: '6px' } },
              tools.map((tool) =>
                h('div', { key: tool.name, className: 'caw-tool' }, [
                  h('div', { key: 'n', className: 'caw-tool-n' }, tool.name),
                  tool.description ? h('div', { key: 'd', className: 'caw-tool-d' }, tool.description) : null,
                ]),
              ),
            ),
          ];
        }
      }
      return h(Card, { title: 'MCP 引擎（实时握手）', extra }, body);
    }

    function ArtifactsCard({ status }) {
      let body;
      if (status.phase === 'loading') body = h(Skeleton, { rows: 6 });
      else if (status.phase === 'error') body = h(ErrorLine, { message: `读取失败：${status.message}` });
      else {
        const d = status.data || {};
        const items = d.artifacts;
        if (items === null) body = h(Empty, null, '证据目录不存在（尚未产生报告/基线）');
        else if (items.length === 0) body = h(Empty, null, '证据目录为空');
        else {
          body = [
            h(
              'div',
              { key: 'list', className: 'caw-scroll' },
              items.map((it, i) =>
                h('div', { key: `${it.name}-${i}`, className: 'caw-item' }, [
                  h('span', { key: 'n', className: 'caw-name' }, it.name, it.kind === 'dir' ? '/' : ''),
                  h('span', { key: 's', className: 'caw-muted' }, fmtBytes(it.bytes)),
                  h('span', { key: 't', className: 'caw-muted', title: fmtTime(it.mtime) }, fmtAgo(it.mtime)),
                ]),
              ),
            ),
            d.listingTruncated
              ? h(
                  'div',
                  { key: 'tr', className: 'caw-muted', style: { marginTop: '6px' } },
                  `仅显示前 ${d.artifactLimit} 项（共 ${d.artifactsTotal} 项）`,
                )
              : null,
          ];
        }
      }
      return h(Card, { title: '证据产物', extra: h('span', { key: 'x', className: 'caw-muted' }, '只读 · 有界') }, body);
    }

    function LogsCard({ logs, file, lines, onFile, onLines, onReload }) {
      const files = (logs.data && logs.data.files) || [];
      const selected = file || (logs.data && logs.data.file) || '';
      const extra = h('div', { style: { display: 'flex', gap: '6px', alignItems: 'center' } }, [
        h(
          'select',
          { key: 'f', className: 'caw-sel', value: selected, onChange: (e) => onFile(e.target.value) },
          files.length
            ? files.map((f) => h('option', { key: f.name, value: f.name }, f.name))
            : h('option', { value: '' }, '（无 .log 文件）'),
        ),
        h(
          'select',
          { key: 'l', className: 'caw-sel', value: lines, onChange: (e) => onLines(e.target.value) },
          ['100', '200', '500'].map((n) => h('option', { key: n, value: n }, `${n} 行`)),
        ),
        h('button', { key: 'r', className: 'caw-btn', type: 'button', onClick: onReload }, '重载'),
      ]);

      let body;
      if (logs.phase === 'loading') body = h(Skeleton, { rows: 7 });
      else if (logs.phase === 'error') body = h(ErrorLine, { message: `读取失败：${logs.message}` });
      else {
        const d = logs.data || {};
        if (d.error) body = h(Empty, null, `无法读取：${d.error}`);
        else if (!d.lines || d.lines.length === 0) body = h(Empty, null, '日志为空');
        else {
          body = [
            h(
              'div',
              { key: 'scroll', className: 'caw-scroll' },
              h(
                'pre',
                { className: 'caw-log' },
                d.lines.map((line, i) => h('div', { key: i, className: 'caw-logline' }, line || ' ')),
              ),
            ),
            d.truncated
              ? h('div', { key: 'tr', className: 'caw-muted', style: { marginTop: '6px' } }, '仅显示文件末尾（已截断）')
              : null,
          ];
        }
      }
      return h(Card, { title: '日志', extra }, body);
    }

    function RoadmapCard({ roadmap }) {
      let body;
      if (roadmap.phase === 'loading') body = h(Skeleton, { rows: 5 });
      else if (roadmap.phase === 'error') body = h(ErrorLine, { message: `读取失败：${roadmap.message}` });
      else {
        const d = roadmap.data || {};
        const items = d.items || [];
        const label = { done: '已完成', active: '进行中', planned: '计划', decision: '待决策' };
        if (d.error) body = h(Empty, null, d.error);
        else if (items.length === 0) body = h(Empty, null, '路线图为空');
        else {
          body = [
            h(
              'div',
              { key: 'list' },
              items.map((item, i) =>
                h('div', { key: i, className: 'caw-road' }, [
                  h('span', { key: 'd', className: `caw-dot caw-dot-${item.status || 'planned'}` }),
                  h('div', { key: 'c', style: { minWidth: 0 } }, [
                    h('div', { key: 't', style: { fontWeight: 550 } }, [
                      item.title,
                      h('span', { key: 'b', className: 'caw-muted', style: { marginLeft: '8px' } }, label[item.status] || item.status),
                    ]),
                    item.area ? h('div', { key: 'a', className: 'caw-muted' }, item.area) : null,
                    item.note ? h('div', { key: 'n', className: 'caw-muted' }, item.note) : null,
                  ]),
                ]),
              ),
            ),
            d.updated ? h('div', { key: 'u', className: 'caw-muted', style: { marginTop: '6px' } }, `更新于 ${d.updated}`) : null,
          ];
        }
      }
      return h(Card, { title: '路线图', extra: h('span', { key: 'x', className: 'caw-muted' }, '随仓库提交') }, body);
    }

    function CtxAuditPanel() {
      const [nonce, setNonce] = useState(0);
      const [engineNonce, setEngineNonce] = useState(0);
      const [logFile, setLogFile] = useState(null);
      const [logLines, setLogLines] = useState('200');
      const [logNonce, setLogNonce] = useState(0);

      const status = useResource(`${API}/status`, [nonce]);
      const engine = useResource(`${API}/engine${engineNonce ? '?refresh=1' : ''}`, [engineNonce]);
      const roadmap = useResource(`${API}/roadmap`, [nonce]);
      const logs = useResource(
        `${API}/logs?lines=${encodeURIComponent(logLines)}${logFile ? `&file=${encodeURIComponent(logFile)}` : ''}`,
        [logFile, logLines, logNonce, nonce],
      );

      const refreshAll = useCallback(() => {
        setEngineNonce((n) => n + 1);
        setNonce((n) => n + 1);
        setLogNonce((n) => n + 1);
      }, []);

      const s = status.phase === 'ready' || status.phase === 'refreshing' ? status.data : null;
      const e = engine.phase === 'ready' || engine.phase === 'refreshing' ? engine.data : null;

      const pills = useMemo(() => {
        const list = [];
        if (s) {
          const found = s.mcp && s.mcp.commandFound;
          list.push(
            h(
              Pill,
              { key: 'mcp', tone: found === true ? 'caw-ok' : found === false ? 'caw-bad' : '' },
              found === true ? 'MCP 已就绪' : found === false ? 'MCP 二进制未找到' : 'MCP 经 PATH 解析',
            ),
          );
        }
        if (e) {
          list.push(
            h(
              Pill,
              { key: 'eng', tone: e.ok ? 'caw-ok' : 'caw-bad' },
              e.ok ? `引擎 ${(e.serverInfo && e.serverInfo.version) || '?'}` : '引擎不可用',
            ),
          );
          if (e.ok) list.push(h(Pill, { key: 'tools' }, `${e.toolCount} 工具`));
        }
        return list;
      }, [s, e]);

      const stats = useMemo(() => {
        const counts = (s && s.counts) || null;
        return [
          { label: 'MCP 工具', value: e && e.ok ? e.toolCount : '—' },
          { label: '证据产物', value: counts ? counts.files + counts.dirs : '—' },
          { label: '证据体积', value: counts ? fmtBytes(counts.bytes) : '—' },
          { label: '日志文件', value: s && s.logs ? s.logs.files.length : '—' },
        ];
      }, [s, e]);

      const busy = status.phase === 'loading';

      return h('div', { className: 'caw-root', 'data-ctx-audit-page': 'true' }, [
        h('style', { key: 'css' }, CSS),
        h('div', { key: 'head', className: 'caw-head' }, [
          h('div', { key: 't' }, [
            h('h2', { key: 'h', className: 'caw-title' }, 'CTX-Audit'),
            h('p', { key: 'p', className: 'caw-sub' }, '代码安全审计 · 证据层控制面板'),
          ]),
          h('div', { key: 's', className: 'caw-spacer' }),
          h('div', { key: 'pills', className: 'caw-pills' }, pills),
          h('button', { key: 'r', className: 'caw-btn', type: 'button', onClick: refreshAll, disabled: busy }, busy ? '刷新中…' : '刷新'),
        ]),
        h('div', { key: 'body', className: 'caw-body' }, [
          h(
            'div',
            { key: 'stats', className: 'caw-stats' },
            stats.map((stat) =>
              h('div', { key: stat.label, className: 'caw-stat' }, [
                h('div', { key: 'v', className: 'caw-stat-v' }, String(stat.value)),
                h('div', { key: 'l', className: 'caw-stat-l' }, stat.label),
              ]),
            ),
          ),
          h('div', { key: 'grid', className: 'caw-grid' }, [
            h(EngineCard, { key: 'engine', engine, onReprobe: () => setEngineNonce((n) => n + 1) }),
            h(StatusCard, { key: 'status', status }),
            h(LogsCard, {
              key: 'logs',
              logs,
              file: logFile,
              lines: logLines,
              onFile: setLogFile,
              onLines: setLogLines,
              onReload: () => setLogNonce((n) => n + 1),
            }),
            h(ArtifactsCard, { key: 'artifacts', status }),
            h(RoadmapCard, { key: 'roadmap', roadmap }),
          ]),
          h('div', { key: 'foot', className: 'caw-foot' }, [
            s && s.workspace ? h('span', { key: 'w' }, `工作区 ${s.workspace}`) : null,
            s && s.generatedAt ? h('span', { key: 'g' }, `快照 ${fmtTime(s.generatedAt)}`) : null,
            h('span', { key: 'e' }, `端点 ${API}/status · /engine · /logs · /roadmap`),
          ]),
        ]),
      ]);
    }

    function CtxAuditIcon() {
      return h(
        'svg',
        {
          viewBox: '0 0 24 24',
          width: 16,
          height: 16,
          'aria-hidden': true,
          style: { display: 'block' },
        },
        h('path', {
          d: 'M12 2 4 5v6c0 5 3.4 9.3 8 11 4.6-1.7 8-6 8-11V5l-8-3Z',
          fill: 'none',
          stroke: 'currentColor',
          strokeWidth: 1.6,
        }),
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('main', () =>
          ctx.slots.register({ name: 'main', key: PANEL_ID }, CtxAuditPanel),
        );
        ctx.slots.inject('sidebar.panellist', () =>
          ctx.slots.register(
            { name: 'sidebar.panellist', id: PANEL_ID, order: 50, label: () => 'CTX-Audit' },
            CtxAuditIcon,
          ),
        );
      },
    };
  },
});
