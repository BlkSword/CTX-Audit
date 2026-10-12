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
.caw-root{color:var(--dsw-alias-label-primary,inherit);font-size:13px;line-height:1.55}
.caw-head{display:flex;align-items:flex-start;gap:14px;flex-wrap:wrap;padding:14px 18px 12px;border-bottom:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.22))}
.caw-title{margin:0;font-size:17px;font-weight:600;letter-spacing:.2px}
.caw-sub{margin:2px 0 0;color:var(--dsw-alias-label-caption,var(--dsw-alias-label-tertiary,inherit));font-size:12px}
.caw-spacer{flex:1}
.caw-pills{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.caw-pill{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.3));border-radius:var(--dsw-radius-lg,999px);padding:2px 9px;font-size:11.5px;color:var(--dsw-alias-label-secondary,inherit);white-space:nowrap}
.caw-ok{color:var(--dsw-alias-state-success-primary,#1a7f37)}
.caw-bad{color:var(--dsw-alias-state-error-primary,#b42318)}
.caw-warn{color:var(--dsw-alias-state-warn-primary,#9a6700)}
.caw-btn{border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.35));background:transparent;color:inherit;border-radius:var(--dsw-radius-sm,8px);padding:3px 10px;font-size:12px;cursor:pointer;transition:background .12s ease}
.caw-btn:hover:not(:disabled){background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.12))}
.caw-btn:disabled{opacity:.5;cursor:default}
.caw-body{padding:14px 18px 18px;display:flex;flex-direction:column;gap:14px}
.caw-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:10px}
.caw-stat{border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.28));border-radius:var(--dsw-radius-sm,8px);padding:9px 12px;background:var(--dsw-alias-bg-layer-1,var(--dsw-alias-bg-base,transparent))}
.caw-stat-v{font-size:19px;font-weight:600;font-variant-numeric:tabular-nums}
.caw-stat-l{font-size:11.5px;color:var(--dsw-alias-label-tertiary,inherit);margin-top:1px}
.caw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:12px;align-items:start}
.caw-card{border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.28));border-radius:var(--dsw-radius-sm,8px);background:var(--dsw-alias-bg-layer-1,var(--dsw-alias-bg-base,transparent));overflow:hidden}
.caw-card-h{display:flex;align-items:center;gap:8px;padding:9px 12px;border-bottom:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.2))}
.caw-card-t{font-weight:600;font-size:12.5px}
.caw-card-b{padding:9px 12px}
.caw-row{display:flex;gap:8px;padding:2.5px 0;align-items:baseline}
.caw-k{color:var(--dsw-alias-label-tertiary,inherit);min-width:74px;flex:none;font-size:12px}
.caw-v{overflow-wrap:anywhere;min-width:0}
.caw-code{font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,Menlo,monospace);font-size:11.5px}
.caw-muted{color:var(--dsw-alias-label-tertiary,inherit);font-size:11.5px}
.caw-scroll{max-height:236px;overflow:auto;scrollbar-width:thin}
.caw-scroll::-webkit-scrollbar{width:8px;height:8px}
.caw-scroll::-webkit-scrollbar-thumb{background:var(--dsw-alias-scrollbar-bg-l2,rgba(128,128,128,.4));border-radius:8px}
.caw-item{display:flex;gap:8px;align-items:baseline;padding:3px 4px;border-bottom:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.16));border-radius:var(--dsw-radius-xs,4px)}
.caw-item:last-child{border-bottom:none}
.caw-item:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.09))}
.caw-name{flex:1;min-width:0;overflow-wrap:anywhere;font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,monospace);font-size:11.5px}
.caw-log{font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,monospace);font-size:11.5px;white-space:pre-wrap;overflow-wrap:anywhere;margin:0;background:transparent}
.caw-logline{padding:1px 0}
.caw-logline:hover{background:var(--dsw-alias-interactive-bg-hover,rgba(128,128,128,.08))}
.caw-sel{border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.35));background:var(--dsw-alias-bg-layer-2,transparent);color:inherit;border-radius:var(--dsw-radius-xs,4px);padding:2px 6px;font-size:11.5px;max-width:220px}
.caw-input{border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.35));background:var(--dsw-alias-bg-layer-2,transparent);color:inherit;border-radius:var(--dsw-radius-xs,4px);padding:3px 7px;font-size:11.5px;width:100%;box-sizing:border-box}
.caw-road{display:flex;gap:9px;padding:6px 2px;border-bottom:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.16))}
.caw-road:last-child{border-bottom:none}
.caw-dot{width:7px;height:7px;border-radius:50%;margin-top:5px;flex:none;background:var(--dsw-alias-state-idle-primary,var(--dsw-alias-label-tertiary,#888))}
.caw-dot-done{background:var(--dsw-alias-state-success-primary,#1a7f37)}
.caw-dot-active{background:var(--dsw-alias-state-business-primary,var(--dsw-alias-state-success-primary,#0969da))}
.caw-dot-planned{background:var(--dsw-alias-state-warn-primary,#9a6700)}
.caw-dot-decision{background:var(--dsw-alias-state-error-primary,#b42318)}
.caw-tool{padding:4px 2px;border-bottom:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.16))}
.caw-tool:last-child{border-bottom:none}
.caw-tool-n{font-family:var(--dsw-font-markdown-code-font-family,ui-monospace,monospace);font-size:11.5px}
.caw-tool-d{color:var(--dsw-alias-label-tertiary,inherit);font-size:11.5px;margin-top:1px}
.caw-foot{display:flex;gap:10px;flex-wrap:wrap;color:var(--dsw-alias-label-tertiary,inherit);font-size:11px;padding-top:2px}
.caw-skel{border-radius:var(--dsw-radius-xs,4px);background:linear-gradient(90deg,var(--dsw-alias-bg-layer-2,rgba(128,128,128,.12)) 25%,var(--dsw-alias-bg-layer-1,rgba(128,128,128,.05)) 37%,var(--dsw-alias-bg-layer-2,rgba(128,128,128,.12)) 63%);background-size:400% 100%;animation:caw-shim 1.3s ease-in-out infinite;height:11px;margin:4px 0}
@keyframes caw-shim{0%{background-position:100% 0}100%{background-position:0 0}}
.caw-err{color:var(--dsw-alias-label-error,#b42318);font-size:12px}
.caw-trow{border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.28));border-radius:var(--dsw-radius-sm,8px);padding:7px 9px;background:var(--dsw-alias-bg-layer-1,transparent);display:flex;flex-direction:column;gap:5px}
.caw-trow-h{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.caw-badge{border:1px solid var(--dsw-alias-border-l2,rgba(128,128,128,.35));border-radius:var(--dsw-radius-lg,999px);padding:1px 7px;font-size:10.5px;color:var(--dsw-alias-label-secondary,inherit)}
.caw-preset{display:flex;align-items:baseline;gap:8px;padding:5px 2px;border-bottom:1px solid var(--dsw-alias-border-l1,rgba(128,128,128,.16))}
.caw-preset:last-child{border-bottom:none}
.caw-picker{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
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

    /** ctx-audit's MCP tool surface, live-verified by the host half's /engine endpoint. */
    const MCP_TOOL_NAMES = [
      'get_project_index',
      'get_symbol_definition',
      'get_symbol_references',
      'get_call_hierarchy',
      'slice_backward',
      'get_dataflow_path',
      'get_sanitizer_guards',
      'get_framework_context',
      'get_incremental_status',
      'read_file',
      'list_files',
      'report_finding',
      'finish_analysis',
    ];

    /** Concatenate the text blocks of a settled tool result. */
    function toolResultText(block) {
      const content = (block && block.content) || [];
      const parts = [];
      for (const part of content) {
        if (part && typeof part.text === 'string') parts.push(part.text);
        else if (typeof part === 'string') parts.push(part);
        else if (part) parts.push(JSON.stringify(part));
      }
      return parts.join('\n');
    }

    /**
     * The registered view for one ctx-audit MCP tool call.
     *
     * `tool.call.toolview` is a keyed slot dispatched by the exact wire tool
     * name, so this component is registered once per name in `MCP_TOOL_NAMES`.
     * The owner passes explicit phase props; only the settled phase carries a
     * result, and a preparing call has no arguments at all.
     */
    function CtxAuditToolRow(props) {
      const [expanded, setExpanded] = useState(false);
      const phase = (props && props.phase) || 'result';
      const block = props && props.block;
      const wireName =
        (block && block.call && block.call.name) || (props && props.toolName) || 'ctx-audit';
      const short = String(wireName).replace(/^mcp__ctxaudit__/, '');

      const text = phase === 'result' ? toolResultText(block) : '';
      const lines = text ? text.split(/\r?\n/) : [];
      const isError = phase === 'result' && Boolean(block && block.isError);
      const shown = expanded ? lines.slice(0, 200) : lines.slice(0, 6);

      const head = [
        h('span', { key: 'b', className: 'caw-badge' }, 'CTX-Audit'),
        h('code', { key: 'n', className: 'caw-code' }, short),
      ];
      if (phase === 'result') {
        head.push(
          h('span', { key: 's', className: isError ? 'caw-bad' : 'caw-ok' }, isError ? '失败' : '完成'),
          h('span', { key: 'l', className: 'caw-muted' }, `${lines.length} 行`),
        );
        if (lines.length > 6) {
          head.push(
            h(
              'button',
              { key: 't', className: 'caw-btn', type: 'button', onClick: () => setExpanded((v) => !v) },
              expanded ? '收起' : '展开',
            ),
          );
        }
      } else {
        head.push(h('span', { key: 'p', className: 'caw-muted' }, phase === 'start' ? '调用中…' : '准备中…'));
      }

      return h('div', { className: 'caw-trow', 'data-ctx-audit-tool': short }, [
        h('div', { key: 'h', className: 'caw-trow-h' }, head),
        block && block.error
          ? h('div', { key: 'e', className: 'caw-err' }, `${block.error.name}: ${block.error.reason || block.error.code}`)
          : null,
        shown.length
          ? h(
              'div',
              { key: 'c', className: 'caw-scroll', style: { maxHeight: expanded ? '320px' : '104px' } },
              h('pre', { className: 'caw-log' }, shown.join('\n')),
            )
          : null,
      ]);
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

    /**
     * Roadmap: live items derived from this repository's own records, plus the
     * forward-looking plan document with its own age. The plan stays a document
     * someone edits -- what changes here is that the live half is recomputed on
     * every refresh, and the document's staleness is visible instead of implied.
     */
    function RoadmapCard({ roadmap }) {
      const label = { done: '已完成', active: '进行中', planned: '计划', decision: '待决策' };

      const rowFor = (item, key) =>
        h('div', { key, className: 'caw-road' }, [
          h('span', { key: 'd', className: `caw-dot caw-dot-${item.status || 'planned'}` }),
          h('div', { key: 'c', style: { minWidth: 0 } }, [
            h('div', { key: 't', style: { fontWeight: 550 } }, [
              item.title,
              h('span', { key: 'b', className: 'caw-muted', style: { marginLeft: '8px' } }, label[item.status] || item.status),
            ]),
            item.area ? h('div', { key: 'a', className: 'caw-muted' }, item.area) : null,
            item.note ? h('div', { key: 'n', className: 'caw-muted' }, item.note) : null,
          ]),
        ]);

      let body;
      if (roadmap.phase === 'loading') body = h(Skeleton, { rows: 5 });
      else if (roadmap.phase === 'error') body = h(ErrorLine, { message: `读取失败：${roadmap.message}` });
      else {
        const d = roadmap.data || {};
        const derived = d.derived || [];
        const plan = d.items || [];
        const planHeader =
          `计划文档（${d.source || '—'}${typeof d.ageDays === 'number' ? ` · ${d.ageDays} 天前更新` : ''}）`;
        body = [
          h('div', { key: 'hd', className: 'caw-muted' }, '实时推导（每次刷新重算）'),
          ...derived.map((item, i) => rowFor(item, `d${i}`)),
          h('div', { key: 'hp', className: 'caw-muted', style: { marginTop: '8px' } }, planHeader),
          ...plan.map((item, i) => rowFor(item, `p${i}`)),
          h(
            'div',
            { key: 'hint', className: 'caw-muted', style: { marginTop: '8px' } },
            '编辑计划文件即可更新下半部分；上半部分由仓库记录实时计算',
          ),
        ];
      }
      return h(
        Card,
        {
          title: '路线图',
          extra: h(SourceBadge, { key: 'x', kind: typeof roadmap.data?.ageDays === 'number' ? 'static' : 'local' }),
        },
        body,
      );
    }


    /**
     * Keeps one card's failure from blanking the whole panel.
     *
     * The slot machinery has its own boundary, but it sits above the panel: an
     * uncaught render error inside a single card would take every other card
     * down with it, which is exactly what happened the first time this panel
     * read a host service it had not declared.
     */
    class CardBoundary extends React.Component {
      constructor(props) {
        super(props);
        this.state = { error: null };
      }

      static getDerivedStateFromError(error) {
        return { error };
      }

      componentDidCatch(error) {
        console.warn('[ctx-audit-web] card crashed:', this.props.label, error);
      }

      render() {
        if (this.state.error) {
          return h(
            Card,
            { title: `${this.props.label}（渲染失败）` },
            h(ErrorLine, { message: String((this.state.error && this.state.error.message) || this.state.error) }),
          );
        }
        return this.props.children;
      }
    }

    /**
     * Preset roster card.
     *
     * The roster comes from the host half's own endpoint, NOT from `ctx.remote`:
     * the client kernel refuses to hand a plugin a service it did not declare
     * ("cannot get property \"remote\" without inject"), and that property access
     * throws by itself, so a defensive `ctx.remote && ...` guard cannot save the
     * render. Going through our own read-only endpoint also keeps this card
     * verifiable with curl.
     */
    function PresetsCard({ presets }) {
      let body;
      if (presets.phase === 'loading') body = h(Skeleton, { rows: 5 });
      else if (presets.phase === 'error') body = h(ErrorLine, { message: `读取失败：${presets.message}` });
      else {
        const d = presets.data || {};
        if (!d.available) {
          body = h(Empty, null, `宿主未提供 agentPresets 服务${d.reason ? `（${d.reason}）` : ''}`);
        } else if (d.error) {
          body = h(Empty, null, `读取失败：${d.error}`);
        } else {
          const rows = d.presets || [];
          if (rows.length === 0) body = h(Empty, null, '名册为空');
          else {
            body = rows.map((row, i) =>
              h('div', { key: row.id || i, className: 'caw-preset' }, [
                h('code', { key: 'id', className: 'caw-code' }, row.id || '?'),
                row.name ? h('span', { key: 'n' }, row.name) : null,
                row.isDefault ? h('span', { key: 'd', className: 'caw-ok' }, '默认') : null,
                row.broken ? h('span', { key: 'b', className: 'caw-bad' }, `损坏：${row.broken}`) : null,
                h('span', { key: 's', className: 'caw-spacer' }),
                row.description ? h('span', { key: 'x', className: 'caw-muted' }, row.description) : null,
              ]),
            );
          }
        }
      }
      return h(
        Card,
        { title: 'Agent 预设', extra: h('span', { key: 'x', className: 'caw-muted' }, '来自注册表') },
        body,
      );
    }

    /** Marks where a card's numbers come from, so nothing on this panel is ambiguous. */
    function SourceBadge({ kind }) {
      const label = kind === 'live' ? '实时' : kind === 'local' ? '本地文件' : '静态文档';
      return h('span', { className: `caw-badge ${kind === 'live' ? 'caw-ok' : 'caw-muted'}` }, label);
    }

    /**
     * Target picker: the current selection, a filter over the discovered
     * candidates, a clickable list, and a manual path entry for targets outside
     * the scan root. The candidate list doubles as the aggregate view, so the
     * panel does not grow two cards that say the same thing.
     */
    function TargetPicker({ targets, target, onSelect }) {
      const [filter, setFilter] = useState('');
      const [manual, setManual] = useState('');
      const d = targets.data || {};
      const all = d.targets || [];
      const rows = filter
        ? all.filter((row) => `${row.name} ${row.path}`.toLowerCase().includes(filter.toLowerCase()))
        : all;
      const current = target || d.workspace || '';
      const withEvidence = all.filter((row) => row.hasAudit);
      const totalBytes = all.reduce((sum, row) => sum + (row.bytes || 0), 0);

      return h(Card, { title: '审计目标', extra: h(SourceBadge, { key: 's', kind: 'local' }) }, [
        h('div', { key: 'cur', className: 'caw-row' }, [
          h('div', { key: 'k', className: 'caw-k' }, '当前'),
          h(
            'div',
            { key: 'v', className: 'caw-v' },
            h('code', { className: 'caw-code' }, current || '—'),
            target ? null : h('span', { key: 'd', className: 'caw-muted' }, '（默认：引擎工作目录）'),
          ),
        ]),
        h(
          Row,
          { key: 'sum', label: '汇总' },
          `候选 ${all.length} · 已有证据 ${withEvidence.length} · 证据体积 ${fmtBytes(totalBytes)} · 扫描根 ${
            d.root || '—'
          }`,
        ),
        h('div', { key: 'tools', className: 'caw-picker', style: { margin: '8px 0' } }, [
          h('input', {
            key: 'f',
            className: 'caw-input',
            style: { flex: '1 1 150px' },
            placeholder: '过滤候选…',
            value: filter,
            onChange: (event) => setFilter(event.target.value),
          }),
          h('input', {
            key: 'm',
            className: 'caw-input',
            style: { flex: '1 1 190px' },
            placeholder: '手动输入绝对路径…',
            value: manual,
            onChange: (event) => setManual(event.target.value),
            onKeyDown: (event) => {
              if (event.key === 'Enter' && manual.trim()) onSelect(manual.trim());
            },
          }),
          h(
            'button',
            { key: 'a', className: 'caw-btn', type: 'button', disabled: !manual.trim(), onClick: () => onSelect(manual.trim()) },
            '应用',
          ),
          target ? h('button', { key: 'r', className: 'caw-btn', type: 'button', onClick: () => onSelect('') }, '回到默认') : null,
        ]),
        h(
          'div',
          { key: 'list', className: 'caw-scroll' },
          rows.length
            ? rows.map((row) =>
                h(
                  'div',
                  {
                    key: row.path,
                    className: 'caw-item',
                    title: row.path,
                    style: {
                      cursor: 'pointer',
                      ...(row.path === current
                        ? { background: 'var(--dsw-alias-interactive-bg-active,rgba(128,128,128,.14))' }
                        : {}),
                    },
                    onClick: () => onSelect(row.path),
                  },
                  [
                    h('span', { key: 'n', className: 'caw-name' }, `${row.hasAudit ? '● ' : '○ '}${row.name}`),
                    h(
                      'span',
                      { key: 'm2', className: 'caw-muted' },
                      row.hasAudit
                        ? `${row.files} 文件 · ${fmtBytes(row.bytes)}${row.logs ? ` · ${row.logs} 日志` : ''}`
                        : '无证据目录',
                    ),
                    h('span', { key: 't', className: 'caw-muted' }, row.newest ? fmtAgo(row.newest) : ''),
                  ],
                ),
              )
            : h('div', { key: 'empty', className: 'caw-muted' }, filter ? '无匹配候选' : '未发现候选'),
        ),
        h(
          'div',
          { key: 'roots', className: 'caw-muted', style: { marginTop: '6px' } },
          `点一行即切换 · 允许根：${(d.allowedRoots || []).join(' · ')}`,
        ),
      ]);
    }


    /** Live engine readout of the selected target: one real MCP `get_project_index`. */
    function ProjectCard({ project, target }) {
      let body;
      if (project.phase === 'loading') body = h(Skeleton, { rows: 5 });
      else if (project.phase === 'error') body = h(ErrorLine, { message: `读取失败：${project.message}` });
      else {
        const d = project.data || {};
        if (!d.ok) {
          body = [
            h(Row, { key: 'st', label: '状态' }, h('span', { className: 'caw-bad' }, d.error || '探测失败')),
            d.stderr ? h('div', { key: 'e', className: 'caw-err caw-code' }, String(d.stderr).slice(0, 300)) : null,
          ];
        } else {
          body = [
            h(Row, { key: 'f', label: '扫描文件' }, `${d.filesScanned ?? '—'}${d.ms ? ` · ${d.ms}ms` : ''}`),
            h(
              Row,
              { key: 'ab', label: '语义分析' },
              d.analysisBacked === true
                ? h('span', { className: 'caw-ok' }, 'analysis_backed')
                : h('span', { className: 'caw-muted' }, '仅启发式 / 未就绪'),
            ),
            h(Row, { key: 'p', label: '主语言' }, (d.primaryLanguages || []).join(', ') || '—'),
            h(Row, { key: 'h', label: '仅启发式' }, (d.heuristicLanguages || []).join(', ') || '—'),
            h(
              Row,
              { key: 'b', label: '构建上下文' },
              h(
                'span',
                {
                  className: d.buildConfidence === 'derived_from_build_artifacts' ? 'caw-ok' : 'caw-muted',
                  title: d.buildNote || '',
                },
                d.buildConfidence || 'unknown',
              ),
            ),
            h(Row, { key: 'c', label: '索引缓存' }, d.cacheHitSource || '—'),
            h(
              'div',
              { key: 'src', className: 'caw-muted', style: { marginTop: '6px' } },
              `cwd = ${d.target || target || '（默认：引擎工作目录）'}${d.checkedAt ? ` · ${fmtAgo(d.checkedAt)}` : ''}`,
            ),
          ];
        }
      }
      return h(Card, { title: '项目体检（真实 MCP 调用）', extra: h(SourceBadge, { key: 's', kind: 'live' }) }, body);
    }

    function CtxAuditPanel() {
      const [nonce, setNonce] = useState(0);
      const [engineNonce, setEngineNonce] = useState(0);
      const [logFile, setLogFile] = useState(null);
      const [logLines, setLogLines] = useState('200');
      const [logNonce, setLogNonce] = useState(0);

      const [target, setTarget] = useState('');
      // Every target-scoped read carries the selection, so the panel follows the
      // chosen project instead of whichever directory the engine was started in.
      const targetQuery = target ? `?target=${encodeURIComponent(target)}` : '';
      const targets = useResource(`${API}/targets`, [nonce]);
      const project = useResource(`${API}/project${targetQuery}`, [nonce, target]);
      const status = useResource(`${API}/status${targetQuery}`, [nonce, target]);
      const engine = useResource(`${API}/engine${engineNonce ? '?refresh=1' : ''}`, [engineNonce]);
      const roadmap = useResource(`${API}/roadmap`, [nonce]);
      const presets = useResource(`${API}/presets`, [nonce]);
      const logs = useResource(
        `${API}/logs?lines=${encodeURIComponent(logLines)}${logFile ? `&file=${encodeURIComponent(logFile)}` : ''}${target ? `&target=${encodeURIComponent(target)}` : ''}`,
        [logFile, logLines, logNonce, nonce, target],
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
      }, [s, e, project]);

      const stats = useMemo(() => {
        const counts = (s && s.counts) || null;
        return [
          { label: 'MCP 工具', value: e && e.ok ? e.toolCount : '—' },
          { label: '证据产物', value: counts ? counts.files + counts.dirs : '—' },
          { label: '证据体积', value: counts ? fmtBytes(counts.bytes) : '—' },
          { label: '日志文件', value: s && s.logs ? s.logs.files.length : '—' },
          { label: '目标文件', value: project.phase === 'ready' && project.data.ok ? project.data.filesScanned : '—' },
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
          h(Pill, { key: 'tgt' }, `目标 ${target ? target.split(/[\\/]/).filter(Boolean).pop() : '默认'}`),
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
            h(CardBoundary, { key: 'engine', label: 'MCP 引擎' },
              h(EngineCard, { engine, onReprobe: () => setEngineNonce((n) => n + 1) })),
            h(CardBoundary, { key: 'status', label: 'MCP 配置' }, h(StatusCard, { status })),
            h(CardBoundary, { key: 'logs', label: '日志' },
              h(LogsCard, { logs, file: logFile, lines: logLines, onFile: setLogFile, onLines: setLogLines, onReload: () => setLogNonce((n) => n + 1) })),
            h(CardBoundary, { key: 'artifacts', label: '证据产物' }, h(ArtifactsCard, { status })),
            h(CardBoundary, { key: 'roadmap', label: '路线图' }, h(RoadmapCard, { roadmap })),
            h(CardBoundary, { key: 'presets', label: 'Agent 预设' }, h(PresetsCard, { presets })),
            h(CardBoundary, { key: 'targets', label: '审计目标' }, h(TargetPicker, { targets, target, onSelect: setTarget })),
            h(CardBoundary, { key: 'project', label: '项目体检' }, h(ProjectCard, { project, target })),
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

        // One keyed entry per ctx-audit MCP tool: `tool.call.toolview` dispatches
        // by exact wire tool name, so each name needs its own registration. An
        // unknown key simply never renders, and a failed registration must not
        // take the host's own tool card down with it.
        for (const tool of MCP_TOOL_NAMES) {
          const key = `mcp__ctxaudit__${tool}`;
          ctx.slots.inject('tool.call.toolview', () => {
            try {
              return ctx.slots.register({ name: 'tool.call.toolview', key }, CtxAuditToolRow);
            } catch (error) {
              console.warn(`[ctx-audit-web] toolview registration failed for ${key}`, error);
              return () => {};
            }
          });
        }
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
