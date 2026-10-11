/**
 * Browser half of the CTX-Audit web surface.
 *
 * A page in this Harness is not a URL route: it is a keyed entry in the layout's
 * `main` slot, selected by the sidebar entry that shares its panel id. So this
 * plugin registers two slots with one shared id:
 *
 *   - `main` (keyed)              the centre panel itself;
 *   - `sidebar.panellist` (list)  the navigation entry that selects it
 *                                 (`ctx.layout.selectPanel(id)` switches panels).
 *
 * Data comes from the host half's read-only endpoint (`/ctx-audit/api/status`)
 * rather than from the session: a `main` key other than the reserved
 * `conversation` gets no Session binding, and the page must render before any
 * agent exists.
 *
 * Contract notes, from the installed plugin-development skill:
 *   - the loader id equals the package name;
 *   - React comes from the browser module table, so `require('react')` is the
 *     only import a plain-JS client half needs — no duplicate React install,
 *     CDN script, or UMD search;
 *   - a Harness Client package must NOT be imported as a module (it may change
 *     without notice and has no type check for plain JS); `dsh.client.inject`
 *     entries only order activation;
 *   - registrations go through `ctx.slots.inject`, because the owning slot may
 *     not be declared yet when this plugin loads;
 *   - no DOM writes outside the component and no append to `document.body`;
 *   - styles use host theme tokens with fallbacks, so a renamed token degrades
 *     the appearance instead of leaving the property unset.
 */
window.__ModuleLoader__.load({
  id: '@local/ctx-audit-web',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useCallback, useEffect, useState } = React;

    /** Shared by the sidebar entry and the centre panel it selects. */
    const PANEL_ID = 'ctx-audit';

    /** Owned by the host half of this same bundle. */
    const STATUS_URL = '/ctx-audit/api/status';

    const style = {
      page: {
        padding: '18px 22px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
        color: 'var(--dsw-alias-text-primary, inherit)',
        fontSize: 'var(--dsw-alias-font-size-body, 13px)',
      },
      header: { display: 'flex', alignItems: 'baseline', gap: '10px' },
      title: { margin: 0, fontSize: '16px', fontWeight: 600 },
      lead: { margin: 0, lineHeight: 1.7, opacity: 0.85 },
      cards: { display: 'flex', gap: '10px', flexWrap: 'wrap' },
      card: {
        flex: '1 1 260px',
        minWidth: 0,
        border: '1px solid var(--dsw-alias-border-secondary, rgba(128,128,128,0.35))',
        borderRadius: '8px',
        padding: '10px 12px',
      },
      cardTitle: { fontWeight: 600, marginBottom: '6px' },
      row: { marginTop: '2px', opacity: 0.9, overflowWrap: 'anywhere' },
      mono: {
        fontFamily: 'var(--dsw-alias-font-family-mono, monospace)',
        fontSize: '12px',
      },
      list: { margin: '4px 0 0', padding: 0, listStyle: 'none', maxHeight: '220px', overflowY: 'auto' },
      listRow: { display: 'flex', gap: '8px', padding: '2px 0', alignItems: 'baseline' },
      listName: { flex: 1, minWidth: 0, overflowWrap: 'anywhere' },
      muted: { opacity: 0.6, fontSize: '12px', whiteSpace: 'nowrap' },
      badgeOk: { color: 'var(--dsw-alias-state-success, #1a7f37)', fontWeight: 600 },
      badgeBad: { color: 'var(--dsw-alias-state-danger, #b42318)', fontWeight: 600 },
      button: {
        alignSelf: 'flex-start',
        border: '1px solid var(--dsw-alias-border-secondary, rgba(128,128,128,0.35))',
        background: 'transparent',
        color: 'inherit',
        borderRadius: '6px',
        padding: '3px 10px',
        fontSize: '12px',
        cursor: 'pointer',
      },
      error: { color: 'var(--dsw-alias-state-danger, #b42318)' },
    };

    function fmtBytes(n) {
      if (typeof n !== 'number') return '';
      if (n < 1024) return `${n} B`;
      if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
      return `${(n / 1024 / 1024).toFixed(1)} MB`;
    }

    function fmtTime(iso) {
      if (!iso) return '';
      const d = new Date(iso);
      return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
    }

    function useStatus() {
      const [refreshKey, setRefreshKey] = useState(0);
      const [state, setState] = useState({ phase: 'loading' });
      const refresh = useCallback(() => setRefreshKey((n) => n + 1), []);

      useEffect(() => {
        let alive = true;
        setState({ phase: 'loading' });
        fetch(STATUS_URL, { headers: { accept: 'application/json' } })
          .then((res) => (res.ok ? res.json() : Promise.reject(new Error(`HTTP ${res.status}`))))
          .then((data) => {
            if (alive) setState({ phase: 'ready', data });
          })
          .catch((error) => {
            if (alive) setState({ phase: 'error', message: String((error && error.message) || error) });
          });
        return () => {
          alive = false;
        };
      }, [refreshKey]);

      return { state, refresh };
    }

    function card(key, title, children) {
      return h('div', { key, style: style.card }, [
        h('div', { key: 'title', style: style.cardTitle }, title),
        ...children,
      ]);
    }

    function McpCard({ data }) {
      const mcp = data.mcp || {};
      const found = mcp.commandFound;
      const children = [
        h('div', { key: 'name', style: style.row }, 'serverName  ', h('code', { style: style.mono }, mcp.serverName || '?')),
        h('div', { key: 'transport', style: style.row }, '传输  ', h('code', { style: style.mono }, mcp.transport || '?')),
        h('div', { key: 'command', style: style.row }, '命令  ', h('code', { style: style.mono }, mcp.command || '?')),
        h(
          'div',
          { key: 'found', style: style.row },
          '二进制  ',
          found === true
            ? h('span', { style: style.badgeOk }, '已找到')
            : found === false
              ? h('span', { style: style.badgeBad }, '未找到（MCP 行会启动失败）')
              : h('span', { style: style.muted }, '裸命令名，经 PATH 解析'),
        ),
        h('div', { key: 'prefix', style: style.row }, '工具名前缀  ', h('code', { style: style.mono }, mcp.toolNamePrefix || '')),
      ];
      return card('mcp', 'MCP 服务器', children);
    }

    function WorkspaceCard({ data }) {
      return card('workspace', '工作区', [
        h('div', { key: 'ws', style: style.row }, h('code', { style: style.mono }, data.workspace || '?')),
        h('div', { key: 'dir', style: style.row }, '证据目录  ', h('code', { style: style.mono }, data.artifactsDir || '?')),
      ]);
    }

    function ArtifactsCard({ data }) {
      const items = data.artifacts;
      let body;
      if (items === null) {
        body = h('div', { style: style.muted }, '目录不存在（尚未产生报告/基线）');
      } else if (items.length === 0) {
        body = h('div', { style: style.muted }, '目录为空');
      } else {
        body = h(
          'ul',
          { style: style.list },
          items.map((it, i) =>
            h('li', { key: `${it.name}-${i}`, style: style.listRow }, [
              h('span', { key: 'n', style: style.listName }, it.name, it.kind === 'dir' ? '/' : ''),
              h('span', { key: 'm', style: style.muted }, [fmtBytes(it.bytes), fmtTime(it.mtime)].filter(Boolean).join('  ')),
            ]),
          ),
        );
      }
      return card('artifacts', `证据产物（最多 ${data.artifactLimit} 项）`, [body]);
    }

    function CtxAuditPage() {
      const { state, refresh } = useStatus();

      const header = h('div', { key: 'header', style: style.header }, [
        h('h2', { key: 'title', style: style.title }, 'CTX-Audit'),
        h(
          'button',
          { key: 'refresh', type: 'button', style: style.button, onClick: refresh, disabled: state.phase === 'loading' },
          state.phase === 'loading' ? '读取中…' : '刷新',
        ),
      ]);

      let content;
      if (state.phase === 'loading') {
        content = h('div', { key: 'loading', style: style.muted }, '正在读取 /ctx-audit/api/status …');
      } else if (state.phase === 'error') {
        content = h('div', { key: 'error', style: style.error }, `读取失败：${state.message}`);
      } else {
        const data = state.data || {};
        content = h('div', { key: 'cards', style: style.cards }, [
          McpCard({ data }),
          WorkspaceCard({ data }),
          ArtifactsCard({ data }),
        ]);
      }

      return h('div', { style: style.page, 'data-ctx-audit-page': 'true' }, [
        header,
        h(
          'p',
          { key: 'lead', style: style.lead },
          '代码安全审计引擎与证据层：确定性引擎输出代码上下文、污点链与置信度，判定由 LLM 完成。',
        ),
        content,
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
          ctx.slots.register({ name: 'main', key: PANEL_ID }, CtxAuditPage),
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
