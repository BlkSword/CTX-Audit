// 组件树探针：用 React 桩递归调用 web 插件里整棵组件树，抓出"渲染期才会暴露"的错误。
//
// 为什么需要它：真实浏览器里的错误要靠人看 console，而插槽的 error boundary 在**面板之上**——
// 面板内部任何一处抛错都会让整页变成空白、没有定位信息。本探针在 CI/本地即可复现：
//   - 只调面板本体不够：子组件（日志卡、项目卡…）里"变量不在作用域"这类错误抓不到；
//   - 桩还要校验**元素类型**：`h('某个中文字符串')` 在真实 React 里会抛
//     InvalidCharacterError（tag name 非法），桩若照单全收就会漏掉。
//
// 用法：
//   node harness/scripts/probe-ctx-audit-web.mjs [--client <client.js 路径>]
// 退出码：0 = 全部组件执行无异常；1 = 有组件抛错（逐条打印）。
// 无第三方依赖：React 以最小桩替代。

import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = args.indexOf('--client');
const clientPath = resolve(flag >= 0 && args[flag + 1] ? args[flag + 1] : join(here, '..', 'plugins', 'ctx-audit-web', 'client.js'));

if (!existsSync(clientPath)) {
  console.error(`client not found: ${clientPath}`);
  process.exit(2);
}

let registration = null;
globalThis.window = { __ModuleLoader__: { load(reg) { registration = reg; } } };
globalThis.fetch = () => Promise.reject(new Error('fetch unavailable in this harness'));

await import(pathToFileURL(clientPath).href);
if (!registration || typeof registration.factory !== 'function') {
  console.error('module did not call window.__ModuleLoader__.load with a factory');
  process.exit(2);
}

const React = {
  createElement(type, props, ...children) {
    // 与真实 React 对齐：字符串类型必须是合法标签名。
    if (typeof type !== 'function' && !/^[a-z][a-z0-9-]*$/.test(String(type))) {
      throw new Error(`invalid element type: ${JSON.stringify(type)}`);
    }
    return { type, props: props || {}, children };
  },
  useState(initial) {
    return [typeof initial === 'function' ? initial() : initial, () => {}];
  },
  useEffect() {},
  useMemo(fn) {
    return fn();
  },
  useCallback(fn) {
    return fn;
  },
  Component: class {
    constructor(props) {
      this.props = props || {};
      this.state = {};
    }
    setState() {}
  },
};

const registrations = [];
const fakeCtx = {
  remote: undefined,
  slots: {
    inject(slot, callback) {
      const disposer = callback();
      return typeof disposer === 'function' ? disposer : () => {};
    },
    register(options, Component) {
      registrations.push({ options, Component });
      return () => {};
    },
  },
};

const sandbox = registration.factory((spec) => {
  if (spec === 'react') return React;
  throw new Error(`unexpected require(${spec})`);
});
if (typeof sandbox.apply !== 'function') {
  console.error('the browser half does not export apply()');
  process.exit(2);
}
sandbox.apply(fakeCtx);

const problems = [];
const visited = new Set();

function walk(node, depth, trail) {
  if (node === null || node === undefined || depth > 8) return;
  if (Array.isArray(node)) {
    for (const item of node) walk(item, depth, trail);
    return;
  }
  if (typeof node !== 'object') return;
  if (Array.isArray(node.children)) walk(node.children, depth, trail);
  if (typeof node.type !== 'function') return;
  const name = node.type.name || 'anonymous';
  const key = `${name}:${depth}`;
  if (visited.has(key)) return;
  visited.add(key);
  try {
    const out =
      node.type.prototype instanceof React.Component ? new node.type(node.props || {}).render() : node.type(node.props || {});
    walk(out, depth + 1, `${trail}/${name}`);
  } catch (error) {
    problems.push(`${trail}/${name} threw: ${(error && error.message) || error}`);
  }
}

// 单靠"空 props"只能覆盖 loading 分支；再补一轮已就绪数据，覆盖数据驱动分支。
const now = new Date().toISOString();
const readyProps = {
  status: {
    phase: 'ready',
    data: {
      workspace: 'D:/example',
      generatedAt: now,
      artifacts: [{ name: 'a.jsonl', size: 10, mtime: now }],
      counts: { files: 1, dirs: 1, bytes: 10 },
      logs: { files: [{ name: 'daemon.log', size: 10, mtime: now }] },
      mcp: { command: 'ctx-audit', args: ['mcp'], serverName: 'ctxaudit', present: true },
    },
  },
  engine: { phase: 'ready', data: { ok: true, toolCount: 1, tools: [{ name: 't', description: 'd' }], version: '0.0.0', protocolVersion: 'x' } },
  targets: {
    phase: 'ready',
    data: {
      root: 'D:/example',
      workspace: 'D:/example/target',
      allowedRoots: ['D:/example'],
      targets: [{ name: 'target', path: 'D:/example/target', hasAudit: true, isProject: true, files: 3, bytes: 100, logs: 1, newest: now }],
    },
  },
  project: {
    phase: 'ready',
    data: {
      ok: true,
      filesScanned: 10,
      analysisBacked: true,
      primaryLanguages: ['rust'],
      heuristicLanguages: ['json'],
      buildConfidence: 'unknown',
      cacheHitSource: 'miss',
      ms: 12,
      target: 'D:/example/target',
    },
  },
  roadmap: { phase: 'ready', data: { source: 'plan.json', ageDays: 1, derived: [{ area: 'a', title: 't', status: 'active', note: 'n' }], items: [{ title: 'p', status: 'done' }] } },
  presets: { phase: 'ready', data: { available: true, presets: [{ id: 'ctx-audit', name: 'CTX-Audit Auditor', isDefault: true, broken: null }] } },
  logs: { phase: 'ready', data: { files: ['daemon.log'], file: 'daemon.log', lines: ['l1', 'l2'], truncated: false } },
};

let slots = 0;
for (const { options, Component } of registrations) {
  if (options.name === 'main') {
    slots += 1;
    walk(React.createElement(Component, {}), 0, 'panel');
    walk(React.createElement(Component, readyProps), 0, 'panelReady');
  }
  if (options.name === 'tool.call.toolview') {
    slots += 1;
    walk(
      React.createElement(Component, {
        phase: 'result',
        toolName: 'mcp__ctxaudit__slice_backward',
        block: { call: { name: 'mcp__ctxaudit__slice_backward' }, content: [{ type: 'text', text: 'ok' }], isError: false },
      }),
      0,
      'toolview',
    );
  }
}

console.log(`client: ${clientPath}`);
console.log(`slots exercised: ${slots} · components visited: ${visited.size}`);
if (problems.length) {
  console.log(`PROBLEMS (${problems.length}):`);
  for (const problem of problems) console.log(`  ${problem}`);
  process.exit(1);
}
console.log('no component threw');
