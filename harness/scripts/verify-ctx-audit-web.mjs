#!/usr/bin/env node
/**
 * Validate the rows shipped by this bundle against the REAL runtime schemas of
 * the installed DSH packages.
 *
 * Why this exists: a preset's rows are not validated at boot. `dsh` starts fine
 * with a broken preset and only reports it when a session tries to mount it — a
 * config key the target plugin does not accept (for example the pre-declaration
 * `text:` field where the persona schema requires `prefix`) shows up as a
 * `broken` preset in the roster, not as a startup error. Booting is therefore
 * not a usable check; importing each target plugin's own `Config` schema and
 * calling it on the row's `config` is.
 *
 * Usage:
 *   node harness/scripts/verify-ctx-audit-web.mjs --dsh <path to @deepseek-ai/dsh>
 *   DSH_PACKAGE_DIR=<path> node harness/scripts/verify-ctx-audit-web.mjs
 *
 * Exit codes: 0 = every row that can be checked passed; 1 = at least one row
 * failed its schema; 2 = the DSH install could not be located.
 *
 * Rows whose `config` contains a `!!js` expression are reported as skipped: the
 * expression cannot be evaluated here, so validating it would produce a false
 * failure. Subpath rows (for example `.../list-agents`) and `cordis:group`
 * containers are handled structurally.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const HERE = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const BUNDLE_DIR = join(HERE, 'plugins', 'ctx-audit-web');

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

const dshDir = argValue('--dsh') ?? process.env.DSH_PACKAGE_DIR;
if (!dshDir || !existsSync(join(dshDir, 'package.json'))) {
  console.error('usage: node verify-ctx-audit-web.mjs --dsh <path to @deepseek-ai/dsh>');
  console.error('       (or set DSH_PACKAGE_DIR)');
  process.exit(2);
}
const dshModules = join(dshDir, 'node_modules');

/** `!!js` has no standing in plain YAML, so load it as an opaque marker. */
const yaml = await import(pathToFileURL(join(dshModules, 'js-yaml', 'index.js')).href).then(
  (m) => m.default ?? m,
);
const jsType = new yaml.Type('tag:yaml.org,2002:js', {
  kind: 'scalar',
  construct: (data) => ({ __js: String(data) }),
});
const schema = yaml.DEFAULT_SCHEMA.extend([jsType]);

function containsJs(value) {
  if (value === null || typeof value !== 'object') return false;
  if (Object.prototype.hasOwnProperty.call(value, '__js')) return true;
  return Object.values(value).some(containsJs);
}

/** Resolve a package specifier to its entry module inside the DSH install. */
async function loadPackageSchema(name) {
  const [scope, pkg, ...rest] = name.split('/');
  if (rest.length > 0) return { kind: 'subpath' };
  const dir = join(dshModules, scope, pkg);
  if (!existsSync(dir)) return { kind: 'missing' };
  const manifest = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  const entry = manifest.exports?.['.']?.default ?? manifest.exports?.['.]'] ?? manifest.main ?? 'lib/index.js';
  const file = join(dir, typeof entry === 'string' ? entry : 'lib/index.js');
  if (!existsSync(file)) return { kind: 'missing-entry' };
  const mod = await import(pathToFileURL(file).href);
  const schemaExport = mod.Config ?? mod.default?.Config;
  if (typeof schemaExport !== 'function') return { kind: 'no-schema' };
  return { kind: 'schema', schema: schemaExport };
}

const results = [];
async function checkRow(row, path) {
  if (typeof row?.name !== 'string' || row.name.length === 0) {
    results.push({ path, verdict: 'FAIL', detail: 'row has no `name`' });
    return;
  }
  if (row.name === 'cordis:group') {
    if (!Array.isArray(row.config)) {
      results.push({ path, verdict: 'FAIL', detail: 'cordis:group needs a nested row list in `config`' });
      return;
    }
    for (const [index, child] of row.config.entries()) {
      await checkRow(child, `${path}/${row.id ?? '?'}[${index}]`);
    }
    return;
  }
  // A preset declaration types `plugins` as an open list, so the declaration
  // itself validates shallowly; the load-bearing part is the nested rows. Check
  // the declaration against its own schema AND every nested row against the
  // schema of the package it names.
  if (row.name === '@deepseek-ai/dsh-agent-preset') {
    try {
      const loadedDecl = await loadPackageSchema(row.name);
      if (loadedDecl.kind === 'schema') {
        loadedDecl.schema(row.config ?? {});
        results.push({ path, verdict: 'ok', detail: 'preset declaration' });
      } else {
        results.push({ path, verdict: 'skip', detail: 'declaration schema unavailable' });
      }
    } catch (error) {
      results.push({ path, verdict: 'FAIL', detail: String((error && error.message) || error).split('\n')[0] });
    }
    for (const [index, child] of (row.config?.plugins ?? []).entries()) {
      await checkRow(child, `${path}/plugins[${index}]`);
    }
    return;
  }
  if (containsJs(row.config)) {
    results.push({ path, verdict: 'skip', detail: 'config contains a !!js expression' });
    return;
  }
  const loaded = await loadPackageSchema(row.name);
  if (loaded.kind === 'subpath') {
    results.push({ path, verdict: 'skip', detail: 'subpath export (no schema entry)' });
    return;
  }
  if (loaded.kind === 'missing' || loaded.kind === 'missing-entry') {
    results.push({ path, verdict: 'FAIL', detail: `package not found in the DSH install: ${row.name}` });
    return;
  }
  if (loaded.kind === 'no-schema') {
    results.push({ path, verdict: 'skip', detail: 'package exports no Config schema' });
    return;
  }
  try {
    loaded.schema(row.config ?? {});
    results.push({ path, verdict: 'ok', detail: '' });
  } catch (error) {
    results.push({ path, verdict: 'FAIL', detail: String((error && error.message) || error).split('\n')[0] });
  }
}

const manifest = JSON.parse(readFileSync(join(BUNDLE_DIR, 'package.json'), 'utf8'));
const patches = manifest.dsh?.bundle?.patch;
const patchFiles = Array.isArray(patches) ? patches : [patches];

for (const relative of patchFiles) {
  const file = join(BUNDLE_DIR, relative);
  if (!existsSync(file)) {
    results.push({ path: relative, verdict: 'FAIL', detail: 'patch file listed by the manifest is missing' });
    continue;
  }
  const document = yaml.load(readFileSync(file, 'utf8'), { schema });
  for (const operation of document ?? []) {
    const rows = operation?.insert ?? [];
    for (const row of rows) {
      await checkRow(row, `${relative}#${row.id ?? row.name}`);
    }
  }
}

const width = Math.max(...results.map((r) => r.path.length), 12);
for (const result of results) {
  const mark = result.verdict === 'ok' ? 'OK  ' : result.verdict === 'skip' ? 'SKIP' : 'FAIL';
  console.log(`${mark}  ${result.path.padEnd(width)}  ${result.detail}`);
}

const failed = results.filter((r) => r.verdict === 'FAIL');
console.log(
  `\n${results.length} rows checked: ${results.filter((r) => r.verdict === 'ok').length} ok, ` +
    `${results.filter((r) => r.verdict === 'skip').length} skipped, ${failed.length} failed`,
);
process.exit(failed.length > 0 ? 1 : 0);
