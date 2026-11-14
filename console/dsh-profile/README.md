# DSH profile: `ctx-audit`

This directory is the **template** for a dedicated DSH profile that serves the
CTX-Audit Console inside the DSH web surface, on its own port. It is kept in the
CTX-Audit repository so the integration is reproducible; the live profile lives
under `$DSH_HOME/profiles/ctx-audit`.

## What it does

- Boots the standard DSH web composition (`dsh-base` + `dsh-web-app`).
- Mounts `dsh-ctx-audit-console`, which serves:
  - the console SPA at `/console`
  - the console API at `/api/console/*`
- Registers the console as a DSH main panel plus a sidebar entry (client half,
  discovered automatically from the package `dsh.client` declaration).
- Does **not** touch the default `web` profile; the port is a boot flag.

## Create the profile

```powershell
dsh --profile ctx-audit --from-default-profile web
```

Then copy `package.json` and `cordis.patch.yml` from this directory over the
generated ones, and install the plugin:

```powershell
dsh plugin --profile ctx-audit install
```

## Run it

```powershell
dsh --profile ctx-audit --port 4321 --no-open
```

Verify:

| URL | Expected |
|---|---|
| `http://127.0.0.1:4321/console/` | the console SPA (200) |
| `http://127.0.0.1:4321/api/console/health` | `{"ok":true,"version":"ctx-audit …"}` |
| `http://127.0.0.1:4321/api/console/actions` | 11 actions |
| `http://127.0.0.1:4321/` | DSH shell (401 without the boot token) |

The DSH shell's boot manifest contains `dsh-ctx-audit-console/client.js`, so the
console panel loads in the browser without any extra roster row.

## Why a separate profile

- The default `web` profile is the user's working session; restarting it would
  interrupt it.
- A dedicated profile keeps the audit surface, its plugin set and its port
  independent, and can be started or stopped on demand.

## Precautions

- Both profiles share `$DSH_HOME` (sessions, auth, logs); only the plugin roster
  and patch layer differ.
- The console is loopback-only and read-only over the audited repository.
