# CTX-Audit Console 一键启动脚本
#
#   .\scripts\start-console.ps1                # 构建（如需要）+ 启动独立 Console
#   .\scripts\start-console.ps1 -Port 4319     # 指定端口
#   .\scripts\start-console.ps1 -Build         # 强制重新构建前端
#   .\scripts\start-console.ps1 -Check         # 只做类型检查与测试，不启动
#
# 独立 Console 与 DSH 内嵌（/console）共用同一 API 实现与 workspace 注册表。

[CmdletBinding()]
param(
    [int]$Port = 4317,
    [string]$HostAddress = '127.0.0.1',
    [switch]$Build,
    [switch]$Check,
    [string]$AuditBin
)

$ErrorActionPreference = 'Stop'
$ConsoleRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $ConsoleRoot 'package.json'))) {
    $ConsoleRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'console'
}
$ConsoleDir = if (Test-Path (Join-Path $ConsoleRoot 'console\package.json')) {
    Join-Path $ConsoleRoot 'console'
} else {
    $ConsoleRoot
}

Write-Host "[ctx-console] workspace: $ConsoleDir"

if (-not (Test-Path (Join-Path $ConsoleDir 'node_modules'))) {
    Write-Host '[ctx-console] installing dependencies…'
    Push-Location $ConsoleDir
    try { npm install --no-audit --no-fund } finally { Pop-Location }
}

if ($Build -or -not (Test-Path (Join-Path $ConsoleDir 'dist\index.html'))) {
    Write-Host '[ctx-console] building SPA…'
    Push-Location $ConsoleDir
    try { npx vite build } finally { Pop-Location }
}

Push-Location $ConsoleDir
try {
    Write-Host '[ctx-console] typecheck…'
    npx tsc --noEmit
    if ($LASTEXITCODE -ne 0) { throw 'typecheck failed' }

    Write-Host '[ctx-console] tests…'
    node --test tests/*.test.mjs
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
} finally {
    Pop-Location
}

if ($Check) {
    Write-Host '[ctx-console] check-only mode: not starting the server'
    exit 0
}

if ($AuditBin) { $env:CTX_AUDIT_BIN = $AuditBin }
$env:CTX_CONSOLE_PORT = "$Port"
$env:CTX_CONSOLE_HOST = $HostAddress

Write-Host "[ctx-console] starting on http://${HostAddress}:${Port}"
Push-Location $ConsoleDir
try { node server/index.mjs } finally { Pop-Location }
