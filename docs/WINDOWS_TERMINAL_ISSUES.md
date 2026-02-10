# Windows 终端兼容性说明

## 已知问题

在 Windows 的某些终端（如 CMD、PowerShell）中运行 TUI 时，可能会遇到输入字符重复显示的问题（输入 'a' 显示 'aa'）。

## 原因

这是 Windows 控制台子系统的限制。Windows 终端会在应用程序处理输入之前自动回显字符，这与应用程序的渲染输出叠加在一起，造成视觉上的重复。

## 解决方案

### 推荐终端

1. **Windows Terminal** (最新版本)
   - 从 Microsoft Store 或 GitHub 安装
   - 提供最佳的终端体验
   - 支持完整的 ANSI 转义序列

2. **Git Bash**
   - 随 Git for Windows 安装
   - 提供类 Unix 终端体验

3. **WSL (Windows Subsystem for Linux)**
   - 在 Linux 环境中运行最佳
   - 完全兼容 Unix 终端行为

### 配置 Windows Terminal

如果使用 Windows Terminal，确保以下设置：

```json
{
    "profiles": {
        "defaults": {
            "experimental.rendering.forceFullRepaint": true,
            "experimental.rendering.forceVTRepaint": true
        }
    }
}
```

### 临时解决方案

如果遇到重复输入问题：

1. **使用 WSL**: 在 WSL 环境中运行 CTX-Audit
2. **使用 SSH**: 从 Linux/Mac 通过 SSH 连接到 Windows 运行
3. **使用替代终端**: 如 ConEmu、Terminus

## 技术细节

CTX-Audit 使用 `crossterm` 库处理终端输入，该库尝试通过设置 Windows 控制台模式来禁用回显：

```rust
const ENABLE_ECHO_INPUT: u32 = 0x0004;
const ENABLE_LINE_INPUT: u32 = 0x0002;

// 禁用回显和行输入
let raw_mode = mode & !ENABLE_ECHO_INPUT & !ENABLE_LINE_INPUT;
```

但由于 Windows 控制台的工作方式，这些设置在某些终端中无法完全阻止回显。

## 启用调试

如果需要诊断问题，可以启用详细的调试日志：

```powershell
# PowerShell
$env:RUST_LOG="ctx_audit=trace,cli=trace"
ctx-audit

# CMD
set RUST_LOG=ctx_audit=trace,cli=trace
ctx-audit
```

查看日志以了解：
- 是否事件被重复触发
- 控制台模式设置是否成功
- 输入处理流程
