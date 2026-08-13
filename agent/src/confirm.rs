// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 工具调用审批
//!
//! M1 从简：工具只分只读/写两类。
//! - Auto：全部放行；
//! - Gate：只读白名单短路放行，写工具一律 deny（非交互场景的安全默认）。
//! 交互式确认回调留待 M2+ 实现。

use serde::{Deserialize, Serialize};

/// 审批模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalMode {
    /// 全部自动放行
    Auto,
    /// 闸门模式：写工具需审批（M1 非交互实现为直接 deny）
    Gate,
}

/// 工具闸门
#[derive(Debug, Clone)]
pub struct ToolGate {
    mode: ApprovalMode,
}

impl ToolGate {
    /// 创建闸门
    pub fn new(mode: ApprovalMode) -> Self {
        Self { mode }
    }

    /// 当前审批模式（子 agent 派生用）
    pub fn mode(&self) -> ApprovalMode {
        self.mode
    }

    /// 检查工具调用是否被允许；Err 为 deny 原因（回喂模型）
    pub fn check(&self, tool_name: &str) -> Result<(), String> {
        match self.mode {
            ApprovalMode::Auto => Ok(()),
            ApprovalMode::Gate => {
                if is_write_tool(tool_name) {
                    Err(format!(
                        "工具 {} 为写操作，当前为 Gate 非交互模式，已拒绝执行；请改用只读工具收集证据并在最终结论中说明",
                        tool_name
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// 判断工具是否为写操作
///
/// 显式写工具集 + 命名启发式（write/delete/update/create/patch/edit/remove/report）。
/// 当前内置工具中仅 report_finding 属于写类。
pub fn is_write_tool(name: &str) -> bool {
    const WRITE_TOOLS: &[&str] = &["report_finding"];
    if WRITE_TOOLS.contains(&name) {
        return true;
    }
    const WRITE_HINTS: &[&str] = &[
        "write", "delete", "update", "create", "patch", "edit", "remove", "report",
    ];
    WRITE_HINTS.iter().any(|hint| name.contains(hint))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Auto 模式全部放行
    #[test]
    fn test_auto_mode_allows_all() {
        let gate = ToolGate::new(ApprovalMode::Auto);
        assert!(gate.check("read_file").is_ok());
        assert!(gate.check("report_finding").is_ok());
    }

    /// Gate 模式：只读放行、写工具 deny
    #[test]
    fn test_gate_mode_denies_write_tools() {
        let gate = ToolGate::new(ApprovalMode::Gate);
        assert!(gate.check("read_file").is_ok());
        assert!(gate.check("text_search").is_ok());
        assert!(gate.check("trace_taint").is_ok());

        let denied = gate.check("report_finding");
        assert!(denied.is_err());
        assert!(denied.unwrap_err().contains("report_finding"));
    }

    /// 写工具分类启发式
    #[test]
    fn test_write_tool_classification() {
        assert!(is_write_tool("report_finding"));
        assert!(is_write_tool("write_file"));
        assert!(is_write_tool("delete_session"));
        assert!(!is_write_tool("read_file"));
        assert!(!is_write_tool("list_files"));
        assert!(!is_write_tool("query_callers"));
    }
}
