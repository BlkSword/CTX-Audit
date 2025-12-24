use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;
use tauri_plugin_shell::process::CommandChild;
use tokio::sync::oneshot;
use tokio::sync::Semaphore;

pub mod service;

pub const MCP_PORT: u16 = 8338;

// 最大并发请求数
pub const MAX_CONCURRENT_REQUESTS: usize = 3;

// 工具特定的超时配置（秒）
pub fn get_tool_timeout(tool_name: &str) -> u64 {
    match tool_name {
        // 快速工具 - 10秒
        "read_file" | "list_files" | "get_loaded_rules" | "search_symbol" => 10,
        // 中等工具 - 30秒
        "get_code_structure" | "find_call_sites" | "get_class_hierarchy" | "search_files" => 30,
        // 慢速工具 - 60秒
        "get_knowledge_graph" | "get_call_graph" | "get_analysis_report" => 60,
        // 超慢速工具 - 180秒
        "build_ast_index" | "run_security_scan" | "verify_finding" => 180,
        // 默认 - 60秒
        _ => 60,
    }
}

// 请求状态跟踪
#[derive(Debug, Clone)]
pub struct RequestInfo {
    pub id: u64,
    pub tool_name: String,
    pub started_at: Instant,
}

pub struct McpState {
    pub child: Mutex<Option<CommandChild>>,
    pub pending: Mutex<HashMap<u64, oneshot::Sender<Result<String, String>>>>,
    pub stdout_buffer: Mutex<String>,
    // 并发控制信号量
    pub request_semaphore: Semaphore,
    // 活跃请求追踪
    pub active_requests: Mutex<HashMap<u64, RequestInfo>>,
    // 最后一次活动时间
    pub last_activity: Mutex<Instant>,
}

impl McpState {
    pub fn new() -> Self {
        Self {
            child: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            stdout_buffer: Mutex::new(String::new()),
            request_semaphore: Semaphore::new(MAX_CONCURRENT_REQUESTS),
            active_requests: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(Instant::now()),
        }
    }

    /// 检查是否有请求超时
    pub fn check_timeout(&self, timeout_secs: u64) -> Vec<u64> {
        let mut active = self.active_requests.lock().unwrap();
        let now = Instant::now();
        let timeout_ids: Vec<u64> = active
            .iter()
            .filter(|(_, info)| now.duration_since(info.started_at).as_secs() > timeout_secs)
            .map(|(id, _)| *id)
            .collect();

        // 移除超时的请求
        for id in &timeout_ids {
            active.remove(id);
        }

        timeout_ids
    }

    /// 更新最后活动时间
    pub fn update_activity(&self) {
        let mut last = self.last_activity.lock().unwrap();
        *last = Instant::now();
    }

    /// 获取空闲时间（秒）
    pub fn idle_time_secs(&self) -> u64 {
        let last = self.last_activity.lock().unwrap();
        last.elapsed().as_secs()
    }
}
