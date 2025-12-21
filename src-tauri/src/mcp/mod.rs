use std::collections::HashMap;
use std::sync::Mutex;
use tauri_plugin_shell::process::CommandChild;
use tokio::sync::oneshot;

pub mod service;

pub const MCP_PORT: u16 = 8338;

pub struct McpState {
    pub child: Mutex<Option<CommandChild>>,
    pub pending: Mutex<HashMap<u64, oneshot::Sender<Result<String, String>>>>,
    pub stdout_buffer: Mutex<String>,
}

impl McpState {
    pub fn new() -> Self {
        Self {
            child: Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
            stdout_buffer: Mutex::new(String::new()),
        }
    }
}
