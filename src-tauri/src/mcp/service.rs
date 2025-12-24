use crate::mcp::{get_tool_timeout, McpState, RequestInfo};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};
use tauri_plugin_shell::process::CommandEvent;
use tauri_plugin_shell::ShellExt;
use tokio::sync::oneshot;
use tokio::time::timeout;

pub fn extract_mcp_text(value: &serde_json::Value) -> String {
    if let Some(result) = value.get("result") {
        if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
            let mut out = String::new();
            for item in content {
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    out.push_str(text);
                }
            }
            return out;
        }
        if let Some(text) = result.as_str() {
            return text.to_string();
        }
        return result.to_string();
    }

    value.to_string()
}

pub async fn handle_python_stdout(app: &AppHandle, state: &McpState, chunk: String) {
    let mut buffer = state.stdout_buffer.lock().unwrap();
    buffer.push_str(&chunk);

    loop {
        let Some(pos) = buffer.find('\n') else {
            break;
        };
        let line = buffer.drain(..=pos).collect::<String>();
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parsed: serde_json::Result<serde_json::Value> = serde_json::from_str(line);
        match parsed {
            Ok(json) => {
                if json.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0") {
                    let id = json.get("id").and_then(|v| v.as_u64());
                    if let Some(id) = id {
                        let sender = {
                            let mut pending = state.pending.lock().unwrap();
                            pending.remove(&id)
                        };

                        // 从活跃请求中移除
                        {
                            let mut active = state.active_requests.lock().unwrap();
                            active.remove(&id);
                        }

                        if let Some(sender) = sender {
                            if let Some(err) = json.get("error") {
                                let msg = err
                                    .get("message")
                                    .and_then(|m| m.as_str())
                                    .unwrap_or("MCP 调用失败");
                                let _ = sender.send(Err(msg.to_string()));
                            } else {
                                let text = extract_mcp_text(&json);
                                let _ = sender.send(Ok(text));
                            }
                            // 更新活动时间
                            state.update_activity();
                            continue;
                        }
                    }
                }

                let _ = app.emit("mcp-message", line.to_string());
            }
            Err(_) => {
                let _ = app.emit("mcp-message", line.to_string());
            }
        }
    }
}

pub async fn start_mcp_server(app: &AppHandle, state: Arc<McpState>) -> Result<(), String> {
    let mut child_guard = state.child.lock().unwrap();
    if child_guard.is_none() {
        let script_path = "../python-sidecar/agent.py";

        let (mut rx, child) = app
            .shell()
            .command("python")
            .args(&[script_path])
            .env("PYTHONUTF8", "1")
            .env("PYTHONIOENCODING", "utf-8")
            .env("MCP_PORT", crate::mcp::MCP_PORT.to_string())
            .spawn()
            .map_err(|e| e.to_string())?;

        *child_guard = Some(child);

        // Send Initialize sequence
        if let Some(c) = child_guard.as_mut() {
            let init_msg = "{\"jsonrpc\": \"2.0\", \"method\": \"initialize\", \"params\": {\"protocolVersion\": \"2024-11-05\", \"capabilities\": {}, \"clientInfo\": {\"name\": \"DeepAuditClient\", \"version\": \"1.0.0\"}}, \"id\": 0}\n";
            let _ = c.write(init_msg.as_bytes());

            let initialized_msg = "{\"jsonrpc\": \"2.0\", \"method\": \"notifications/initialized\", \"params\": {}}\n";
            let _ = c.write(initialized_msg.as_bytes());
        }

        // Spawn listener
        let app_handle = app.clone();
        let state_clone = state.clone();

        tauri::async_runtime::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    CommandEvent::Stdout(line) => {
                        let text = String::from_utf8_lossy(&line).to_string();
                        handle_python_stdout(&app_handle, &state_clone, text).await;
                    }
                    CommandEvent::Stderr(line) => {
                        let text = String::from_utf8_lossy(&line);
                        let _ = app_handle.emit("mcp-message", text.to_string());
                    }
                    CommandEvent::Terminated(_) => {
                        // Python进程终止，尝试重启
                        let _ = app_handle.emit("mcp-terminated", "Python进程已终止");
                        break;
                    }
                    _ => {}
                }
            }
        });
    }
    Ok(())
}

/// 健康检查任务
pub fn start_health_check(_app: AppHandle, state: Arc<McpState>) {
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;

            // 检查Python进程是否还在运行
            let child_exists = {
                let child = state.child.lock().unwrap();
                child.is_some()
            };

            if !child_exists {
                continue;
            }

            // 清理超时的请求
            let timeout_ids = state.check_timeout(300); // 5分钟超时
            if !timeout_ids.is_empty() {
                let mut pending = state.pending.lock().unwrap();
                for id in timeout_ids {
                    if let Some(tx) = pending.remove(&id) {
                        let _ = tx.send(Err("请求超时".to_string()));
                    }
                }
            }
        }
    });
}

pub async fn call_tool(
    state: &McpState,
    tool_name: String,
    arguments: String,
) -> Result<String, String> {
    println!("Calling MCP Tool: {} with args: {}", tool_name, arguments);

    // 获取该工具的超时时间
    let timeout_secs = get_tool_timeout(&tool_name);

    // 使用信号量限制并发
    let _permit = state
        .request_semaphore
        .acquire()
        .await
        .map_err(|_| "请求队列已满，请稍后重试".to_string())?;

    let id: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);

    let (tx, rx) = oneshot::channel::<Result<String, String>>();

    // 记录活跃请求
    {
        let mut active = state.active_requests.lock().unwrap();
        active.insert(
            id,
            RequestInfo {
                id,
                tool_name: tool_name.clone(),
                started_at: Instant::now(),
            },
        );
    }

    {
        let mut pending = state.pending.lock().unwrap();
        pending.insert(id, tx);
    }

    let write_result = {
        let mut child_guard = state.child.lock().unwrap();
        if let Some(child) = child_guard.as_mut() {
            let msg = format!(
                "{{\"jsonrpc\": \"2.0\", \"method\": \"tools/call\", \"params\": {{\"name\": \"{}\", \"arguments\": {}}}, \"id\": {}}}\n",
                tool_name, arguments, id
            );

            child.write(msg.as_bytes()).map_err(|e| e.to_string())
        } else {
            Err("MCP 服务器未运行".to_string())
        }
    };

    if let Err(e) = write_result {
        let mut pending = state.pending.lock().unwrap();
        pending.remove(&id);
        let mut active = state.active_requests.lock().unwrap();
        active.remove(&id);
        return Err(e);
    }

    // 使用工具特定的超时时间
    match timeout(Duration::from_secs(timeout_secs), rx).await {
        Ok(Ok(result)) => {
            state.update_activity();
            result
        }
        Ok(Err(_)) => {
            let mut active = state.active_requests.lock().unwrap();
            active.remove(&id);
            Err("MCP 响应通道已关闭".to_string())
        }
        Err(_) => {
            let mut pending = state.pending.lock().unwrap();
            pending.remove(&id);
            let mut active = state.active_requests.lock().unwrap();
            active.remove(&id);
            Err(format!("MCP 调用超时 ({}秒)", timeout_secs))
        }
    }
}
