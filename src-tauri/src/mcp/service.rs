use crate::mcp::McpState;
use std::sync::Arc;
use std::time::Duration;
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
                    _ => {}
                }
            }
        });
    }
    Ok(())
}

pub async fn call_tool(
    state: &McpState,
    tool_name: String,
    arguments: String,
) -> Result<String, String> {
    println!("Calling MCP Tool: {} with args: {}", tool_name, arguments);

    let id: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);

    let (tx, rx) = oneshot::channel::<Result<String, String>>();

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
        return Err(e);
    }

    match timeout(Duration::from_secs(120), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("MCP 响应通道已关闭".to_string()),
        Err(_) => {
            let mut pending = state.pending.lock().unwrap();
            pending.remove(&id);
            Err("MCP 调用超时".to_string())
        }
    }
}
