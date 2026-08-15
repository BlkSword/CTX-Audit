// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 会话存储（选型 B1：append-only JSONL）
//!
//! 每个会话一个 `<项目>/.ctx-audit/sessions/<id>.jsonl` 文件，每行一条记录。
//! 事件即写盘，崩溃只丢最后一条；启动时重放恢复消息历史；
//! 中断的 tool call 以 `interrupted` 标记，重放时连同对应 assistant tool_call 一并跳过。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::provider::{ChatMessage, ToolCall};

/// 会话记录（每行一条）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionRecord {
    /// 会话元信息（首行）
    Meta {
        /// 初始 prompt
        prompt: String,
        /// 模型名
        model: String,
        /// 创建时间
        created_at: DateTime<Utc>,
    },

    /// 用户消息（含注入的提示）
    User {
        /// 文本内容
        content: String,
    },

    /// assistant 消息
    Assistant {
        /// 文本内容（纯 tool_call 消息可为空）
        content: Option<String>,
        /// 工具调用
        #[serde(default)]
        tool_calls: Vec<ToolCall>,
    },

    /// 工具执行结果
    Tool {
        /// 调用 ID
        tool_call_id: String,
        /// 工具名
        name: String,
        /// 输出文本
        output: String,
        /// 是否错误
        is_error: bool,
        /// 是否中断（崩溃/中止导致未执行完，重放时跳过）
        #[serde(default)]
        interrupted: bool,
    },
}

/// 带时间戳的 JSONL 行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionLine {
    /// 写入时间
    pub ts: DateTime<Utc>,
    /// 记录体
    #[serde(flatten)]
    pub record: SessionRecord,
}

/// 会话
pub struct Session {
    id: String,
    path: PathBuf,
}

impl Session {
    /// 会话存储目录
    pub fn sessions_dir(project_dir: &Path) -> PathBuf {
        project_dir.join(".ctx-audit").join("sessions")
    }

    /// 创建新会话（生成目录与空文件）
    pub fn create(project_dir: &Path) -> std::io::Result<Self> {
        let dir = Self::sessions_dir(project_dir);
        std::fs::create_dir_all(&dir)?;
        let id = uuid::Uuid::new_v4().to_string();
        let path = dir.join(format!("{}.jsonl", id));
        std::fs::File::create(&path)?;
        Ok(Self { id, path })
    }

    /// 创建带前缀的会话（M4 子 agent：文件名 `<prefix>-<uuid8>.jsonl`，
    /// 带父轮次/父会话标识便于审计隔离与追溯）
    pub fn create_with_prefix(project_dir: &Path, prefix: &str) -> std::io::Result<Self> {
        let dir = Self::sessions_dir(project_dir);
        std::fs::create_dir_all(&dir)?;
        let short = &uuid::Uuid::new_v4().to_string()[..8];
        let id = format!("{}-{}", prefix, short);
        let path = dir.join(format!("{}.jsonl", id));
        std::fs::File::create(&path)?;
        Ok(Self { id, path })
    }

    /// 打开已有会话文件（重放恢复用）
    pub fn open(path: PathBuf) -> Self {
        let id = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Self { id, path }
    }

    /// 会话 ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 会话文件路径
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 追加一条记录（事件即写盘）
    pub fn append(&self, record: &SessionRecord) -> std::io::Result<()> {
        let line = SessionLine {
            ts: Utc::now(),
            record: record.clone(),
        };
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)?;
        let mut json = serde_json::to_string(&line)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        json.push('\n');
        file.write_all(json.as_bytes())?;
        file.sync_data()?;
        Ok(())
    }

    /// 重放全部记录（坏行跳过并告警，保证崩溃残留不阻塞恢复）
    pub fn replay(&self) -> std::io::Result<Vec<SessionLine>> {
        let content = std::fs::read_to_string(&self.path)?;
        let mut lines = Vec::new();
        for (idx, raw) in content.lines().enumerate() {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            match serde_json::from_str::<SessionLine>(raw) {
                Ok(line) => lines.push(line),
                Err(e) => {
                    tracing::warn!("会话 {} 第 {} 行解析失败（已跳过）: {}", self.id, idx + 1, e)
                }
            }
        }
        Ok(lines)
    }

    /// 从会话记录重建 LLM 消息历史
    ///
    /// 中断的 tool call（interrupted=true）连同 assistant 消息里对应的
    /// tool_call 一并剔除，保证 history 满足 API 的 tool_call/tool 配对约束。
    pub fn build_messages(&self) -> std::io::Result<Vec<ChatMessage>> {
        let lines = self.replay()?;

        // 收集中断的 tool_call_id
        let interrupted: std::collections::HashSet<&str> = lines
            .iter()
            .filter_map(|l| match &l.record {
                SessionRecord::Tool {
                    tool_call_id,
                    interrupted: true,
                    ..
                } => Some(tool_call_id.as_str()),
                _ => None,
            })
            .collect();

        let mut messages = Vec::new();
        for line in &lines {
            match &line.record {
                SessionRecord::Meta { .. } => {}
                SessionRecord::User { content } => messages.push(ChatMessage::user(content)),
                SessionRecord::Assistant {
                    content,
                    tool_calls,
                } => {
                    let kept: Vec<ToolCall> = tool_calls
                        .iter()
                        .filter(|c| !interrupted.contains(c.id.as_str()))
                        .cloned()
                        .collect();
                    // 全部 tool_call 都被剔除且无文本时跳过该消息
                    if content.is_none() && kept.is_empty() && !tool_calls.is_empty() {
                        continue;
                    }
                    messages.push(ChatMessage::assistant(content.clone(), kept));
                }
                SessionRecord::Tool {
                    tool_call_id,
                    output,
                    interrupted,
                    ..
                } => {
                    if *interrupted {
                        continue;
                    }
                    messages.push(ChatMessage::tool(tool_call_id, output));
                }
            }
        }
        Ok(messages)
    }
}

/// 会话摘要（`agent sessions` 列表用）
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// 会话 ID
    pub id: String,
    /// 文件路径
    pub path: PathBuf,
    /// 创建时间（Meta 缺失时为 None）
    pub created_at: Option<DateTime<Utc>>,
    /// 初始 prompt（Meta 缺失时为 None）
    pub prompt: Option<String>,
    /// 模型名
    pub model: Option<String>,
    /// 记录条数
    pub records: usize,
}

/// 列出项目下的全部会话
pub fn list_sessions(project_dir: &Path) -> std::io::Result<Vec<SessionInfo>> {
    let dir = Session::sessions_dir(project_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut infos = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("jsonl") {
            continue;
        }
        let session = Session::open(path);
        let lines = session.replay().unwrap_or_default();
        let (mut created_at, mut prompt, mut model) = (None, None, None);
        for line in &lines {
            if let SessionRecord::Meta {
                prompt: p,
                model: m,
                created_at: c,
            } = &line.record
            {
                created_at = Some(*c);
                prompt = Some(p.clone());
                model = Some(m.clone());
                break;
            }
        }
        infos.push(SessionInfo {
            id: session.id().to_string(),
            path: session.path().to_path_buf(),
            created_at,
            prompt,
            model,
            records: lines.len(),
        });
    }
    // 最新在前
    infos.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(infos)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试临时目录（避免引入 tempfile 依赖）
    fn temp_project(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ctx-audit-agent-test-{}-{}",
            tag,
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_records() -> Vec<SessionRecord> {
        vec![
            SessionRecord::Meta {
                prompt: "审计 src/".into(),
                model: "test-model".into(),
                created_at: Utc::now(),
            },
            SessionRecord::User {
                content: "审计 src/".into(),
            },
            SessionRecord::Assistant {
                content: None,
                tool_calls: vec![
                    ToolCall {
                        id: "call_ok".into(),
                        name: "read_file".into(),
                        arguments: "{}".into(),
                    },
                    ToolCall {
                        id: "call_dead".into(),
                        name: "list_files".into(),
                        arguments: "{}".into(),
                    },
                ],
            },
            SessionRecord::Tool {
                tool_call_id: "call_ok".into(),
                name: "read_file".into(),
                output: "文件内容".into(),
                is_error: false,
                interrupted: false,
            },
            SessionRecord::Tool {
                tool_call_id: "call_dead".into(),
                name: "list_files".into(),
                output: String::new(),
                is_error: false,
                interrupted: true,
            },
            SessionRecord::Assistant {
                content: Some("结论".into()),
                tool_calls: vec![],
            },
        ]
    }

    /// JSONL 写入 + 重放恢复
    #[test]
    fn test_session_write_and_replay() {
        let project = temp_project("replay");
        let session = Session::create(&project).unwrap();
        for record in &sample_records() {
            session.append(record).unwrap();
        }

        let lines = session.replay().unwrap();
        assert_eq!(lines.len(), 6);
        assert!(matches!(lines[0].record, SessionRecord::Meta { .. }));
        assert!(matches!(lines[5].record, SessionRecord::Assistant { .. }));

        std::fs::remove_dir_all(&project).ok();
    }

    /// 重放构建消息历史：interrupted tool call 被跳过，
    /// 且 assistant 消息中对应的 tool_call 一并剔除
    #[test]
    fn test_build_messages_skips_interrupted() {
        let project = temp_project("interrupted");
        let session = Session::create(&project).unwrap();
        for record in &sample_records() {
            session.append(record).unwrap();
        }

        let messages = session.build_messages().unwrap();
        // user + assistant(剔除 call_dead) + tool(call_ok) + assistant(结论)
        assert_eq!(messages.len(), 4);
        assert_eq!(messages[0].role, "user");
        assert_eq!(messages[1].role, "assistant");
        // call_dead 被剔除，只剩 call_ok
        let kept = messages[1].tool_calls.as_ref().unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, "call_ok");
        assert_eq!(messages[2].role, "tool");
        assert_eq!(messages[2].tool_call_id.as_deref(), Some("call_ok"));
        assert_eq!(messages[3].role, "assistant");
        assert_eq!(messages[3].content.as_deref(), Some("结论"));

        std::fs::remove_dir_all(&project).ok();
    }

    /// 坏行不阻塞重放（模拟崩溃写入一半）
    #[test]
    fn test_replay_tolerates_corrupt_tail() {
        let project = temp_project("corrupt");
        let session = Session::create(&project).unwrap();
        session
            .append(&SessionRecord::User {
                content: "hi".into(),
            })
            .unwrap();
        // 模拟崩溃残留的半行
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(session.path())
            .unwrap();
        file.write_all(b"{\"ts\":\"2026-08-08T00:00:00Z\",\"type\":\"user\",\"cont")
            .unwrap();

        let lines = session.replay().unwrap();
        assert_eq!(lines.len(), 1);

        std::fs::remove_dir_all(&project).ok();
    }

    /// 会话列表
    #[test]
    fn test_list_sessions() {
        let project = temp_project("list");
        let session = Session::create(&project).unwrap();
        session
            .append(&SessionRecord::Meta {
                prompt: "p".into(),
                model: "m".into(),
                created_at: Utc::now(),
            })
            .unwrap();
        session
            .append(&SessionRecord::User {
                content: "p".into(),
            })
            .unwrap();

        let infos = list_sessions(&project).unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].records, 2);
        assert_eq!(infos[0].prompt.as_deref(), Some("p"));

        std::fs::remove_dir_all(&project).ok();
    }
}
