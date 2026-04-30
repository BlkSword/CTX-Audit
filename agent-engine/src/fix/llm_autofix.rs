// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! LLM 驱动的 AutoFix 生成器
//!
//! 利用漏洞上下文（污点路径、代码片段、验证结果）让 LLM 生成精准修复。

use ctx_audit_llm::{LLMClient, LLMMessage};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::repair_generator::RepairSuggestion;

/// LLM AutoFix 生成结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoFixResult {
    /// 漏洞 ID
    pub vuln_id: String,
    /// 生成的修复建议列表（按置信度排序）
    pub suggestions: Vec<RepairSuggestion>,
    /// LLM 的分析说明
    pub analysis: String,
    /// 是否成功生成
    pub success: bool,
}

/// LLM AutoFix 生成器
pub struct LlmAutoFixGenerator {
    llm: Arc<dyn LLMClient>,
    max_tokens: u32,
}

impl LlmAutoFixGenerator {
    pub fn new(llm: Arc<dyn LLMClient>) -> Self {
        Self {
            llm,
            max_tokens: 4096,
        }
    }

    /// 为已确认的漏洞生成修复建议
    pub async fn generate_fix(
        &self,
        vuln_id: &str,
        vuln_type: &str,
        file_path: &str,
        line: usize,
        code_snippet: &str,
        taint_path: Option<&[TaintStepSummary]>,
        language: &str,
    ) -> AutoFixResult {
        let prompt = self.build_prompt(vuln_type, file_path, line, code_snippet, taint_path, language);

        let messages = vec![
            LLMMessage::system(AUTOFIX_SYSTEM_PROMPT.to_string()),
            LLMMessage::user(prompt),
        ];

        match self.llm.generate(messages, self.max_tokens, 0.3).await {
            Ok(response) => {
                let text = response.get_text();
                self.parse_fix_response(vuln_id, &text)
            }
            Err(e) => {
                AutoFixResult {
                    vuln_id: vuln_id.to_string(),
                    suggestions: Vec::new(),
                    analysis: format!("AutoFix 生成失败: {}", e),
                    success: false,
                }
            }
        }
    }

    fn build_prompt(
        &self,
        vuln_type: &str,
        file_path: &str,
        line: usize,
        code_snippet: &str,
        taint_path: Option<&[TaintStepSummary]>,
        language: &str,
    ) -> String {
        let mut prompt = format!(
            "## 漏洞信息\n\
             - 类型: {}\n\
             - 文件: {}:{}\n\
             - 语言: {}\n\n\
             ## 漏洞代码\n\
             ```{}\n{}\n```\n",
            vuln_type, file_path, line, language, language, code_snippet
        );

        if let Some(path) = taint_path {
            prompt.push_str("\n## 污点传播路径\n");
            for step in path {
                prompt.push_str(&format!(
                    "- 行 {}: `{}` ({})\n",
                    step.line, step.symbol, step.step_type
                ));
            }
        }

        prompt.push_str("\n## 任务\n");
        prompt.push_str(AUTOFIX_TASK_INSTRUCTION);

        prompt
    }

    fn parse_fix_response(&self, vuln_id: &str, text: &str) -> AutoFixResult {
        let mut suggestions = Vec::new();
        let mut analysis = String::new();

        // 提取 JSON 块
        if let Some(json_str) = extract_json_block(text) {
            if let Ok(parsed) = serde_json::from_str::<AutoFixOutput>(&json_str) {
                analysis = parsed.analysis.clone();
                for fix in parsed.fixes {
                    suggestions.push(
                        RepairSuggestion::new(&fix.vuln_type, &fix.original_code, &fix.fixed_code)
                            .with_explanation(&fix.explanation)
                            .with_confidence(fix.confidence)
                    );
                }
            }
        }

        // 如果 JSON 解析失败，尝试从 markdown 提取
        let success = !suggestions.is_empty();
        if !success {
            analysis = text.chars().take(500).collect();
        }

        AutoFixResult {
            vuln_id: vuln_id.to_string(),
            suggestions,
            analysis,
            success,
        }
    }
}

/// 污点步骤摘要（轻量级）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintStepSummary {
    pub line: usize,
    pub symbol: String,
    pub step_type: String,
}

/// LLM AutoFix 输出格式
#[derive(Debug, Deserialize)]
struct AutoFixOutput {
    analysis: String,
    fixes: Vec<AutoFixEntry>,
}

#[derive(Debug, Deserialize)]
struct AutoFixEntry {
    vuln_type: String,
    original_code: String,
    fixed_code: String,
    explanation: String,
    confidence: f32,
}

fn extract_json_block(text: &str) -> Option<String> {
    // 尝试提取 ```json ... ``` 块
    if let Some(start) = text.find("```json") {
        let json_start = start + 7;
        if let Some(end) = text[json_start..].find("```") {
            return Some(text[json_start..json_start + end].trim().to_string());
        }
    }
    // 尝试提取 { ... } 块
    if let Some(start) = text.find('{') {
        if let Some(end) = text.rfind('}') {
            return Some(text[start..=end].to_string());
        }
    }
    None
}

const AUTOFIX_SYSTEM_PROMPT: &str = r#"You are a security code fix expert. You analyze vulnerability findings and generate precise, minimal code fixes.

Rules:
1. Generate the MINIMAL change needed to fix the vulnerability
2. Preserve existing functionality and code style
3. Use the appropriate security fix pattern (parameterized queries, output encoding, input validation, etc.)
4. Output JSON format"#;

const AUTOFIX_TASK_INSTRUCTION: &str = r#"
Based on the vulnerability information and taint flow above, generate a fix.

Output JSON:
```json
{
  "analysis": "Brief explanation of why this is vulnerable",
  "fixes": [
    {
      "vuln_type": "SQL injection",
      "original_code": "the vulnerable code",
      "fixed_code": "the fixed code",
      "explanation": "why this fix works",
      "confidence": 0.9
    }
  ]
}
```"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_block_with_markers() {
        let text = "Some text\n```json\n{\"key\": \"value\"}\n```\nMore text";
        let result = extract_json_block(text);
        assert_eq!(result, Some("{\"key\": \"value\"}".to_string()));
    }

    #[test]
    fn test_extract_json_block_raw() {
        let text = "Some text\n{\"key\": \"value\"}\nMore text";
        let result = extract_json_block(text);
        assert_eq!(result, Some("{\"key\": \"value\"}".to_string()));
    }
}
