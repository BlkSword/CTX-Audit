// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 意图推断器
//!
//! 分析函数/方法的目的，识别安全敏感操作

use crate::semantic::context_analyzer::SemanticContext;
use serde::{Deserialize, Serialize};

/// 代码意图类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CodeIntent {
    /// 用户认证
    Authentication,

    /// 权限检查
    Authorization,

    /// 数据验证
    DataValidation,

    /// 数据库操作
    DatabaseOperation,

    /// 文件操作
    FileOperation,

    /// 外部调用
    ExternalCall,

    /// 业务逻辑
    BusinessLogic,
}

impl std::fmt::Display for CodeIntent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodeIntent::Authentication => write!(f, "用户认证"),
            CodeIntent::Authorization => write!(f, "权限检查"),
            CodeIntent::DataValidation => write!(f, "数据验证"),
            CodeIntent::DatabaseOperation => write!(f, "数据库操作"),
            CodeIntent::FileOperation => write!(f, "文件操作"),
            CodeIntent::ExternalCall => write!(f, "外部调用"),
            CodeIntent::BusinessLogic => write!(f, "业务逻辑"),
        }
    }
}

/// 数据语义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSemantic {
    /// 变量名
    pub variable_name: String,

    /// 数据类型
    pub data_type: String,

    /// 来源
    pub source: String,

    /// 是否被污染
    pub is_tainted: bool,

    /// 已知的净化方法
    pub sanitization: Vec<String>,
}

/// 安全风险等级
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityRisk {
    /// 无风险
    None,

    /// 低风险
    Low,

    /// 中等风险
    Medium,

    /// 高风险
    High,

    /// 严重风险
    Critical,
}

/// 意图推断结果
#[derive(Debug, Clone)]
pub struct IntentInferenceResult {
    /// 推断的意图
    pub intent: CodeIntent,

    /// 置信度 (0.0 - 1.0)
    pub confidence: f32,

    /// 推理依据
    pub reasoning: String,

    /// 发现的安全指标
    pub indicators: Vec<String>,
}

/// 意图推断器
pub struct IntentInferencer {
    /// 意图模式库
    intent_patterns: Vec<IntentPattern>,
}

/// 意图模式
#[derive(Debug, Clone)]
struct IntentPattern {
    /// 意图类型
    intent: CodeIntent,

    /// 函数名模式
    name_patterns: Vec<String>,

    /// 关键词
    keywords: Vec<String>,

    /// 危险操作
    dangerous_operations: Vec<String>,
}

impl IntentInferencer {
    /// 创建新的意图推断器
    pub fn new() -> Self {
        let intent_patterns = vec![
            // 认证意图
            IntentPattern {
                intent: CodeIntent::Authentication,
                name_patterns: vec![
                    "login".into(),
                    "authenticate".into(),
                    "signin".into(),
                    "auth".into(),
                ],
                keywords: vec!["password".into(), "credential".into(), "token".into()],
                dangerous_operations: vec![
                    "password_check".into(),
                    "hash_compare".into(),
                ],
            },
            // 授权意图
            IntentPattern {
                intent: CodeIntent::Authorization,
                name_patterns: vec![
                    "check_permission".into(),
                    "has_access".into(),
                    "can_access".into(),
                    "is_owner".into(),
                    "require_role".into(),
                ],
                keywords: vec![
                    "permission".into(),
                    "role".into(),
                    "access".into(),
                    "authorize".into(),
                ],
                dangerous_operations: vec![
                    "admin_check".into(),
                    "role_check".into(),
                ],
            },
            // 数据验证意图
            IntentPattern {
                intent: CodeIntent::DataValidation,
                name_patterns: vec![
                    "validate".into(),
                    "sanitize".into(),
                    "clean".into(),
                    "escape".into(),
                    "filter".into(),
                ],
                keywords: vec![
                    "valid".into(),
                    "sanitize".into(),
                    "escape".into(),
                    "allow".into(),
                ],
                dangerous_operations: vec![],
            },
            // 数据库操作意图
            IntentPattern {
                intent: CodeIntent::DatabaseOperation,
                name_patterns: vec![
                    "execute".into(),
                    "query".into(),
                    "select".into(),
                    "insert".into(),
                    "update".into(),
                    "delete".into(),
                ],
                keywords: vec![
                    "SELECT".into(),
                    "INSERT".into(),
                    "UPDATE".into(),
                    "DELETE".into(),
                    "query".into(),
                ],
                dangerous_operations: vec![
                    "raw_sql".into(),
                    "string_concat".into(),
                    "format_query".into(),
                ],
            },
            // 文件操作意图
            IntentPattern {
                intent: CodeIntent::FileOperation,
                name_patterns: vec![
                    "read_file".into(),
                    "write_file".into(),
                    "open".into(),
                    "save".into(),
                    "delete_file".into(),
                ],
                keywords: vec![
                    "open".into(),
                    "read".into(),
                    "write".into(),
                    "file".into(),
                    "path".into(),
                ],
                dangerous_operations: vec![
                    "path_traversal".into(),
                    "arbitrary_file".into(),
                ],
            },
            // 外部调用意图
            IntentPattern {
                intent: CodeIntent::ExternalCall,
                name_patterns: vec![
                    "fetch".into(),
                    "request".into(),
                    "call_api".into(),
                    "http_request".into(),
                ],
                keywords: vec![
                    "http".into(),
                    "https".into(),
                    "url".into(),
                    "api".into(),
                ],
                dangerous_operations: vec![
                    "ssrf".into(),
                    "redirect".into(),
                ],
            },
            // 业务逻辑意图（默认）
            IntentPattern {
                intent: CodeIntent::BusinessLogic,
                name_patterns: vec![
                    "process".into(),
                    "handle".into(),
                    "calculate".into(),
                    "compute".into(),
                ],
                keywords: vec![
                    "business".into(),
                    "logic".into(),
                    "calculate".into(),
                ],
                dangerous_operations: vec![
                    "race_condition".into(),
                    "logic_flaw".into(),
                ],
            },
        ];

        Self { intent_patterns }
    }

    /// 推断代码意图
    pub fn infer_intent(
        &self,
        code: &str,
        context: &SemanticContext,
    ) -> IntentInferenceResult {
        let mut scores: Vec<(CodeIntent, f32)> = Vec::new();

        for pattern in &self.intent_patterns {
            let mut score = 0.0;

            // 检查函数名匹配
            let code_lower = code.to_lowercase();
            for name_pattern in &pattern.name_patterns {
                if code_lower.contains(name_pattern) {
                    score += 0.4;
                }
            }

            // 检查关键词匹配
            for keyword in &pattern.keywords {
                if code_lower.contains(keyword) {
                    score += 0.3;
                }
            }

            // 检查危险操作
            for operation in &pattern.dangerous_operations {
                if code_lower.contains(operation) {
                    score += 0.3;
                }
            }

            scores.push((pattern.intent.clone(), score));
        }

        // 选择得分最高的意图
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

        let (intent, confidence) = scores
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .unwrap_or((CodeIntent::BusinessLogic, 0.5));

        let reasoning = self.generate_reasoning(&intent, code, confidence);

        let indicators = self.extract_indicators(code, &intent);

        IntentInferenceResult {
            intent,
            confidence: confidence.min(1.0),
            reasoning,
            indicators,
        }
    }

    /// 生成推理依据
    fn generate_reasoning(&self, intent: &CodeIntent, code: &str, confidence: f32) -> String {
        let mut reasoning = format!(
            "推断代码意图为: {} (置信度: {:.2})\n",
            intent, confidence
        );

        // 分析代码特征
        if code.contains("request.") || code.contains("Request") {
            reasoning.push_str("- 检测到 Web 请求处理\n");
        }
        if code.contains("SELECT") || code.contains("INSERT") {
            reasoning.push_str("- 检测到 SQL 操作\n");
        }
        if code.contains("open(") || code.contains("File(") {
            reasoning.push_str("- 检测到文件操作\n");
        }

        reasoning
    }

    /// 提取安全指标
    fn extract_indicators(&self, code: &str, intent: &CodeIntent) -> Vec<String> {
        let mut indicators = Vec::new();

        // 通用安全指标
        if code.contains("request.") && code.contains(".execute(") {
            indicators.push("潜在 SQL 注入: Web 请求直接拼接到 SQL 执行".to_string());
        }
        if code.contains("innerHTML") || code.contains("document.write") {
            indicators.push("潜在 XSS: 动态 HTML 内容生成".to_string());
        }
        if code.contains("os.system") || code.contains("subprocess.call") {
            indicators.push("潜在命令注入: 系统命令执行".to_string());
        }

        // 意图特定指标
        match intent {
            CodeIntent::Authentication => {
                if code.contains("==") && code.contains("password") {
                    indicators.push("不安全密码比较: 使用 == 而非恒定时间比较".to_string());
                }
            }
            CodeIntent::Authorization => {
                if code.contains("return True") && !code.contains("check") {
                    indicators.push("缺少实际权限检查".to_string());
                }
            }
            _ => {}
        }

        indicators
    }

    /// 获取支持的意图类型
    pub fn get_supported_intents(&self) -> Vec<CodeIntent> {
        self.intent_patterns
            .iter()
            .map(|p| p.intent.clone())
            .collect()
    }
}

impl Default for IntentInferencer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_inference_auth() {
        let inferencer = IntentInferencer::new();

        let code = r#"
        def login(request):
            username = request.form.get('username')
            password = request.form.get('password')
            if authenticate(username, password):
                return True
        "#;

        let context = SemanticContext::default();
        let result = inferencer.infer_intent(code, &context);

        assert_eq!(result.intent, CodeIntent::Authentication);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_intent_inference_database() {
        let inferencer = IntentInferencer::new();

        let code = "db.execute(\"SELECT * FROM users WHERE id = \" + user_id)";
        let context = SemanticContext::default();
        let result = inferencer.infer_intent(code, &context);

        assert_eq!(result.intent, CodeIntent::DatabaseOperation);
    }
}
