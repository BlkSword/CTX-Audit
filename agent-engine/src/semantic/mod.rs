// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 代码语义理解引擎
//!
//! 从"模式匹配"升级为"语义推理"，理解代码意图而非机械匹配模式

mod context_analyzer;
mod intent_inferencer;

pub use context_analyzer::{
    ContextAwareAnalyzer, FrameworkSemantic, SecurityBoundary, SemanticContext,
};
pub use intent_inferencer::{
    CodeIntent, DataSemantic, IntentInferenceResult, IntentInferencer, SecurityRisk,
};

/// 代码语义理解结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SemanticUnderstanding {
    /// 代码意图
    pub intent: CodeIntent,

    /// 数据语义
    pub data_semantics: Vec<DataSemantic>,

    /// 安全边界
    pub security_boundaries: Vec<SecurityBoundary>,

    /// 风险评估
    pub risk_assessment: SecurityRisk,

    /// 置信度
    pub confidence: f32,

    /// 推理依据
    pub reasoning: String,
}

/// 语义理解引擎
pub struct SemanticUnderstandingEngine {
    /// 意图推断器
    intent_inferencer: IntentInferencer,

    /// 上下文感知分析器
    context_analyzer: ContextAwareAnalyzer,
}

impl SemanticUnderstandingEngine {
    /// 创建新的语义理解引擎
    pub fn new() -> Self {
        Self {
            intent_inferencer: IntentInferencer::new(),
            context_analyzer: ContextAwareAnalyzer::new(),
        }
    }

    /// 理解代码语义（不依赖模式匹配）
    pub async fn understand_code(
        &self,
        code: &str,
        context: &SemanticContext,
    ) -> SemanticUnderstanding {
        // 1. 识别代码意图
        let intent_result = self.intent_inferencer.infer_intent(code, context);

        // 2. 理解数据语义
        let data_semantics = self.analyze_data_semantics(code, context);

        // 3. 识别安全边界
        let security_boundaries = self
            .context_analyzer
            .identify_security_boundaries(code, context);

        // 4. 构建语义模型
        let risk_assessment = self.assess_semantic_risk(&intent_result, &security_boundaries);

        SemanticUnderstanding {
            intent: intent_result.intent,
            data_semantics,
            security_boundaries,
            risk_assessment,
            confidence: intent_result.confidence,
            reasoning: intent_result.reasoning,
        }
    }

    /// 分析数据语义
    fn analyze_data_semantics(
        &self,
        code: &str,
        context: &SemanticContext,
    ) -> Vec<DataSemantic> {
        let mut semantics = Vec::new();

        // 识别用户输入数据
        if let Some(inputs) = self.identify_user_inputs(code) {
            semantics.extend(inputs);
        }

        // 识别敏感数据处理
        if let Some(sensitive) = self.identify_sensitive_data(code) {
            semantics.extend(sensitive);
        }

        // 识别外部系统交互
        if let Some(external) = self.identify_external_interactions(code) {
            semantics.extend(external);
        }

        semantics
    }

    /// 识别用户输入
    fn identify_user_inputs(&self, code: &str) -> Option<Vec<DataSemantic>> {
        let mut inputs = Vec::new();

        // 常见的用户输入模式
        let patterns = [
            ("request.body", "HTTP 请求体"),
            ("request.args", "URL 参数"),
            ("request.form", "表单数据"),
            ("request.cookies", "Cookie 数据"),
            ("request.headers", "HTTP 头"),
            ("input()", "标准输入"),
            ("raw_input()", "标准输入"),
            ("sys.argv", "命令行参数"),
            ("os.environ", "环境变量"),
        ];

        for (pattern, source) in &patterns {
            if code.contains(pattern) {
                inputs.push(DataSemantic {
                    variable_name: pattern.to_string(),
                    data_type: "UserInput".to_string(),
                    source: source.to_string(),
                    is_tainted: true,
                    sanitization: vec![],
                });
            }
        }

        if inputs.is_empty() {
            None
        } else {
            Some(inputs)
        }
    }

    /// 识别敏感数据
    fn identify_sensitive_data(&self, code: &str) -> Option<Vec<DataSemantic>> {
        let mut sensitive = Vec::new();

        let patterns = [
            ("password", "密码"),
            ("api_key", "API 密钥"),
            ("secret", "密钥"),
            ("token", "令牌"),
            ("credit_card", "信用卡"),
            ("ssn", "社会安全号"),
        ];

        for (pattern, description) in &patterns {
            if code.to_lowercase().contains(pattern) {
                sensitive.push(DataSemantic {
                    variable_name: pattern.to_string(),
                    data_type: "SensitiveData".to_string(),
                    source: description.to_string(),
                    is_tainted: false,
                    sanitization: vec![],
                });
            }
        }

        if sensitive.is_empty() {
            None
        } else {
            Some(sensitive)
        }
    }

    /// 识别外部交互
    fn identify_external_interactions(&self, code: &str) -> Option<Vec<DataSemantic>> {
        let mut interactions = Vec::new();

        // 数据库操作
        if code.contains(".execute(") || code.contains(".query(") {
            interactions.push(DataSemantic {
                variable_name: "database_query".to_string(),
                data_type: "DatabaseOperation".to_string(),
                source: "SQL 查询".to_string(),
                is_tainted: true,
                sanitization: vec![],
            });
        }

        // HTTP 请求
        if code.contains("requests.") || code.contains("fetch(") || code.contains("http.get(") {
            interactions.push(DataSemantic {
                variable_name: "http_request".to_string(),
                data_type: "ExternalCall".to_string(),
                source: "HTTP 请求".to_string(),
                is_tainted: true,
                sanitization: vec![],
            });
        }

        // 文件操作
        if code.contains("open(") || code.contains("File(") || code.contains("Path(") {
            interactions.push(DataSemantic {
                variable_name: "file_operation".to_string(),
                data_type: "FileOperation".to_string(),
                source: "文件访问".to_string(),
                is_tainted: true,
                sanitization: vec![],
            });
        }

        if interactions.is_empty() {
            None
        } else {
            Some(interactions)
        }
    }

    /// 评估语义风险
    fn assess_semantic_risk(
        &self,
        intent_result: &IntentInferenceResult,
        boundaries: &[SecurityBoundary],
    ) -> SecurityRisk {
        let mut risk_level = 0.0;

        // 基于意图的风险评估
        match &intent_result.intent {
            CodeIntent::Authentication => risk_level += 0.3,
            CodeIntent::Authorization => risk_level += 0.2,
            CodeIntent::ExternalCall => risk_level += 0.4,
            CodeIntent::FileOperation => risk_level += 0.3,
            CodeIntent::DatabaseOperation => risk_level += 0.4,
            CodeIntent::DataValidation => risk_level -= 0.2,
            _ => {}
        }

        // 基于安全边界的风险评估
        for boundary in boundaries {
            match boundary {
                SecurityBoundary::None => risk_level += 0.5,
                SecurityBoundary::Implicit => risk_level += 0.3,
                SecurityBoundary::Explicit => risk_level -= 0.2,
            }
        }

        // 转换为风险等级
        if risk_level >= 0.8 {
            SecurityRisk::Critical
        } else if risk_level >= 0.6 {
            SecurityRisk::High
        } else if risk_level >= 0.4 {
            SecurityRisk::Medium
        } else if risk_level >= 0.2 {
            SecurityRisk::Low
        } else {
            SecurityRisk::None
        }
    }
}

impl Default for SemanticUnderstandingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_engine_creation() {
        let engine = SemanticUnderstandingEngine::new();
        assert_eq!(engine.intent_inferencer.get_supported_intents().len(), 7);
    }

    #[test]
    fn test_identify_user_inputs() {
        let engine = SemanticUnderstandingEngine::new();

        let code = r#"
        def login(request):
            username = request.args.get('username')
            password = request.form.get('password')
        "#;

        let inputs = engine.identify_user_inputs(code);
        assert!(inputs.is_some());

        let inputs = inputs.unwrap();
        assert_eq!(inputs.len(), 2);
    }
}
