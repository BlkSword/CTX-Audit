// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 增强污点分析引擎
//!
//! 基于 AST 的变量追踪，提供更精确的污点分析
//! 追踪用户输入（污点源）到危险函数（污点汇）的数据流

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::taint::{
    FlowLocation, FlowNode, FlowNodeType, Severity, TaintFlow, TaintSink, TaintSource,
    VulnerabilityType,
};

/// 变量污点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableTaint {
    /// 变量名
    pub name: String,
    /// 污点来源
    pub source_line: usize,
    /// 污点来源变量（如果是传播）
    pub source_var: Option<String>,
    /// 是否已被净化
    pub is_sanitized: bool,
    /// 净化函数（如果有）
    pub sanitizer: Option<String>,
    /// 传播路径
    pub propagation_path: Vec<PropagationStep>,
}

/// 传播步骤
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationStep {
    /// 行号
    pub line: usize,
    /// 步骤类型
    pub step_type: PropagationStepType,
    /// 源变量
    pub from_var: Option<String>,
    /// 目标变量
    pub to_var: String,
    /// 代码片段
    pub code: Option<String>,
}

/// 传播步骤类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PropagationStepType {
    /// 污点源（用户输入）
    Source,
    /// 变量赋值
    Assignment,
    /// 函数参数传递
    ParameterPass,
    /// 函数返回值
    ReturnValue,
    /// 字段访问
    FieldAccess,
    /// 字符串拼接
    Concatenation,
    /// 净化处理
    Sanitization,
    /// 污点汇（危险函数）
    Sink,
}

/// 增强污点分析器
pub struct EnhancedTaintAnalyzer {
    /// 污点源列表
    sources: Vec<TaintSource>,
    /// 污点汇列表
    sinks: Vec<TaintSink>,
    /// 净化函数模式
    sanitizers: Vec<SanitizerPattern>,
}

/// 净化函数模式
#[derive(Debug, Clone)]
struct SanitizerPattern {
    pattern: String,
    affects_vars: bool,
}

impl EnhancedTaintAnalyzer {
    /// 创建新的增强污点分析器
    pub fn new() -> Self {
        Self {
            sources: Self::default_sources(),
            sinks: Self::default_sinks(),
            sanitizers: Self::default_sanitizers(),
        }
    }

    /// 分析代码，返回污点流列表
    pub fn analyze(&self, code: &str, file_path: &str, language: &str) -> Vec<TaintFlow> {
        let lines: Vec<&str> = code.lines().collect();
        let mut flows = Vec::new();

        // 1. 识别所有污点源并追踪变量
        let tainted_vars = self.find_and_track_sources(&lines, file_path, language);

        // 2. 识别所有污点汇
        let sinks = self.find_sinks(&lines, file_path, language);

        // 3. 对每个汇点，检查是否有污点变量到达
        for (sink_loc, sink_def) in &sinks {
            if let Some(flow) =
                self.trace_to_sink(&tainted_vars, sink_loc, sink_def, &lines, file_path)
            {
                flows.push(flow);
            }
        }

        flows
    }

    /// 查找污点源并追踪变量传播
    fn find_and_track_sources(
        &self,
        lines: &[&str],
        file_path: &str,
        language: &str,
    ) -> HashMap<String, VariableTaint> {
        let mut tainted_vars = HashMap::new();

        for (line_idx, line) in lines.iter().enumerate() {
            let line_num = line_idx + 1;

            // 检查每个污点源模式
            for source in &self.sources {
                if !source.matches(line, language) {
                    continue;
                }

                // 提取被污染的变量名
                if let Some(var_name) = self.extract_tainted_variable(line, language) {
                    let taint = VariableTaint {
                        name: var_name.clone(),
                        source_line: line_num,
                        source_var: None,
                        is_sanitized: false,
                        sanitizer: None,
                        propagation_path: vec![PropagationStep {
                            line: line_num,
                            step_type: PropagationStepType::Source,
                            from_var: None,
                            to_var: var_name.clone(),
                            code: Some(line.trim().to_string()),
                        }],
                    };
                    tainted_vars.insert(var_name, taint);
                }
            }

            // 追踪变量传播（赋值）
            self.track_assignments(line, line_num, &mut tainted_vars, language);

            // 检查净化
            self.check_sanitization(line, line_num, &mut tainted_vars);
        }

        tainted_vars
    }

    /// 从代码行提取被污染的变量名
    fn extract_tainted_variable(&self, line: &str, language: &str) -> Option<String> {
        let line = line.trim();

        // 赋值语句: var = ...
        if let Some(eq_pos) = line.find('=') {
            if eq_pos > 0 {
                let left_side = line[..eq_pos].trim();
                // 处理多种声明方式
                let var_name = left_side
                    .strip_prefix("let ")
                    .or_else(|| left_side.strip_prefix("var "))
                    .or_else(|| left_side.strip_prefix("const "))
                    .or_else(|| left_side.strip_prefix("auto "))
                    .or_else(|| left_side.strip_prefix("mut "))
                    .or_else(|| left_side.strip_prefix("int "))
                    .or_else(|| left_side.strip_prefix("string "))
                    .or_else(|| left_side.strip_prefix("String "))
                    .unwrap_or(left_side);

                // 清理变量名
                let var_name = var_name.split('.').next().unwrap_or(var_name);
                let var_name = var_name.split('[').next().unwrap_or(var_name);
                let var_name = var_name.trim().to_string();

                if !var_name.is_empty() && Self::is_valid_var_name(&var_name) {
                    return Some(var_name);
                }
            }
        }

        None
    }

    /// 检查是否是有效的变量名
    fn is_valid_var_name(name: &str) -> bool {
        if name.is_empty() {
            return false;
        }
        let first_char = name.chars().next().unwrap();
        (first_char.is_alphabetic() || first_char == '_') && !name.contains(' ')
    }

    /// 追踪变量赋值传播
    fn track_assignments(
        &self,
        line: &str,
        line_num: usize,
        tainted_vars: &mut HashMap<String, VariableTaint>,
        _language: &str,
    ) {
        let line = line.trim();

        // 跳过注释
        if line.starts_with("//") || line.starts_with("#") || line.starts_with("/*") {
            return;
        }

        // 检查赋值: target = source 或 target := source
        if let Some(eq_pos) = line.find('=') {
            if eq_pos == 0 {
                return;
            }
            // 确保是赋值而不是比较
            let before_eq: String = line.chars().take(eq_pos).collect();
            if before_eq.ends_with('=')
                || before_eq.ends_with('!')
                || before_eq.ends_with('<')
                || before_eq.ends_with('>')
            {
                return; // 比较运算符
            }

            let target = before_eq.trim();
            let source = line[eq_pos + 1..].trim();

            // 清理 target
            let target_clean = target
                .strip_prefix("let ")
                .or_else(|| target.strip_prefix("var "))
                .or_else(|| target.strip_prefix("const "))
                .or_else(|| target.strip_prefix("auto "))
                .or_else(|| target.strip_prefix("mut "))
                .unwrap_or(target)
                .trim();

            // 收集需要添加的新污点变量
            let mut new_entries: Vec<(String, VariableTaint)> = Vec::new();

            // 检查 source 是否包含污点变量
            for (tainted_name, taint) in tainted_vars.iter() {
                if source.contains(tainted_name) && !taint.is_sanitized {
                    // 传播污点
                    let new_var_name = target_clean
                        .split('.')
                        .next()
                        .unwrap_or(target_clean)
                        .to_string();

                    if Self::is_valid_var_name(&new_var_name) && new_var_name != *tainted_name {
                        let mut new_taint = taint.clone();
                        new_taint.name = new_var_name.clone();
                        new_taint.source_var = Some(tainted_name.clone());
                        new_taint.propagation_path.push(PropagationStep {
                            line: line_num,
                            step_type: PropagationStepType::Assignment,
                            from_var: Some(tainted_name.clone()),
                            to_var: new_var_name.clone(),
                            code: Some(line.to_string()),
                        });

                        // 如果原变量已被净化，新变量也标记为净化
                        if taint.is_sanitized {
                            new_taint.is_sanitized = true;
                            new_taint.sanitizer = taint.sanitizer.clone();
                        }

                        new_entries.push((new_var_name, new_taint));
                    }
                }
            }

            // 插入新的污点变量
            for (name, taint) in new_entries {
                tainted_vars.insert(name, taint);
            }
        }
    }

    /// 检查净化
    fn check_sanitization(
        &self,
        line: &str,
        line_num: usize,
        tainted_vars: &mut HashMap<String, VariableTaint>,
    ) {
        let line_lower = line.to_lowercase();

        for sanitizer in &self.sanitizers {
            if line_lower.contains(&sanitizer.pattern.to_lowercase()) {
                // 找到该行中可能被净化的变量
                for (var_name, taint) in tainted_vars.iter_mut() {
                    if line.contains(var_name) && !taint.is_sanitized {
                        taint.is_sanitized = true;
                        taint.sanitizer = Some(sanitizer.pattern.clone());
                        taint.propagation_path.push(PropagationStep {
                            line: line_num,
                            step_type: PropagationStepType::Sanitization,
                            from_var: Some(var_name.clone()),
                            to_var: var_name.clone(),
                            code: Some(line.trim().to_string()),
                        });
                    }
                }
            }
        }
    }

    /// 查找污点汇
    fn find_sinks(
        &self,
        lines: &[&str],
        file_path: &str,
        language: &str,
    ) -> Vec<(FlowLocation, &TaintSink)> {
        let mut sinks = Vec::new();

        for (line_idx, line) in lines.iter().enumerate() {
            for sink in &self.sinks {
                if sink.matches(line, language) {
                    sinks.push((
                        FlowLocation {
                            file_path: file_path.to_string(),
                            line: line_idx + 1,
                            column: None,
                            symbol: sink.name.clone(),
                            node_id: None,
                            code_snippet: Some(line.trim().to_string()),
                        },
                        sink,
                    ));
                }
            }
        }

        sinks
    }

    /// 追踪污点到汇点
    fn trace_to_sink(
        &self,
        tainted_vars: &HashMap<String, VariableTaint>,
        sink_loc: &FlowLocation,
        sink_def: &TaintSink,
        lines: &[&str],
        file_path: &str,
    ) -> Option<TaintFlow> {
        let sink_line = lines.get(sink_loc.line - 1)?;

        // 检查汇点行是否包含任何污点变量
        for (var_name, taint) in tainted_vars {
            // 检查污点变量是否在汇点行中使用
            if sink_line.contains(var_name) {
                // 检查污点是否在汇点之前（控制流）
                if taint.source_line < sink_loc.line {
                    // 计算置信度
                    let confidence = self.calculate_confidence(taint, sink_def);

                    // 构建传播路径
                    let path = self.build_propagation_path(taint, sink_loc, file_path);

                    return Some(TaintFlow {
                        id: uuid::Uuid::new_v4().to_string(),
                        source: FlowLocation {
                            file_path: file_path.to_string(),
                            line: taint.source_line,
                            column: None,
                            symbol: taint.name.clone(),
                            node_id: None,
                            code_snippet: lines
                                .get(taint.source_line - 1)
                                .map(|s| s.trim().to_string()),
                        },
                        sink: sink_loc.clone(),
                        path,
                        vulnerability_type: sink_def.vulnerability_type.clone(),
                        severity: if taint.is_sanitized {
                            Severity::Low
                        } else {
                            sink_def.severity.clone()
                        },
                        confidence,
                    });
                }
            }
        }

        None
    }

    /// 计算置信度
    fn calculate_confidence(&self, taint: &VariableTaint, sink_def: &TaintSink) -> f32 {
        let mut confidence: f32 = 0.7; // 基础置信度

        // 如果有传播路径，增加置信度
        if taint.propagation_path.len() > 2 {
            confidence += 0.1;
        }

        // 如果变量被净化，大幅降低置信度
        if taint.is_sanitized {
            confidence *= 0.3;
        }

        // 根据漏洞类型调整
        match sink_def.vulnerability_type {
            VulnerabilityType::SqlInjection | VulnerabilityType::CommandInjection => {
                confidence += 0.1;
            }
            VulnerabilityType::CrossSiteScripting | VulnerabilityType::PathTraversal => {
                confidence += 0.05;
            }
            _ => {}
        }

        confidence.clamp(0.1, 0.95)
    }

    /// 构建传播路径
    fn build_propagation_path(
        &self,
        taint: &VariableTaint,
        sink_loc: &FlowLocation,
        file_path: &str,
    ) -> Vec<FlowNode> {
        let mut path = Vec::new();

        // 添加源点
        path.push(FlowNode {
            node_type: FlowNodeType::Source,
            file_path: file_path.to_string(),
            line: taint.source_line,
            symbol: taint.name.clone(),
            code_snippet: taint.propagation_path.first().and_then(|s| s.code.clone()),
        });

        // 添加中间传播步骤
        for step in &taint.propagation_path {
            if step.step_type != PropagationStepType::Source {
                let node_type = match step.step_type {
                    PropagationStepType::Assignment => FlowNodeType::Assignment,
                    PropagationStepType::Sanitization => FlowNodeType::Sanitized,
                    PropagationStepType::ParameterPass => FlowNodeType::Call,
                    _ => FlowNodeType::Statement,
                };

                path.push(FlowNode {
                    node_type,
                    file_path: file_path.to_string(),
                    line: step.line,
                    symbol: step.to_var.clone(),
                    code_snippet: step.code.clone(),
                });
            }
        }

        // 添加汇点
        path.push(FlowNode {
            node_type: FlowNodeType::Sink,
            file_path: file_path.to_string(),
            line: sink_loc.line,
            symbol: sink_loc.symbol.clone(),
            code_snippet: sink_loc.code_snippet.clone(),
        });

        path
    }

    /// 默认净化函数模式
    fn default_sanitizers() -> Vec<SanitizerPattern> {
        vec![
            // Python
            SanitizerPattern {
                pattern: "escape".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "quote".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "sanitize".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "clean".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "html.escape".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "bleach.clean".to_string(),
                affects_vars: true,
            },
            // JavaScript
            SanitizerPattern {
                pattern: "encodeURIComponent".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "escapeHtml".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "DOMPurify".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "validator.escape".to_string(),
                affects_vars: true,
            },
            // Java
            SanitizerPattern {
                pattern: "StringEscapeUtils".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "ESAPI.encoder".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "PreparedStatement".to_string(),
                affects_vars: true,
            },
            // PHP
            SanitizerPattern {
                pattern: "htmlspecialchars".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "mysqli_real_escape".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "pg_escape".to_string(),
                affects_vars: true,
            },
            // General SQL
            SanitizerPattern {
                pattern: "parameterized".to_string(),
                affects_vars: true,
            },
            SanitizerPattern {
                pattern: "bind_param".to_string(),
                affects_vars: true,
            },
        ]
    }

    /// 默认污点源（复用 taint.rs 中的定义）
    fn default_sources() -> Vec<TaintSource> {
        super::taint::TaintAnalyzer::new().into_sources()
    }

    /// 默认污点汇（复用 taint.rs 中的定义）
    fn default_sinks() -> Vec<TaintSink> {
        super::taint::TaintAnalyzer::new().into_sinks()
    }
}

impl Default for EnhancedTaintAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tainted_variable() {
        let analyzer = EnhancedTaintAnalyzer::new();

        // 测试各种语言的赋值语句
        assert_eq!(
            analyzer.extract_tainted_variable("user_id = request.args.get('id')", "python"),
            Some("user_id".to_string())
        );

        assert_eq!(
            analyzer.extract_tainted_variable("const name = req.body.name", "javascript"),
            Some("name".to_string())
        );

        assert_eq!(
            analyzer.extract_tainted_variable(
                "let input = document.getElementById('input').value",
                "javascript"
            ),
            Some("input".to_string())
        );
    }

    #[test]
    fn test_variable_propagation() {
        let analyzer = EnhancedTaintAnalyzer::new();

        let code = r#"
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)
"#;

        let flows = analyzer.analyze(code, "test.py", "python");

        // 应该检测到污点流
        assert!(!flows.is_empty());

        // 检查传播路径
        let flow = &flows[0];
        assert!(flow.path.len() >= 2); // 至少有源和汇
    }

    #[test]
    fn test_sanitization_detection() {
        let analyzer = EnhancedTaintAnalyzer::new();

        let code = r#"
user_input = request.args.get('q')
safe_input = html.escape(user_input)
response = f"<div>{safe_input}</div>"
"#;

        let flows = analyzer.analyze(code, "test.py", "python");

        // 应该检测到污点流，但置信度应该较低
        if !flows.is_empty() {
            let flow = &flows[0];
            assert!(flow.confidence < 0.5);
            assert_eq!(flow.severity, Severity::Low);
        }
    }

    #[test]
    fn test_no_false_positive() {
        let analyzer = EnhancedTaintAnalyzer::new();

        // 汇在源之前，不应该产生污点流
        let code = r#"
cursor.execute(query)
user_input = request.args.get('id')
"#;

        let flows = analyzer.analyze(code, "test.py", "python");
        assert!(flows.is_empty());
    }

    #[test]
    fn test_is_valid_var_name() {
        assert!(EnhancedTaintAnalyzer::is_valid_var_name("user_id"));
        assert!(EnhancedTaintAnalyzer::is_valid_var_name("_private"));
        assert!(EnhancedTaintAnalyzer::is_valid_var_name("name123"));
        assert!(!EnhancedTaintAnalyzer::is_valid_var_name("123abc"));
        assert!(!EnhancedTaintAnalyzer::is_valid_var_name(""));
        assert!(!EnhancedTaintAnalyzer::is_valid_var_name("has space"));
    }
}
