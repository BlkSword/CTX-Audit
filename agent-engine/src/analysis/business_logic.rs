// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 业务逻辑分析器
//!
//! 检测 IDOR、权限绕过、状态机异常、业务规则违反等传统工具无法发现的漏洞

use crate::semantic::SemanticContext;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// 从代码行中提取路由路径
fn extract_route_from_line(line: &str) -> Option<String> {
    // 尝试双引号
    if let Some(start) = line.find('"') {
        if let Some(end) = line[start + 1..].find('"') {
            return Some(line[start + 1..start + 1 + end].to_string());
        }
    }
    // 尝试单引号
    if let Some(start) = line.find('\'') {
        if let Some(end) = line[start + 1..].find('\'') {
            return Some(line[start + 1..start + 1 + end].to_string());
        }
    }
    None
}

/// 业务逻辑分析器
pub struct BusinessLogicAnalyzer {
    /// 权限模型识别器
    authz_detector: AuthorizationDetector,

    /// 状态机分析器
    state_machine_analyzer: StateMachineAnalyzer,

    /// 业务规则提取器
    business_rule_extractor: BusinessRuleExtractor,
}

/// IDOR 漏洞
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IDORVulnerability {
    /// 端点路径
    pub endpoint_path: String,

    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: usize,

    /// 资源参数名
    pub resource_param: String,

    /// 请求方法
    pub method: String,

    /// 严重程度
    pub severity: String,

    /// 描述
    pub description: String,

    /// 修复建议
    pub remediation: String,
}

/// 授权检测结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCheck {
    /// 是否存在权限检查
    pub has_check: bool,

    /// 检查类型
    pub check_type: AuthzCheckType,

    /// 检查位置
    pub check_location: Option<String>,

    /// 检查的权限类型
    pub permission_type: Option<String>,
}

/// 权限检查类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthzCheckType {
    /// 角色检查
    RoleCheck,

    /// 所有权检查
    OwnershipCheck,

    /// 权限检查
    PermissionCheck,

    /// ACL 检查
    AclCheck,

    /// 自定义检查
    CustomCheck,

    /// 无检查
    None,
}

/// 状态机异常
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachineAnomaly {
    /// 异常类型
    pub anomaly_type: StateMachineAnomalyType,

    /// 当前状态
    pub current_state: String,

    /// 非法转换
    pub invalid_transition: String,

    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: usize,

    /// 严重程度
    pub severity: String,

    /// 描述
    pub description: String,
}

/// 状态机异常类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StateMachineAnomalyType {
    /// 跳过状态
    SkippedState,

    /// 逆向状态
    ReversedState,

    /// 未处理的边界条件
    UnhandledEdgeCase,

    /// 竞态条件
    RaceCondition,
}

/// 业务规则违反
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessRuleViolation {
    /// 规则类型
    pub rule_type: BusinessRuleType,

    /// 规则描述
    pub rule_description: String,

    /// 违反情况
    pub violation: String,

    /// 文件路径
    pub file_path: String,

    /// 行号
    pub line: usize,

    /// 严重程度
    pub severity: String,
}

/// 业务规则类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BusinessRuleType {
    /// 数量限制
    QuantityLimit,

    /// 金额限制
    AmountLimit,

    /// 时间限制
    TimeLimit,

    /// 速率限制
    RateLimit,

    /// 业务流程顺序
    ProcessOrder,

    /// 其他
    Other,
}

impl BusinessLogicAnalyzer {
    /// 创建新的业务逻辑分析器
    pub fn new() -> Self {
        Self {
            authz_detector: AuthorizationDetector::new(),
            state_machine_analyzer: StateMachineAnalyzer::new(),
            business_rule_extractor: BusinessRuleExtractor::new(),
        }
    }

    /// 检测 IDOR (Insecure Direct Object Reference)
    pub fn detect_idor(
        &self,
        endpoints: &[ApiEndpointInfo],
        code: &str,
    ) -> Vec<IDORVulnerability> {
        let mut vulnerabilities = Vec::new();

        let auth_model = self.authz_detector.build_authorization_model(code);

        for endpoint in endpoints {
            if let Some(resource_id_param) = &endpoint.resource_id_param {
                if !auth_model.has_ownership_check(endpoint) {
                    vulnerabilities.push(IDORVulnerability {
                        endpoint_path: endpoint.path.clone(),
                        file_path: endpoint.file_path.clone(),
                        line: endpoint.line,
                        resource_param: resource_id_param.clone(),
                        method: endpoint.method.clone(),
                        severity: "High".to_string(),
                        description: format!(
                            "端点 {} 直接访问资源 {} 而未验证所有权",
                            endpoint.path, resource_id_param
                        ),
                        remediation: format!(
                            "在访问 {} 之前验证当前用户是否有权访问资源 {}",
                            endpoint.path, resource_id_param
                        ),
                    });
                }
            }
        }

        vulnerabilities
    }

    /// 检测权限绕过
    pub fn detect_authorization_bypass(
        &self,
        endpoints: &[ApiEndpointInfo],
        code: &str,
    ) -> Vec<String> {
        let mut issues = Vec::new();

        for endpoint in endpoints {
            if endpoint.auth_required {
                let check = self.authz_detector.analyze_authorization(endpoint, code);

                match check {
                    AuthorizationCheck {
                        has_check: false,
                        check_type: AuthzCheckType::None,
                        ..
                    } => {
                        issues.push(format!(
                            "端点 {} 要求认证但缺少权限检查",
                            endpoint.path
                        ));
                    }
                    AuthorizationCheck {
                        has_check: true,
                        check_type: AuthzCheckType::None,
                        ..
                    } => {
                        issues.push(format!(
                            "端点 {} 有权限检查但类型未知，可能存在绕过",
                            endpoint.path
                        ));
                    }
                    _ => {}
                }
            }
        }

        issues
    }

    /// 分析状态机异常
    pub fn analyze_state_machines(
        &self,
        code: &str,
        file_path: &str,
    ) -> Vec<StateMachineAnomaly> {
        self.state_machine_analyzer
            .analyze(code, file_path)
            .into_iter()
            .filter(|a| matches!(a.severity.as_str(), "High|Critical"))
            .collect()
    }

    /// 提取业务规则
    pub fn extract_business_rules(
        &self,
        code: &str,
        file_path: &str,
    ) -> Vec<BusinessRuleViolation> {
        self.business_rule_extractor
            .extract_rules(code, file_path)
            .into_iter()
            .filter(|v| matches!(v.severity.as_str(), "Medium|High|Critical"))
            .collect()
    }

    /// 综合分析业务逻辑安全
    pub async fn analyze(
        &self,
        code: &str,
        context: &SemanticContext,
    ) -> BusinessLogicAnalysisResult {
        let mut findings = Vec::new();

        // 1. API 端点分析（从代码文本中提取基础端点信息）
        let endpoints = Self::extract_endpoints_from_code(code, context.file_path.as_deref().unwrap_or(""));

        // 2. IDOR 检测
        let idor_findings = self.detect_idor(&endpoints, code);
        for finding in idor_findings {
            findings.push(BusinessLogicFinding {
                finding_type: "IDOR".to_string(),
                severity: finding.severity,
                location: format!("{}:{}", finding.file_path, finding.line),
                description: finding.description,
                remediation: finding.remediation,
            });
        }

        // 3. 权限绕过检测
        let bypass_issues = self.detect_authorization_bypass(&endpoints, code);
        for issue in bypass_issues {
            findings.push(BusinessLogicFinding {
                finding_type: "AuthorizationBypass".to_string(),
                severity: "High".to_string(),
                location: context.file_path.clone().unwrap_or_default(),
                description: issue,
                remediation: "确保所有需要认证的端点都有适当的权限检查".to_string(),
            });
        }

        // 4. 状态机分析
        let state_anomalies = self.analyze_state_machines(
            code,
            context.file_path.as_deref().unwrap_or("unknown"),
        );
        for anomaly in state_anomalies {
            findings.push(BusinessLogicFinding {
                finding_type: "StateMachineAnomaly".to_string(),
                severity: anomaly.severity,
                location: format!("{}:{}", anomaly.file_path, anomaly.line),
                description: anomaly.description,
                remediation: "验证状态转换的合法性，添加适当的检查".to_string(),
            });
        }

        // 5. 业务规则违反检测
        let rule_violations = self.extract_business_rules(
            code,
            context.file_path.as_deref().unwrap_or("unknown"),
        );
        for violation in rule_violations {
            findings.push(BusinessLogicFinding {
                finding_type: format!("BusinessRuleViolation::{:?}", violation.rule_type),
                severity: violation.severity,
                location: format!("{}:{}", violation.file_path, violation.line),
                description: violation.violation,
                remediation: "验证业务规则的正确实现".to_string(),
            });
        }

        // 计算统计信息（在移动 findings 之前）
        let statistics = self.calculate_statistics(&findings);

        BusinessLogicAnalysisResult {
            findings,
            api_endpoints: endpoints,
            statistics,
        }
    }

    /// 提取 API 端点信息（从攻击面映射结果转换）
    pub fn endpoints_from_attack_surface(
        entry_points: &[deepaudit_core::EntryPoint],
    ) -> Vec<ApiEndpointInfo> {
        entry_points
            .iter()
            .filter(|ep| ep.entry_type == deepaudit_core::EntryType::HttpEndpoint)
            .map(|ep| ApiEndpointInfo {
                path: ep.route.clone().unwrap_or_default(),
                method: ep.http_method.clone().unwrap_or("GET".to_string()),
                controller: ep.function_name.clone().unwrap_or_default(),
                file_path: ep.file_path.clone(),
                line: ep.line,
                auth_required: ep.auth_required,
                resource_id_param: Self::extract_resource_id_param(ep.route.as_deref()),
            })
            .collect()
    }

    /// 从路由中提取资源 ID 参数名
    fn extract_resource_id_param(route: Option<&str>) -> Option<String> {
        let route = route?;
        // Spring: {id}, @PathVariable
        if let Some(start) = route.find('{') {
            if let Some(end) = route[start..].find('}') {
                let param = &route[start + 1..start + end];
                return Some(param.to_string());
            }
        }
        // Express: :id
        for segment in route.split('/') {
            if segment.starts_with(':') {
                return Some(segment[1..].to_string());
            }
        }
        // Django: <int:id> or <id>
        if route.contains('<') && route.contains('>') {
            if let Some(start) = route.find('<') {
                if let Some(end) = route[start..].find('>') {
                    let inner = &route[start + 1..start + end];
                    let name = inner.split(':').last().unwrap_or(inner);
                    return Some(name.to_string());
                }
            }
        }
        None
    }

    /// 基于攻击面映射进行完整业务逻辑分析
    pub async fn analyze_with_attack_surface(
        &self,
        attack_surface: &deepaudit_core::AttackSurface,
        project_path: &str,
    ) -> BusinessLogicAnalysisResult {
        let mut findings = Vec::new();

        let endpoints = Self::endpoints_from_attack_surface(&attack_surface.entry_points);

        // 收集每个端点文件的代码并分析
        let mut analyzed_files: HashSet<String> = HashSet::new();
        for ep in &attack_surface.entry_points {
            if analyzed_files.contains(&ep.file_path) {
                continue;
            }
            analyzed_files.insert(ep.file_path.clone());

            if let Ok(code) = std::fs::read_to_string(&ep.file_path) {
                let context = SemanticContext {
                    file_path: Some(ep.file_path.clone()),
                    function_name: ep.function_name.clone(),
                    language: None,
                    framework: None,
                    imports: Vec::new(),
                    decorators: Vec::new(),
                    extra: HashMap::new(),
                };

                let mut result = self.analyze(&code, &context).await;
                findings.append(&mut result.findings);
            }
        }

        // 额外：检测未认证端点
        for ep in &attack_surface.entry_points {
            if !ep.auth_required && ep.entry_type == deepaudit_core::EntryType::HttpEndpoint {
                findings.push(BusinessLogicFinding {
                    finding_type: "UnauthenticatedEndpoint".to_string(),
                    severity: "High".to_string(),
                    location: format!("{}:{}", ep.file_path, ep.line),
                    description: format!(
                        "端点 {} {} 未配置认证保护",
                        ep.http_method.as_deref().unwrap_or("?"),
                        ep.route.as_deref().unwrap_or("?")
                    ),
                    remediation: "为该端点添加认证中间件或注解".to_string(),
                });
            }
        }

        let statistics = self.calculate_statistics(&findings);

        BusinessLogicAnalysisResult {
            findings,
            api_endpoints: endpoints,
            statistics,
        }
    }

    /// 从代码中提取端点信息（基于正则匹配，简化版）
    fn extract_endpoints_from_code(code: &str, file_path: &str) -> Vec<ApiEndpointInfo> {
        let mut endpoints = Vec::new();

        for (line_num, line) in code.lines().enumerate() {
            let trimmed = line.trim();

            // Spring: @GetMapping("/path")
            if trimmed.contains("@GetMapping") || trimmed.contains("@PostMapping")
                || trimmed.contains("@RequestMapping") || trimmed.contains("@DeleteMapping")
                || trimmed.contains("@PutMapping") || trimmed.contains("@PatchMapping")
            {
                let method = if trimmed.contains("Get") { "GET" }
                    else if trimmed.contains("Post") { "POST" }
                    else if trimmed.contains("Put") { "PUT" }
                    else if trimmed.contains("Delete") { "DELETE" }
                    else if trimmed.contains("Patch") { "PATCH" }
                    else { "GET" };

                let route = extract_route_from_line(trimmed);
                let resource_param = Self::extract_resource_id_param(route.as_deref());

                endpoints.push(ApiEndpointInfo {
                    path: route.unwrap_or_default(),
                    method: method.to_string(),
                    controller: String::new(),
                    file_path: file_path.to_string(),
                    line: line_num + 1,
                    auth_required: false,
                    resource_id_param: resource_param,
                });
            }

            // Express: app.get('/path')
            if (trimmed.contains("app.get(") || trimmed.contains("app.post(")
                || trimmed.contains("router.get(") || trimmed.contains("router.post("))
            {
                let method = if trimmed.contains(".get(") { "GET" }
                    else if trimmed.contains(".post(") { "POST" }
                    else if trimmed.contains(".put(") { "PUT" }
                    else if trimmed.contains(".delete(") { "DELETE" }
                    else { "GET" };

                let route = extract_route_from_line(trimmed);
                let resource_param = Self::extract_resource_id_param(route.as_deref());

                endpoints.push(ApiEndpointInfo {
                    path: route.unwrap_or_default(),
                    method: method.to_string(),
                    controller: String::new(),
                    file_path: file_path.to_string(),
                    line: line_num + 1,
                    auth_required: trimmed.contains("auth"),
                    resource_id_param: resource_param,
                });
            }
        }

        endpoints
    }

    /// 计算统计信息
    fn calculate_statistics(&self, findings: &[BusinessLogicFinding]) -> BusinessLogicStatistics {
        let severity_counts: HashMap<String, usize> = findings
            .iter()
            .fold(HashMap::new(), |mut acc, f| {
                *acc.entry(f.finding_type.clone()).or_insert(0) += 1;
                acc
            });

        BusinessLogicStatistics {
            total_findings: findings.len(),
            critical_count: findings.iter().filter(|f| f.severity == "Critical").count(),
            high_count: findings.iter().filter(|f| f.severity == "High").count(),
            medium_count: findings.iter().filter(|f| f.severity == "Medium").count(),
            low_count: findings.iter().filter(|f| f.severity == "Low").count(),
            findings_by_type: severity_counts,
        }
    }
}

impl Default for BusinessLogicAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// API 端点信息
#[derive(Debug, Clone)]
pub struct ApiEndpointInfo {
    pub path: String,
    pub method: String,
    pub controller: String,
    pub file_path: String,
    pub line: usize,
    pub auth_required: bool,
    pub resource_id_param: Option<String>,
}

/// 业务逻辑发现
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessLogicFinding {
    /// 发现类型
    pub finding_type: String,

    /// 严重程度
    pub severity: String,

    /// 位置
    pub location: String,

    /// 描述
    pub description: String,

    /// 修复建议
    pub remediation: String,
}

/// 业务逻辑分析结果
#[derive(Debug, Clone)]
pub struct BusinessLogicAnalysisResult {
    pub findings: Vec<BusinessLogicFinding>,
    pub api_endpoints: Vec<ApiEndpointInfo>,
    pub statistics: BusinessLogicStatistics,
}

/// 业务逻辑统计
#[derive(Debug, Clone)]
pub struct BusinessLogicStatistics {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub findings_by_type: HashMap<String, usize>,
}

/// 授权检测器
pub struct AuthorizationDetector {
    // 预定义的权限检查模式
    authz_patterns: Vec<AuthzPattern>,
}

/// 授权模式
#[derive(Debug, Clone)]
struct AuthzPattern {
    pattern_type: AuthzCheckType,
    patterns: Vec<String>,
}

/// 授权模型
#[derive(Debug, Clone)]
struct AuthorizationModel {
    // 检测到的权限检查
    checks: Vec<AuthorizationCheck>,
}

impl AuthorizationModel {
    /// 检查端点是否有所有权检查
    fn has_ownership_check(&self, _endpoint: &ApiEndpointInfo) -> bool {
        self.checks.iter().any(|check| {
            check.check_type == AuthzCheckType::OwnershipCheck
        })
    }
}

impl AuthorizationDetector {
    fn new() -> Self {
        let authz_patterns = vec![
            AuthzPattern {
                pattern_type: AuthzCheckType::RoleCheck,
                patterns: vec![
                    "request.user.role".into(),
                    "user.role".into(),
                    "has_role".into(),
                    "is_admin".into(),
                    "is_superuser".into(),
                ],
            },
            AuthzPattern {
                pattern_type: AuthzCheckType::OwnershipCheck,
                patterns: vec![
                    "user.id ==".into(),
                    "request.user.id ==".into(),
                    "obj.owner ==".into(),
                    "is_owner".into(),
                ],
            },
            AuthzPattern {
                pattern_type: AuthzCheckType::PermissionCheck,
                patterns: vec![
                    "has_permission".into(),
                    "user.can".into(),
                    "user.has_perm".into(),
                ],
            },
        ];

        Self { authz_patterns }
    }

    fn build_authorization_model(&self, code: &str) -> AuthorizationModel {
        let mut checks = Vec::new();

        for pattern in &self.authz_patterns {
            for pattern_str in &pattern.patterns {
                if code.contains(pattern_str) {
                    checks.push(AuthorizationCheck {
                        has_check: true,
                        check_type: pattern.pattern_type.clone(),
                        check_location: None,
                        permission_type: None,
                    });
                    break;
                }
            }
        }

        AuthorizationModel { checks }
    }

    fn analyze_authorization(&self, endpoint: &ApiEndpointInfo, code: &str) -> AuthorizationCheck {
        // 检查是否有权限检查
        let has_check = self
            .authz_patterns
            .iter()
            .any(|pattern| {
                pattern
                    .patterns
                    .iter()
                    .any(|p| code.contains(p))
            });

        if !has_check {
            return AuthorizationCheck {
                has_check: false,
                check_type: AuthzCheckType::None,
                check_location: None,
                permission_type: None,
            };
        }

        // 确定检查类型
        let check_type = self
            .authz_patterns
            .iter()
            .find(|pattern| {
                pattern
                    .patterns
                    .iter()
                    .any(|p| code.contains(p))
            })
            .map(|p| p.pattern_type.clone())
            .unwrap_or(AuthzCheckType::None);

        AuthorizationCheck {
            has_check: true,
            check_type,
            check_location: Some(endpoint.file_path.clone()),
            permission_type: None,
        }
    }
}

impl Default for AuthorizationDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// 状态机分析器
pub struct StateMachineAnalyzer {
    // 状态机模式
    state_patterns: Vec<StatePattern>,
}

/// 状态模式
#[derive(Debug, Clone)]
struct StatePattern {
    states: Vec<String>,
    transitions: Vec<(String, String)>,
}

impl StateMachineAnalyzer {
    fn new() -> Self {
        Self {
            state_patterns: vec![
                // 订单状态机
                StatePattern {
                    states: vec![
                        "pending".into(),
                        "paid".into(),
                        "shipped".into(),
                        "delivered".into(),
                        "cancelled".into(),
                        "refunded".into(),
                    ],
                    transitions: vec![
                        ("pending".into(), "paid".into()),
                        ("paid".into(), "shipped".into()),
                        ("shipped".into(), "delivered".into()),
                        ("pending".into(), "cancelled".into()),
                        ("paid".into(), "refunded".into()),
                    ],
                },
            ],
        }
    }

    fn analyze(&self, code: &str, file_path: &str) -> Vec<StateMachineAnomaly> {
        let mut anomalies = Vec::new();

        // 检测潜在的竞态条件
        if code.contains("if obj.status == \"pending\"")
            && !code.contains("select_for_update")
        {
            anomalies.push(StateMachineAnomaly {
                anomaly_type: StateMachineAnomalyType::RaceCondition,
                current_state: "pending".into(),
                invalid_transition: "无原子更新的状态检查".to_string(),
                file_path: file_path.to_string(),
                line: 0,
                severity: "High".to_string(),
                description: "状态检查和转换之间存在竞态条件".to_string(),
            });
        }

        anomalies
    }
}

impl Default for StateMachineAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// 业务规则提取器
pub struct BusinessRuleExtractor {
    // 规则模式
    rule_patterns: Vec<BusinessRulePattern>,
}

/// 业务规则模式
#[derive(Debug, Clone)]
struct BusinessRulePattern {
    rule_type: BusinessRuleType,
    patterns: Vec<String>,
    severity: String,
}

impl BusinessRuleExtractor {
    fn new() -> Self {
        let rule_patterns = vec![
            BusinessRulePattern {
                rule_type: BusinessRuleType::QuantityLimit,
                patterns: vec!["quantity > ".into(), "max_count".into()],
                severity: "Medium".to_string(),
            },
            BusinessRulePattern {
                rule_type: BusinessRuleType::AmountLimit,
                patterns: vec!["amount > ".into(), "max_amount".into()],
                severity: "High".to_string(),
            },
            BusinessRulePattern {
                rule_type: BusinessRuleType::RateLimit,
                patterns: vec!["@rate_limit".into(), "limit_requests".into()],
                severity: "Medium".to_string(),
            },
        ];

        Self { rule_patterns }
    }

    fn extract_rules(&self, code: &str, file_path: &str) -> Vec<BusinessRuleViolation> {
        let mut violations = Vec::new();

        for pattern in &self.rule_patterns {
            for pattern_str in &pattern.patterns {
                if let Some(pos) = code.find(pattern_str) {
                    violations.push(BusinessRuleViolation {
                        rule_type: pattern.rule_type.clone(),
                        rule_description: format!("检测到业务规则模式: {}", pattern_str),
                        violation: format!(
                            "在 {} 处发现业务规则相关代码: {}",
                            file_path, pattern_str
                        ),
                        file_path: file_path.to_string(),
                        line: 0, // TODO: 计算实际行号
                        severity: pattern.severity.clone(),
                    });
                }
            }
        }

        violations
    }
}

impl Default for BusinessRuleExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = BusinessLogicAnalyzer::new();
        // 测试创建成功
        assert_eq!(analyzer.authz_detector.authz_patterns.len(), 3);
    }

    #[test]
    fn test_idor_detection() {
        let analyzer = BusinessLogicAnalyzer::new();

        let code = r#"
        @app.route('/api/files/<int:file_id>/download')
        def download_file(file_id):
            file = File.objects.get(id=file_id)
            return send_file(file.path)
        "#;

        let endpoints = vec![ApiEndpointInfo {
            path: "/api/files/{file_id}/download".to_string(),
            method: "GET".to_string(),
            controller: "download_file".to_string(),
            file_path: "files.py".to_string(),
            line: 3,
            auth_required: true,
            resource_id_param: Some("file_id".to_string()),
        }];

        let idor_findings = analyzer.detect_idor(&endpoints, code);

        // 应该检测到 IDOR 漏洞
        assert!(!idor_findings.is_empty());
    }
}
