// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 项目安全框架检测。
//!
//! 扫描 pom.xml / build.gradle，检测项目中使用的安全框架依赖。
//! 用于调整端点认证判断——不同框架的认证机制不同，笼统报告
//! "端点未配置认证"会产生大量误报（如 Shiro 项目的端点报
//! Spring Security 缺失）。

use serde::{Deserialize, Serialize};
use std::path::Path;

/// 检测到的安全框架
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityFramework {
    /// Apache Shiro — filter-based auth
    Shiro,
    /// Spring Security — annotation + filter chain
    SpringSecurity,
    /// pac4j — Java security engine
    Pac4j,
    /// Keycloak adapter
    Keycloak,
    /// JWT-based auth (jjwt, nimbus-jose-jwt, auth0-jwt)
    Jwt,
    /// OAuth2 / OIDC (Spring Security OAuth, Google OAuth)
    OAuth2,
}

impl std::fmt::Display for SecurityFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shiro => write!(f, "Apache Shiro"),
            Self::SpringSecurity => write!(f, "Spring Security"),
            Self::Pac4j => write!(f, "pac4j"),
            Self::Keycloak => write!(f, "Keycloak"),
            Self::Jwt => write!(f, "JWT"),
            Self::OAuth2 => write!(f, "OAuth2"),
        }
    }
}

/// 项目框架配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProjectProfile {
    /// 构建工具：maven / gradle / unknown
    pub build_tool: Option<String>,
    /// 检测到的安全框架
    pub security_frameworks: Vec<SecurityFramework>,
    /// Spring Boot 版本（用于判断默认安全配置）
    pub spring_boot_version: Option<String>,
}

impl ProjectProfile {
    /// 项目是否使用指定的安全框架
    pub fn has_framework(&self, framework: &SecurityFramework) -> bool {
        self.security_frameworks.contains(framework)
    }

    /// 项目是否有任何已知的安全框架
    pub fn has_any_security(&self) -> bool {
        !self.security_frameworks.is_empty()
    }

    /// 生成针对 UnauthenticatedEndpoint finding 的提示
    pub fn auth_context_hint(&self) -> Option<String> {
        if self.security_frameworks.is_empty() {
            return Some(
                "No known security framework detected. Endpoints may lack authentication."
                    .to_string(),
            );
        }
        let frameworks: Vec<String> = self
            .security_frameworks
            .iter()
            .map(|f| f.to_string())
            .collect();
        Some(format!(
            "Detected security framework(s): {}. Endpoint authentication may be managed by these frameworks rather than Spring Security annotations. Review the framework-specific auth configuration before classifying as vulnerable.",
            frameworks.join(", ")
        ))
    }
}

/// 从项目根目录检测安全框架
pub fn detect_project_profile(project_path: &Path) -> ProjectProfile {
    let mut profile = ProjectProfile::default();

    // 1. 查找 pom.xml
    for pom_name in &["pom.xml", "build.gradle", "build.gradle.kts"] {
        let build_file = project_path.join(pom_name);
        if build_file.exists() {
            if pom_name.ends_with("xml") {
                profile.build_tool = Some("maven".to_string());
                parse_pom_xml_deps(&build_file, &mut profile);
            } else {
                profile.build_tool = Some("gradle".to_string());
                parse_gradle_deps(&build_file, &mut profile);
            }
            break; // 只处理第一个找到的构建文件
        }
    }

    // 2. 也查子模块的 pom.xml
    if profile.build_tool.is_none() {
        if let Ok(entries) = std::fs::read_dir(project_path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with('.') {
                    continue;
                }
                let sub_pom = entry.path().join("pom.xml");
                if sub_pom.exists() {
                    profile.build_tool = Some("maven (submodule)".to_string());
                    parse_pom_xml_deps(&sub_pom, &mut profile);
                }
            }
        }
    }

    profile
}

/// 解析 pom.xml 中的安全框架依赖
fn parse_pom_xml_deps(path: &Path, profile: &mut ProjectProfile) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let lower = content.to_lowercase();

    // Shiro
    if lower.contains("<groupid>org.apache.shiro</groupid>")
        || lower.contains("shiro-spring")
        || lower.contains("shiro-core")
    {
        if !profile.has_framework(&SecurityFramework::Shiro) {
            profile.security_frameworks.push(SecurityFramework::Shiro);
        }
    }

    // Spring Security
    if lower.contains("spring-boot-starter-security")
        || lower.contains("spring-security")
        || lower.contains("<groupid>org.springframework.security</groupid>")
    {
        if !profile.has_framework(&SecurityFramework::SpringSecurity) {
            profile.security_frameworks.push(SecurityFramework::SpringSecurity);
        }
    }

    // Spring Boot version
    if let Some(ver_start) = lower.find("spring-boot") {
        if let Some(ver_end) = lower[ver_start..].find("</version>") {
            let snippet = &lower[ver_start..ver_start + ver_end];
            if let Some(v) = snippet.find(">") {
                profile.spring_boot_version = Some(snippet[v + 1..].trim().to_string());
            }
        }
    }

    // pac4j
    if lower.contains("pac4j") {
        if !profile.has_framework(&SecurityFramework::Pac4j) {
            profile.security_frameworks.push(SecurityFramework::Pac4j);
        }
    }

    // Keycloak
    if lower.contains("keycloak") {
        if !profile.has_framework(&SecurityFramework::Keycloak) {
            profile.security_frameworks.push(SecurityFramework::Keycloak);
        }
    }

    // JWT libraries
    if lower.contains("jjwt")
        || lower.contains("nimbus-jose-jwt")
        || lower.contains("java-jwt")
        || lower.contains("jose4j")
    {
        if !profile.has_framework(&SecurityFramework::Jwt) {
            profile.security_frameworks.push(SecurityFramework::Jwt);
        }
    }

    // OAuth2
    if lower.contains("spring-security-oauth2")
        || lower.contains("oauth2-client")
        || lower.contains("oauth2-resource-server")
    {
        if !profile.has_framework(&SecurityFramework::OAuth2) {
            profile.security_frameworks.push(SecurityFramework::OAuth2);
        }
    }
}

/// 解析 build.gradle / build.gradle.kts 中的安全框架依赖
fn parse_gradle_deps(path: &Path, profile: &mut ProjectProfile) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let lower = content.to_lowercase();

    let checks: &[(&str, fn() -> SecurityFramework)] = &[
        ("shiro", || SecurityFramework::Shiro),
        ("spring-security", || SecurityFramework::SpringSecurity),
        ("spring-boot-starter-security", || SecurityFramework::SpringSecurity),
        ("pac4j", || SecurityFramework::Pac4j),
        ("keycloak", || SecurityFramework::Keycloak),
        ("jjwt", || SecurityFramework::Jwt),
        ("nimbus-jose", || SecurityFramework::Jwt),
        ("oauth2", || SecurityFramework::OAuth2),
    ];

    for (pattern, make_fw) in checks {
        if lower.contains(pattern) && !profile.security_frameworks.iter().any(|f| *f == make_fw()) {
            profile.security_frameworks.push(make_fw());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_shiro_in_pom() {
        let tmp = std::env::temp_dir().join("ctx-fw-test-pom");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let pom = tmp.join("pom.xml");
        std::fs::write(
            &pom,
            r#"<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.shiro</groupId>
      <artifactId>shiro-spring</artifactId>
      <version>1.2.4</version>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();
        let profile = detect_project_profile(&tmp);
        assert!(profile.has_framework(&SecurityFramework::Shiro));
        assert!(profile.auth_context_hint().unwrap().contains("Shiro"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_spring_security() {
        let tmp = std::env::temp_dir().join("ctx-fw-test-spring");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let pom = tmp.join("pom.xml");
        std::fs::write(
            &pom,
            r#"<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
  </dependencies>
</project>"#,
        )
        .unwrap();
        let profile = detect_project_profile(&tmp);
        assert!(profile.has_framework(&SecurityFramework::SpringSecurity));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_empty_project() {
        let tmp = std::env::temp_dir().join("ctx-fw-test-empty");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let profile = detect_project_profile(&tmp);
        assert!(!profile.has_any_security());
        assert!(profile.auth_context_hint().unwrap().contains("No known"));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
