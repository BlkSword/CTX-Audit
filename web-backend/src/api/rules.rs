use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::fs;

use crate::state::AppState;

/// 规则响应结构（与前端保持一致）
#[derive(Serialize, Deserialize, Clone)]
pub struct RuleResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
}

impl From<deepaudit_core::rules::model::Rule> for RuleResponse {
    fn from(rule: deepaudit_core::rules::model::Rule) -> Self {
        RuleResponse {
            id: rule.id,
            name: rule.name,
            description: rule.description,
            severity: format!("{:?}", rule.severity).to_lowercase(),
            language: rule.language,
            pattern: rule.pattern,
            query: rule.query,
            category: rule.category,
            cwe: rule.cwe,
        }
    }
}

/// 规则统计信息
#[derive(Serialize)]
pub struct RuleStats {
    pub total: usize,
    pub by_severity: serde_json::Value,
    pub by_language: serde_json::Value,
    pub by_category: serde_json::Value,
}

pub fn configure_rules_routes(cfg: &mut web::ServiceConfig) {
    cfg
        .route("", web::get().to(get_rules))
        .route("", web::post().to(create_rule))
        .route("/stats", web::get().to(get_rule_stats))
        .route("/{rule_id}", web::get().to(get_rule_by_id))
        .route("/{rule_id}", web::put().to(update_rule))
        .route("/{rule_id}", web::delete().to(delete_rule));
}

/// 获取所有规则列表
pub async fn get_rules(
    _state: web::Data<AppState>,
) -> impl Responder {
    // 从项目根目录的 rules 目录加载规则（web-backend 在项目根目录下）
    let rules_path = std::path::Path::new("../rules");

    if !rules_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rules directory not found"
        }));
    }

    match deepaudit_core::rules::loader::load_rules_from_dir(rules_path) {
        Ok(core_rules) => {
            let rules: Vec<RuleResponse> = core_rules
                .into_iter()
                .map(|r| RuleResponse::from(r))
                .collect();
            HttpResponse::Ok().json(rules)
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to load rules: {}", e)
            }))
        }
    }
}

/// 根据ID获取单个规则详情
pub async fn get_rule_by_id(
    _state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let rule_id = path.into_inner();

    let rules_path = std::path::Path::new("../rules");

    if !rules_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rules directory not found"
        }));
    }

    match deepaudit_core::rules::loader::load_rules_from_dir(rules_path) {
        Ok(core_rules) => {
            let rule = core_rules
                .into_iter()
                .find(|r| r.id == rule_id)
                .map(|r| RuleResponse::from(r));

            match rule {
                Some(rule) => HttpResponse::Ok().json(rule),
                None => HttpResponse::NotFound().json(serde_json::json!({
                    "error": format!("Rule '{}' not found", rule_id)
                })),
            }
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to load rules: {}", e)
            }))
        }
    }
}

/// 获取规则统计信息
pub async fn get_rule_stats(
    _state: web::Data<AppState>,
) -> impl Responder {
    let rules_path = std::path::Path::new("../rules");

    if !rules_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rules directory not found"
        }));
    }

    match deepaudit_core::rules::loader::load_rules_from_dir(rules_path) {
        Ok(core_rules) => {
            let total = core_rules.len();

            // 按严重级别统计
            let mut by_severity = serde_json::Map::new();
            for rule in &core_rules {
                let severity = format!("{:?}", rule.severity).to_lowercase();
                let count = by_severity.entry(severity).or_insert(serde_json::json!(0));
                if let Some(n) = count.as_i64() {
                    *count = serde_json::json!(n + 1);
                }
            }

            // 按语言统计
            let mut by_language = serde_json::Map::new();
            for rule in &core_rules {
                let count = by_language.entry(rule.language.clone()).or_insert(serde_json::json!(0));
                if let Some(n) = count.as_i64() {
                    *count = serde_json::json!(n + 1);
                }
            }

            // 按类别统计
            let mut by_category = serde_json::Map::new();
            for rule in &core_rules {
                if let Some(category) = &rule.category {
                    let count = by_category.entry(category.clone()).or_insert(serde_json::json!(0));
                    if let Some(n) = count.as_i64() {
                        *count = serde_json::json!(n + 1);
                    }
                }
            }

            let stats = RuleStats {
                total,
                by_severity: serde_json::to_value(by_severity).unwrap_or_default(),
                by_language: serde_json::to_value(by_language).unwrap_or_default(),
                by_category: serde_json::to_value(by_category).unwrap_or_default(),
            };

            HttpResponse::Ok().json(stats)
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to load rules: {}", e)
            }))
        }
    }
}

/// 将 RuleResponse 转换为 YAML 格式
fn rule_to_yaml(rule: &RuleResponse) -> String {
    let mut yaml = String::new();
    yaml.push_str(&format!("id: {}\n", rule.id));
    yaml.push_str(&format!("name: {}\n", rule.name));
    yaml.push_str(&format!("description: {}\n", rule.description));
    yaml.push_str(&format!("severity: {}\n", rule.severity));
    yaml.push_str(&format!("language: {}\n", rule.language));
    if let Some(category) = &rule.category {
        yaml.push_str(&format!("category: {}\n", category));
    }
    if let Some(cwe) = &rule.cwe {
        yaml.push_str(&format!("cwe: {}\n", cwe));
    }
    if let Some(pattern) = &rule.pattern {
        yaml.push_str(&format!("pattern: {}\n", pattern));
    }
    if let Some(query) = &rule.query {
        yaml.push_str(&format!("query: {}\n", query));
    }
    yaml
}

/// 保存规则到文件
fn save_rule_to_file(rule: &RuleResponse, rules_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let file_name = format!("{}.yaml", rule.id);
    let file_path = rules_path.join(&file_name);

    let yaml_content = rule_to_yaml(rule);

    let mut file = fs::File::create(&file_path)?;
    file.write_all(yaml_content.as_bytes())?;

    Ok(())
}

/// 创建新规则
pub async fn create_rule(
    _state: web::Data<AppState>,
    rule: web::Json<RuleResponse>,
) -> impl Responder {
    let rules_path = std::path::Path::new("../rules");

    // 确保规则目录存在
    if !rules_path.exists() {
        if let Err(e) = fs::create_dir_all(rules_path) {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create rules directory: {}", e)
            }));
        }
    }

    // 检查规则ID是否已存在
    let existing_rules = match deepaudit_core::rules::loader::load_rules_from_dir(rules_path) {
        Ok(rules) => rules,
        Err(_) => vec![],
    };

    if existing_rules.iter().any(|r| r.id == rule.id) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Rule with ID '{}' already exists", rule.id)
        }));
    }

    // 保存规则到文件
    match save_rule_to_file(&rule, rules_path) {
        Ok(_) => {
            tracing::info!("Created new rule: {}", rule.id);
            HttpResponse::Ok().json(rule.into_inner())
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to save rule: {}", e)
            }))
        }
    }
}

/// 更新规则
pub async fn update_rule(
    _state: web::Data<AppState>,
    path: web::Path<String>,
    rule: web::Json<RuleResponse>,
) -> impl Responder {
    let rule_id = path.into_inner();
    let rules_path = std::path::Path::new("../rules");

    if !rules_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rules directory not found"
        }));
    }

    // 检查规则是否存在
    let existing_rules = match deepaudit_core::rules::loader::load_rules_from_dir(rules_path) {
        Ok(rules) => rules,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to load rules: {}", e)
            }));
        }
    };

    if !existing_rules.iter().any(|r| r.id == rule_id) {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("Rule '{}' not found", rule_id)
        }));
    }

    // 如果ID发生变化，需要删除旧文件
    let rule_data = rule.into_inner();
    if rule_data.id != rule_id {
        let old_file = rules_path.join(format!("{}.yaml", rule_id));
        let _ = fs::remove_file(&old_file);
    }

    // 保存更新后的规则
    match save_rule_to_file(&rule_data, rules_path) {
        Ok(_) => {
            tracing::info!("Updated rule: {}", rule_data.id);
            HttpResponse::Ok().json(rule_data)
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to save rule: {}", e)
            }))
        }
    }
}

/// 删除规则
pub async fn delete_rule(
    _state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let rule_id = path.into_inner();
    let rules_path = std::path::Path::new("../rules");

    if !rules_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": "Rules directory not found"
        }));
    }

    let file_name = format!("{}.yaml", rule_id);
    let file_path = rules_path.join(&file_name);

    if !file_path.exists() {
        return HttpResponse::NotFound().json(serde_json::json!({
            "error": format!("Rule '{}' not found", rule_id)
        }));
    }

    match fs::remove_file(&file_path) {
        Ok(_) => {
            tracing::info!("Deleted rule: {}", rule_id);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Rule '{}' deleted successfully", rule_id)
            }))
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to delete rule: {}", e)
            }))
        }
    }
}
