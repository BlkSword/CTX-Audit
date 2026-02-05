//! Prompt 加载器
//!
//! 从文件系统加载 YAML 格式的 Prompt 模板

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Prompt 模板
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PromptTemplate {
    /// 系统提示词
    pub system_prompt: String,

    /// 提示词片段（命名的模板片段）
    #[serde(default)]
    pub prompts: HashMap<String, String>,

    /// 模板变量说明
    #[serde(default)]
    pub variables: HashMap<String, VariableDefinition>,
}

/// 变量定义
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct VariableDefinition {
    /// 变量描述
    pub description: String,

    /// 默认值
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,

    /// 是否必需
    #[serde(default)]
    pub required: bool,
}

/// Prompt 加载器
pub struct PromptLoader {
    /// 模板缓存
    cache: Arc<RwLock<HashMap<String, PromptTemplate>>>,

    /// 模板目录
    templates_dir: String,
}

impl PromptLoader {
    /// 创建新的加载器
    pub fn new(templates_dir: String) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            templates_dir,
        }
    }

    /// 使用默认目录创建加载器
    pub fn with_default_dir() -> Self {
        Self::new("src-tauri/prompts".to_string())
    }

    /// 加载 Prompt 模板
    pub async fn load(&self, agent_type: &str) -> Result<PromptTemplate, PromptError> {
        // 检查缓存
        {
            let cache = self.cache.read().await;
            if let Some(template) = cache.get(agent_type) {
                return Ok(template.clone());
            }
        }

        // 加载文件
        let path = Path::new(&self.templates_dir).join(format!("{}.yaml", agent_type));
        let content = tokio::fs::read_to_string(&path)
            .await
            .map_err(|e| PromptError::NotFound(format!("无法读取模板文件 {}: {}", path.display(), e)))?;

        // 解析 YAML
        let template: PromptTemplate = serde_yaml::from_str(&content)
            .map_err(|e| PromptError::ParseError(format!("解析 YAML 失败: {}", e)))?;

        // 缓存模板
        {
            let mut cache = self.cache.write().await;
            cache.insert(agent_type.to_string(), template.clone());
        }

        Ok(template)
    }

    /// 重新加载模板（清除缓存）
    pub async fn reload(&self, agent_type: &str) -> Result<PromptTemplate, PromptError> {
        // 清除缓存
        {
            let mut cache = self.cache.write().await;
            cache.remove(agent_type);
        }

        // 重新加载
        self.load(agent_type).await
    }

    /// 清空所有缓存
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }

    /// 渲染模板字符串（变量替换）
    pub fn render(&self, template: &str, variables: &HashMap<String, String>) -> String {
        let mut result = template.to_string();

        for (key, value) in variables {
            let placeholder1 = format!("{{{}}}", key);
            let placeholder2 = format!("{{{{{}}}}}", key); // 双花括号格式

            result = result.replace(&placeholder1, value);
            result = result.replace(&placeholder2, value);
        }

        result
    }

    /// 渲染 Prompt 模板
    pub fn render_template(
        &self,
        template: &PromptTemplate,
        variables: &HashMap<String, String>,
    ) -> String {
        self.render(&template.system_prompt, variables)
    }

    /// 获取所有已缓存的模板名称
    pub async fn cached_templates(&self) -> Vec<String> {
        let cache = self.cache.read().await;
        cache.keys().cloned().collect()
    }
}

impl Default for PromptLoader {
    fn default() -> Self {
        Self::with_default_dir()
    }
}

/// Prompt 错误类型
#[derive(Debug, Clone, thiserror::Error)]
pub enum PromptError {
    #[error("模板未找到: {0}")]
    NotFound(String),

    #[error("解析错误: {0}")]
    ParseError(String),

    #[error("变量错误: {0}")]
    VariableError(String),

    #[error("IO 错误: {0}")]
    IoError(String),
}

/// 全局 Prompt 加载器单例
pub fn global_loader() -> &'static PromptLoader {
    use std::sync::OnceLock;
    static LOADER: OnceLock<PromptLoader> = OnceLock::new();
    LOADER.get_or_init(|| PromptLoader::with_default_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_simple() {
        let loader = PromptLoader::with_default_dir();
        let template = "Hello, {name}! You are {age} years old.";

        let mut vars = HashMap::new();
        vars.insert("name".to_string(), "Alice".to_string());
        vars.insert("age".to_string(), "30".to_string());

        let result = loader.render(template, &vars);
        assert_eq!(result, "Hello, Alice! You are 30 years old.");
    }

    #[test]
    fn test_render_missing_variable() {
        let loader = PromptLoader::with_default_dir();
        let template = "Hello, {name}!";

        let mut vars = HashMap::new();
        // 不提供 name 变量

        let result = loader.render(template, &vars);
        // 缺失的变量不会被替换
        assert_eq!(result, "Hello, {name}!");
    }
}
