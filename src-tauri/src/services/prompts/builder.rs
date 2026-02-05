//! Prompt 构建器
//!
//! 构建复杂的 Prompt，支持上下文注入和约束添加

use std::collections::HashMap;

use crate::models::agent::{AgentContext, AgentType};

/// Prompt 构建器
pub struct PromptBuilder {
    /// 基础模板
    base_template: String,

    /// 系统提示词部分
    system_parts: Vec<String>,

    /// 用户指令部分
    user_parts: Vec<String>,

    /// 约束条件
    constraints: Vec<String>,

    /// 示例
    examples: Vec<PromptExample>,

    /// 上下文信息
    context: HashMap<String, String>,
}

/// Prompt 示例
#[derive(Debug, Clone)]
pub struct PromptExample {
    /// 输入
    pub input: String,

    /// 输出
    pub output: String,

    /// 说明
    pub explanation: Option<String>,
}

impl PromptBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self {
            base_template: String::new(),
            system_parts: Vec::new(),
            user_parts: Vec::new(),
            constraints: Vec::new(),
            examples: Vec::new(),
            context: HashMap::new(),
        }
    }

    /// 设置基础模板
    pub fn with_template(mut self, template: String) -> Self {
        self.base_template = template;
        self
    }

    /// 添加系统提示词部分
    pub fn add_system(mut self, part: impl Into<String>) -> Self {
        self.system_parts.push(part.into());
        self
    }

    /// 添加用户指令部分
    pub fn add_user(mut self, part: impl Into<String>) -> Self {
        self.user_parts.push(part.into());
        self
    }

    /// 添加约束条件
    pub fn add_constraint(mut self, constraint: impl Into<String>) -> Self {
        self.constraints.push(constraint.into());
        self
    }

    /// 添加示例
    pub fn add_example(mut self, example: PromptExample) -> Self {
        self.examples.push(example);
        self
    }

    /// 添加上下文变量
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// 添加多个上下文变量
    pub fn with_context_map(mut self, context: HashMap<String, String>) -> Self {
        for (key, value) in context {
            self.context.insert(key, value);
        }
        self
    }

    /// 构建 Prompt
    pub fn build(&self) -> BuiltPrompt {
        let system = self.build_system();
        let user = self.build_user();

        BuiltPrompt { system, user }
    }

    /// 构建系统提示词
    fn build_system(&self) -> String {
        let mut parts = Vec::new();

        // 基础模板
        if !self.base_template.is_empty() {
            parts.push(self.base_template.clone());
        }

        // 系统部分
        parts.extend(self.system_parts.clone());

        // 约束条件
        if !self.constraints.is_empty() {
            parts.push("## 约束条件".to_string());
            for (i, constraint) in self.constraints.iter().enumerate() {
                parts.push(format!("{}. {}", i + 1, constraint));
            }
        }

        // 示例
        if !self.examples.is_empty() {
            parts.push("## 示例".to_string());
            for (i, example) in self.examples.iter().enumerate() {
                parts.push(format!("### 示例 {}", i + 1));
                parts.push(format!("输入: {}", example.input));
                parts.push(format!("输出: {}", example.output));
                if let Some(ref explanation) = example.explanation {
                    parts.push(format!("说明: {}", explanation));
                }
            }
        }

        // 替换变量
        let loader = super::loader::PromptLoader::with_default_dir();
        parts
            .into_iter()
            .map(|p| loader.render(&p, &self.context))
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// 构建用户指令
    fn build_user(&self) -> String {
        let parts: Vec<String> = self.user_parts.clone();

        // 替换变量
        let loader = super::loader::PromptLoader::with_default_dir();
        parts
            .into_iter()
            .map(|p| loader.render(&p, &self.context))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl Default for PromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 构建完成的 Prompt
#[derive(Debug, Clone)]
pub struct BuiltPrompt {
    /// 系统提示词
    pub system: String,

    /// 用户指令
    pub user: String,
}

impl BuiltPrompt {
    /// 转换为 LLM 消息格式
    pub fn to_messages(&self) -> Vec<crate::models::llm::LLMMessage> {
        vec![
            crate::models::llm::LLMMessage::system(&self.system),
            crate::models::llm::LLMMessage::user(&self.user),
        ]
    }
}

/// Prompt 上下文
///
/// 从 Agent 上下文中提取的信息
pub struct PromptContext {
    /// 项目路径
    pub project_path: String,

    /// 审计类型
    pub audit_type: String,

    /// 可用的工具列表
    pub available_tools: Vec<String>,

    /// 额外的上下文信息
    pub extra: HashMap<String, String>,
}

impl PromptContext {
    /// 从 Agent 上下文创建
    pub fn from_agent_context(ctx: &AgentContext) -> Self {
        let tools = vec![
            "read_file".to_string(),
            "list_files".to_string(),
            "search_symbol".to_string(),
            "report_finding".to_string(),
            "finish_analysis".to_string(),
        ];

        Self {
            project_path: ctx.project_path.clone(),
            audit_type: ctx.audit_type.to_string(),
            available_tools: tools,
            extra: HashMap::new(),
        }
    }

    /// 转换为变量映射
    pub fn to_variables(&self) -> HashMap<String, String> {
        let mut vars = HashMap::new();
        vars.insert("project_path".to_string(), self.project_path.clone());
        vars.insert("audit_type".to_string(), self.audit_type.clone());
        vars.insert(
            "tools_list".to_string(),
            self.available_tools.join(", "),
        );

        // 添加额外的变量
        for (key, value) in &self.extra {
            vars.insert(key.clone(), value.clone());
        }

        vars
    }
}

/// 为特定 Agent 类型构建 Prompt
pub async fn build_prompt_for_agent(
    agent_type: AgentType,
    context: &PromptContext,
) -> Result<BuiltPrompt, String> {
    let loader = super::loader::global_loader();
    let template = loader
        .load(&agent_type.to_string())
        .await
        .map_err(|e| e.to_string())?;

    let vars = context.to_variables();

    Ok(BuiltPrompt {
        system: loader.render(&template.system_prompt, &vars),
        user: "开始执行任务。".to_string(),
    })
}

/// ReAct Prompt 构建器
pub struct ReactPromptBuilder {
    inner: PromptBuilder,
}

impl ReactPromptBuilder {
    /// 创建新的 ReAct Prompt 构建器
    pub fn new() -> Self {
        let inner = PromptBuilder::new()
            .add_system("你是一个使用 ReAct (推理-行动) 框架的安全代码审计专家。")
            .add_constraint("每次行动前必须先进行思考")
            .add_constraint("使用可用的工具来收集信息")
            .add_constraint("基于收集的信息进行分析和判断")
            .add_constraint("发现漏洞时使用 report_finding 工具报告")
            .add_constraint("完成分析后使用 finish_analysis 工具结束");

        Self { inner }
    }

    /// 添加可用工具
    pub fn with_tools(mut self, tools: &[String]) -> Self {
        let tools_list = tools.join("\n- ");
        self.inner = self
            .inner
            .add_system(format!("## 可用工具\n- {}", tools_list));
        self
    }

    /// 添加任务描述
    pub fn with_task(mut self, task: impl Into<String>) -> Self {
        self.inner = self.inner.add_user(task);
        self
    }

    /// 构建 Prompt
    pub fn build(self) -> BuiltPrompt {
        self.inner.build()
    }
}

impl Default for ReactPromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_builder() {
        let builder = PromptBuilder::new()
            .add_system("你是一个助手")
            .add_user("帮助我")
            .with_context("name", "Alice");

        let prompt = builder.build();
        assert!(prompt.system.contains("助手"));
        assert!(prompt.user.contains("帮助我"));
    }

    #[test]
    fn test_built_prompt_to_messages() {
        let prompt = BuiltPrompt {
            system: "你是一个助手".to_string(),
            user: "帮助我".to_string(),
        };

        let messages = prompt.to_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].get_text(), "你是一个助手");
        assert_eq!(messages[1].get_text(), "帮助我");
    }

    #[test]
    fn test_react_prompt_builder() {
        let builder = ReactPromptBuilder::new()
            .with_tools(&["read_file".to_string(), "search".to_string()])
            .with_task("审计这个项目");

        let prompt = builder.build();
        assert!(prompt.system.contains("ReAct"));
        assert!(prompt.user.contains("审计这个项目"));
    }
}
