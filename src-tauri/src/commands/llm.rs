// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// LLM 配置请求
#[derive(Debug, Deserialize)]
pub struct LLMConfigRequest {
    pub provider: String,
    pub model: String,
    pub api_key: String,
    #[serde(default)]
    pub api_endpoint: Option<String>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

/// 连接测试结果
#[derive(Debug, Serialize)]
pub struct TestResult {
    pub success: bool,
    pub message: String,
    pub details: Option<TestDetails>,
}

/// 测试详细信息
#[derive(Debug, Serialize)]
pub struct TestDetails {
    pub endpoint: String,
    pub model: String,
    pub response_time_ms: Option<u64>,
    pub available_models: Option<Vec<String>>,
}

/// OpenAI 兼容 API 响应
#[derive(Debug, Deserialize)]
struct ModelsResponse {
    #[serde(default)]
    pub data: Vec<ModelInfo>,
    pub error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct ModelInfo {
    pub id: String,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: Option<String>,
}

/// 测试 LLM 连接
#[tauri::command]
pub async fn test_llm_connection(config: LLMConfigRequest) -> Result<TestResult, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // 构建 API 端点
    let base_url = config.api_endpoint.as_ref().map(|s| s.as_str()).unwrap_or_else(|| {
        // 根据提供商选择默认端点
        match config.provider.to_lowercase().as_str() {
            "openai" => "https://api.openai.com/v1",
            "azure" => "https://openai.azure.com/v1",
            "anthropic" => "https://api.anthropic.com/v1",
            "deepseek" => "https://api.deepseek.com/v1",
            "ollama" => "http://localhost:11434/v1",
            _ => "https://api.openai.com/v1",
        }
    });

    let models_url = format!("{}/models", base_url.trim_end_matches('/'));

    // 记录开始时间
    let start = std::time::Instant::now();

    // 发送请求
    let response = client
        .get(&models_url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .send()
        .await;

    let response_time = start.elapsed().as_millis() as u64;

    match response {
        Ok(resp) => {
            let status = resp.status();

            if status.is_success() {
                // 尝试解析响应
                match resp.json::<ModelsResponse>().await {
                    Ok(models_response) => {
                        let available_models = if models_response.data.is_empty() {
                            None
                        } else {
                            Some(models_response.data.iter().map(|m| m.id.clone()).collect())
                        };

                        // 检查请求的模型是否可用
                        let model_available = available_models.as_ref()
                            .map(|models: &Vec<String>| models.iter().any(|m| m == &config.model || m.contains(&config.model)))
                            .unwrap_or(true); // 如果无法获取模型列表，假设可用

                        if model_available || available_models.is_none() {
                            Ok(TestResult {
                                success: true,
                                message: format!("连接成功！模型: {}", config.model),
                                details: Some(TestDetails {
                                    endpoint: base_url.to_string(),
                                    model: config.model.clone(),
                                    response_time_ms: Some(response_time),
                                    available_models,
                                }),
                            })
                        } else {
                            Ok(TestResult {
                                success: false,
                                message: format!("连接成功，但模型 '{}' 不可用。可用模型: {:?}",
                                    config.model,
                                    available_models),
                                details: Some(TestDetails {
                                    endpoint: base_url.to_string(),
                                    model: config.model,
                                    response_time_ms: Some(response_time),
                                    available_models,
                                }),
                            })
                        }
                    }
                    Err(_) => {
                        // 响应成功但无法解析，仍然视为成功
                        Ok(TestResult {
                            success: true,
                            message: format!("连接成功！模型: {}", config.model),
                            details: Some(TestDetails {
                                endpoint: base_url.to_string(),
                                model: config.model,
                                response_time_ms: Some(response_time),
                                available_models: None,
                            }),
                        })
                    }
                }
            } else {
                // 错误响应
                let error_text = resp.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                Ok(TestResult {
                    success: false,
                    message: format!("连接失败 (HTTP {}): {}", status.as_u16(), error_text),
                    details: Some(TestDetails {
                        endpoint: base_url.to_string(),
                        model: config.model,
                        response_time_ms: Some(response_time),
                        available_models: None,
                    }),
                })
            }
        }
        Err(e) => {
            // 网络错误
            if e.is_timeout() {
                Ok(TestResult {
                    success: false,
                    message: format!("连接超时: {}", e),
                    details: None,
                })
            } else if e.is_connect() {
                Ok(TestResult {
                    success: false,
                    message: format!("无法连接到服务器: {}\n请检查 API 端点是否正确", e),
                    details: None,
                })
            } else {
                Ok(TestResult {
                    success: false,
                    message: format!("连接失败: {}", e),
                    details: None,
                })
            }
        }
    }
}

/// 测试已保存的 LLM 配置
#[tauri::command]
pub async fn test_llm_config(
    _id: String,
    _db: tauri::State<'_, crate::services::database::Database>,
) -> Result<TestResult, String> {
    // 这里需要从数据库获取配置
    // 由于当前数据库模式可能没有存储 LLM 配置，
    // 我们暂时返回一个错误消息
    Ok(TestResult {
        success: false,
        message: "请使用直接测试连接功能（test_llm_connection）".to_string(),
        details: None,
    })
}
