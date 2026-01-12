use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use crate::state::AppState;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct BuildIndexRequest {
    pub project_path: String,
    pub project_id: Option<i64>,  // 新增：项目ID，用于保存到数据库
}

#[derive(Serialize)]
pub struct BuildIndexResponse {
    pub files_processed: usize,
    pub message: String,
    pub index_id: Option<i64>,  // 新增：返回数据库中的索引ID
}

#[derive(Serialize, Deserialize)]
pub struct SearchSymbolRequest {
    pub symbol_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetCallGraphRequest {
    pub entry_function: String,
    pub max_depth: Option<usize>,
    pub project_id: Option<i64>,  // 新增：项目ID，用于保存图谱
    pub save_graph: Option<bool>,  // 新增：是否保存图谱到数据库
}

#[derive(Serialize)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub file_path: String,
    pub line: usize,
}

// 新增：历史查询请求
#[derive(Serialize, Deserialize)]
pub struct GetHistoryRequest {
    pub project_id: i64,
    pub limit: Option<usize>,
}

// 新增：历史记录响应
#[derive(Serialize)]
pub struct AstIndexHistory {
    pub id: i64,
    pub index_version: String,
    pub total_symbols: i64,
    pub total_files: i64,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct CodeGraphHistory {
    pub id: i64,
    pub graph_type: String,
    pub entry_point: Option<String>,
    pub node_count: i64,
    pub edge_count: i64,
    pub created_at: String,
}

// ==================== AST Context 相关 ====================

#[derive(Serialize, Deserialize)]
pub struct AstContextRequest {
    pub file_path: String,
    pub line_range: Vec<usize>,
    #[serde(default)]
    pub include_callers: bool,
    #[serde(default)]
    pub include_callees: bool,
    pub project_id: Option<i64>,
    pub project_path: Option<String>,
}

#[derive(Serialize)]
pub struct AstContextResponse {
    pub file_path: String,
    pub line_range: Vec<usize>,
    pub context: AstContextData,
}

#[derive(Serialize)]
pub struct AstContextData {
    pub code_snippet: String,
    pub function_name: Option<String>,
    pub callers: Vec<CallerInfo>,
    pub callees: Vec<CalleeInfo>,
    pub symbols: Vec<ContextSymbol>,
}

#[derive(Serialize)]
pub struct CallerInfo {
    pub file_path: String,
    pub function_name: String,
    pub line: usize,
}

#[derive(Serialize)]
pub struct CalleeInfo {
    pub name: String,
    pub file_path: String,
    pub line: usize,
}

#[derive(Serialize)]
pub struct ContextSymbol {
    pub name: String,
    pub kind: String,
    pub line: usize,
    pub column: usize,
}

pub fn configure_ast_routes(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/build_index", web::post().to(build_index))
        .route("/search_symbol/{name}", web::get().to(search_symbol))
        .route("/get_call_graph", web::post().to(get_call_graph))
        .route("/get_code_structure/{file_path}", web::get().to(get_code_structure))
        .route("/get_knowledge_graph", web::post().to(get_knowledge_graph))
        .route("/context", web::post().to(get_ast_context))  // 新增：AST上下文端点
        // 新增：历史查询端点
        .route("/history/indices/{project_id}", web::get().to(get_index_history))
        .route("/history/graphs/{project_id}", web::get().to(get_graph_history));
}

pub async fn build_index(
    state: web::Data<AppState>,
    req: web::Json<BuildIndexRequest>,
) -> impl Responder {
    tracing::info!(
        "[AST:build_index] 开始构建索引 - project_path: {}, project_id: {:?}",
        req.project_path,
        req.project_id
    );

    let start_time = std::time::Instant::now();
    let mut engine = state.ast_engine.lock().await;

    // 设置仓库路径
    engine.use_repository(&req.project_path);
    tracing::debug!("[AST:build_index] 已设置仓库路径: {}", req.project_path);

    // 如果提供了 project_id，尝试从数据库加载之前的索引
    if let Some(project_id) = req.project_id {
        tracing::info!("[AST:build_index] 尝试从数据库加载索引 - project_id: {}", project_id);
        match load_ast_index_from_db(&state, project_id, &req.project_path).await {
            Ok(Some(cache_data)) => {
                tracing::info!(
                    "[AST:build_index] 从数据库加载了 {} 个文件的 AST 索引",
                    cache_data.index.len()
                );
                engine.load_from_cache_data(cache_data);
            }
            Ok(None) => {
                tracing::info!("[AST:build_index] 数据库中未找到之前的索引，从头开始");
            }
            Err(e) => {
                tracing::warn!("[AST:build_index] 从数据库加载索引失败: {}, 从头开始", e);
            }
        }
    }

    // 扫描项目（如果有缓存，这将是增量更新）
    let scan_start = std::time::Instant::now();
    let files_processed = match engine.scan_project(&req.project_path) {
        Ok(count) => count,
        Err(e) => {
            tracing::error!("[AST:build_index] 扫描项目失败: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to scan project: {}", e)
            }));
        }
    };
    let scan_duration = scan_start.elapsed();
    tracing::info!(
        "[AST:build_index] 扫描完成 - 文件数: {}, 耗时: {}ms",
        files_processed,
        scan_duration.as_millis()
    );

    // 获取所有符号用于存储
    let symbols = match engine.get_all_symbols() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("[AST:build_index] 获取符号失败: {}", e);
            Vec::new()
        }
    };

    drop(engine);

    tracing::info!(
        "[AST:build_index] 索引构建完成 - 总耗时: {}ms, 符号数: {}",
        start_time.elapsed().as_millis(),
        symbols.len()
    );

    // 如果提供了 project_id，保存到数据库
    let mut index_id = None;
    if let Some(project_id) = req.project_id {
        match save_ast_index_to_db(&state, project_id, &req.project_path, files_processed, &symbols).await {
            Ok(id) => {
                index_id = Some(id);
                tracing::info!("Saved AST index to database: id={}", id);
            }
            Err(e) => {
                tracing::error!("Failed to save AST index: {}", e);
                // 继续返回，不阻断流程
            }
        }

        // 更新缓存状态
        let mut cache_state = state.ast_cache_state.lock().await;
        cache_state.current_project_id = Some(project_id);
        cache_state.current_project_path = Some(req.project_path.clone());
        cache_state.symbol_count = symbols.len();
    }

    HttpResponse::Ok().json(BuildIndexResponse {
        files_processed,
        message: format!("Successfully indexed {} files", files_processed),
        index_id,
    })
}

/// 从数据库加载 AST 索引
async fn load_ast_index_from_db(
    state: &AppState,
    project_id: i64,
    _project_path: &str,
) -> Result<Option<deepaudit_core::CacheData>, Box<dyn std::error::Error>> {
    tracing::info!("Loading AST index from database for project {}", project_id);

    // 查询最近的索引
    let row = match sqlx::query_as::<_, (i64, String, String)>(
        "SELECT id, index_version, index_data
         FROM ast_indices
         WHERE project_id = ?
         ORDER BY created_at DESC
         LIMIT 1"
    )
    .bind(project_id)
    .fetch_optional(&state.db)
    .await?
    {
        Some(row) => row,
        None => {
            tracing::info!("No AST index found in database for project {}", project_id);
            return Ok(None);
        }
    };

    let (id, version, index_data_json) = row;
    tracing::info!("Found AST index {} (version {}) in database", id, version);

    // 从 JSON 反序列化符号
    let symbols: Vec<deepaudit_core::Symbol> = match serde_json::from_str::<Vec<deepaudit_core::Symbol>>(&index_data_json) {
        Ok(s) => {
            tracing::info!("Deserialized {} symbols from database", s.len());
            s
        }
        Err(e) => {
            tracing::error!("Failed to deserialize symbols from database: {}", e);
            return Err(e.into());
        }
    };

    if symbols.is_empty() {
        tracing::warn!("Database returned empty symbol list for project {}", project_id);
    }

    // 构建文件索引
    let mut index = std::collections::HashMap::new();
    let mut class_map = std::collections::HashMap::new();

    // 按文件路径分组符号
    let mut file_symbols: std::collections::HashMap<String, Vec<deepaudit_core::Symbol>> = std::collections::HashMap::new();
    for symbol in symbols {
        let file_path = symbol.file_path.clone();
        file_symbols.entry(file_path).or_default().push(symbol);
    }

    tracing::info!("Grouped symbols into {} files", file_symbols.len());

    // 为每个文件创建 FileIndex
    for (file_path, symbols) in file_symbols {
        // 获取文件的修改时间
        let mtime = match std::fs::metadata(&file_path) {
            Ok(metadata) => metadata.modified()
                .map(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0))
                .unwrap_or(0),
            Err(_) => 0,
        };

        index.insert(file_path.clone(), deepaudit_core::FileIndex { mtime, symbols });

        // 构建类映射
        for symbol in index.get(&file_path).unwrap().symbols.iter() {
            if matches!(symbol.kind, deepaudit_core::SymbolKind::Class) {
                class_map.insert(symbol.name.clone(), file_path.clone());
            }
        }
    }

    tracing::info!("Built CacheData with {} files and {} classes", index.len(), class_map.len());

    Ok(Some(deepaudit_core::CacheData {
        index,
        class_map,
        build_time: chrono::Utc::now().to_rfc3339(),
    }))
}

/// 保存 AST 索引到数据库
async fn save_ast_index_to_db(
    state: &AppState,
    project_id: i64,
    project_path: &str,
    files_processed: usize,
    symbols: &[deepaudit_core::Symbol],
) -> Result<i64, Box<dyn std::error::Error>> {
    let mut tx = state.db.begin().await?;

    // 生成索引版本号（使用时间戳）
    let index_version = format!("{}-{}", chrono::Utc::now().to_rfc3339(), Uuid::new_v4());

    // 序列化符号数据
    let index_data = serde_json::to_string(symbols)?;

    // 1. 插入 ast_indices 记录
    let idx = sqlx::query_scalar::<_, i64>(
        "INSERT INTO ast_indices (project_id, index_version, total_symbols, total_files, index_data)
         VALUES (?, ?, ?, ?, ?)
         RETURNING id"
    )
    .bind(project_id)
    .bind(&index_version)
    .bind(symbols.len() as i64)
    .bind(files_processed as i64)
    .bind(&index_data)
    .fetch_one(&mut *tx)
    .await?;

    // 2. 批量插入符号
    for symbol in symbols {
        let metadata_json = serde_json::to_string(&symbol.metadata)?;
        let symbol_type = format!("{:?}", symbol.kind);

        // 生成唯一的 symbol_id (使用 name:file_path:line)
        let symbol_id = format!("{}:{}:{}", symbol.name, symbol.file_path, symbol.line);

        // 从 parent_classes 获取父类名称，用逗号连接
        let parent_name = if !symbol.parent_classes.is_empty() {
            symbol.parent_classes.join(",")
        } else {
            String::new()
        };

        sqlx::query(
            "INSERT INTO symbols (project_id, ast_index_id, symbol_id, symbol_name, symbol_type, file_path, line_number, end_line, parent_name, metadata)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(project_id)
        .bind(idx)
        .bind(&symbol_id)
        .bind(&symbol.name)
        .bind(&symbol_type)
        .bind(&symbol.file_path)
        .bind(symbol.start_line as i64)
        .bind(symbol.end_line as i64)
        .bind(&parent_name)
        .bind(&metadata_json)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(idx)
}

pub async fn search_symbol(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let name = path.into_inner();

    tracing::info!(
        "[AST:search_symbol] 搜索符号 - name: {}, project_id: {:?}",
        name,
        query.get("project_id")
    );

    // 如果提供了项目信息，确保缓存已加载
    if let (Some(project_id_str), Some(project_path)) = (query.get("project_id"), query.get("project_path")) {
        if let Ok(project_id) = project_id_str.parse::<i64>() {
            let _ = ensure_cache_loaded(&state, project_id, project_path).await;
        }
    }

    let mut engine = state.ast_engine.lock().await;

    let results = match engine.search_symbols(&name) {
        Ok(results) => {
            tracing::info!("[AST:search_symbol] 找到 {} 个符号匹配", results.len());
            results
        }
        Err(_) => {
            // 没有缓存，返回空结果
            tracing::warn!("[AST:search_symbol] 未加载 AST 缓存，返回空结果");
            return HttpResponse::Ok().json(vec![] as Vec<Symbol>);
        }
    };

    let symbols: Vec<Symbol> = results
        .iter()
        .map(|s| Symbol {
            name: s.name.clone(),
            kind: format!("{:?}", s.kind),
            file_path: s.file_path.clone(),
            line: s.line as usize,
        })
        .collect();

    HttpResponse::Ok().json(symbols)
}

pub async fn get_call_graph(
    state: web::Data<AppState>,
    req: web::Json<GetCallGraphRequest>,
) -> impl Responder {
    let mut engine = state.ast_engine.lock().await;

    let max_depth = req.max_depth.unwrap_or(3);
    let call_graph = match engine.get_call_graph(&req.entry_function, max_depth) {
        Ok(graph) => graph,
        Err(_) => {
            // 没有缓存，返回空图
            tracing::info!("No AST cache loaded, returning empty call graph");
            return HttpResponse::Ok().json(serde_json::json!({
                "nodes": [],
                "edges": []
            }));
        }
    };

    drop(engine);

    // 如果需要保存到数据库
    let mut graph_id = None;
    if req.save_graph.unwrap_or(false) {
        if let Some(project_id) = req.project_id {
            match save_code_graph_to_db(&state, project_id, "call_graph", Some(&req.entry_function), &call_graph).await {
                Ok(id) => {
                    graph_id = Some(id);
                    tracing::info!("Saved call graph to database: id={}", id);
                }
                Err(e) => {
                    tracing::error!("Failed to save call graph: {}", e);
                }
            }
        }
    }

    // 添加 graph_id 到响应
    let mut response = call_graph.clone();
    if let Some(id) = graph_id {
        if let Some(obj) = response.as_object_mut() {
            obj.insert("graph_id".to_string(), serde_json::json!(id));
        }
    }

    match serde_json::to_value(response) {
        Ok(value) => HttpResponse::Ok().json(value),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to serialize call graph: {}", e)
        }))
    }
}

/// 保存代码图谱到数据库
async fn save_code_graph_to_db(
    state: &AppState,
    project_id: i64,
    graph_type: &str,
    entry_point: Option<&str>,
    graph_data: &serde_json::Value,
) -> Result<i64, Box<dyn std::error::Error>> {
    let graph_json = serde_json::to_string(graph_data)?;

    // 计算 nodes 和 edges 数量
    let node_count = graph_data["nodes"].as_array().map(|v| v.len()).unwrap_or(0) as i64;
    let edge_count = graph_data["edges"].as_array().map(|v| v.len()).unwrap_or(0) as i64;

    let graph_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO code_graphs (project_id, graph_type, entry_point, graph_data, node_count, edge_count)
         VALUES (?, ?, ?, ?, ?, ?)
         RETURNING id"
    )
    .bind(project_id)
    .bind(graph_type)
    .bind(entry_point)
    .bind(&graph_json)
    .bind(node_count)
    .bind(edge_count)
    .fetch_one(&state.db)
    .await?;

    // 如果是调用关系图，保存调用关系到 call_relations 表
    if graph_type == "call_graph" {
        if let Some(edges) = graph_data["edges"].as_array() {
            for edge in edges {
                let from = edge["from"].as_str().unwrap_or("");
                let to = edge["to"].as_str().unwrap_or("");
                let file_path = edge["file"].as_str().unwrap_or("");
                let line = edge["line"].as_i64().unwrap_or(0);

                if !from.is_empty() && !to.is_empty() {
                    sqlx::query(
                        "INSERT INTO call_relations (project_id, graph_id, caller_function, callee_function, file_path, line_number)
                         VALUES (?, ?, ?, ?, ?, ?)"
                    )
                    .bind(project_id)
                    .bind(graph_id)
                    .bind(from)
                    .bind(to)
                    .bind(file_path)
                    .bind(line)
                    .execute(&state.db)
                    .await?;
                }
            }
        }
    }

    Ok(graph_id)
}

pub async fn get_code_structure(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    let file_path = path.into_inner();

    tracing::info!(
        "[AST:get_code_structure] 获取代码结构 - file_path: {}, project_id: {:?}",
        file_path,
        query.get("project_id")
    );

    // 如果提供了项目信息，确保缓存已加载
    if let (Some(project_id_str), Some(project_path)) = (query.get("project_id"), query.get("project_path")) {
        if let Ok(project_id) = project_id_str.parse::<i64>() {
            let _ = ensure_cache_loaded(&state, project_id, project_path).await;
        }
    }

    let mut engine = state.ast_engine.lock().await;

    let structure = match engine.get_file_structure(&file_path) {
        Ok(structure) => {
            tracing::info!("[AST:get_code_structure] 找到 {} 个符号", structure.len());
            structure
        }
        Err(e) => {
            // 没有缓存，返回空结果
            tracing::warn!("[AST:get_code_structure] 未找到 AST 缓存: {}", e);
            return HttpResponse::Ok().json(vec![] as Vec<Symbol>);
        }
    };

    let symbols: Vec<Symbol> = structure
        .iter()
        .map(|s| Symbol {
            name: s.name.clone(),
            kind: format!("{:?}", s.kind),
            file_path: s.file_path.clone(),
            line: s.line as usize,
        })
        .collect();

    HttpResponse::Ok().json(symbols)
}

#[derive(Serialize, Deserialize)]
pub struct KnowledgeGraphRequest {
    pub limit: Option<usize>,
    pub project_id: Option<i64>,
    pub project_path: Option<String>,
}

#[derive(Serialize)]
pub struct KnowledgeGraphResponse {
    pub graph: GraphData,
}

#[derive(Serialize)]
pub struct GraphData {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub node_type: String,
}

#[derive(Serialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub label: Option<String>,
    #[serde(rename = "type")]
    pub edge_type: String,
}

/// 确保AST引擎已加载指定项目的缓存
async fn ensure_cache_loaded(
    state: &AppState,
    project_id: i64,
    project_path: &str,
) -> Result<(), String> {
    // 检查是否已经加载了同一个项目的缓存
    {
        let cache_state = state.ast_cache_state.lock().await;
        if cache_state.current_project_id == Some(project_id)
            && cache_state.symbol_count > 0 {
            // 已经加载了同一个项目的有效缓存
            tracing::info!("Using cached AST data for project {} ({} symbols)",
                project_id, cache_state.symbol_count);
            return Ok(());
        }
    }

    // 需要加载新项目的缓存
    tracing::info!("Loading AST cache for project {} (path: {})", project_id, project_path);

    // 从数据库加载
    match load_ast_index_from_db(state, project_id, project_path).await {
        Ok(Some(cache_data)) => {
            let symbol_count: usize = cache_data.index.values().map(|v| v.symbols.len()).sum();
            tracing::info!("Loaded AST cache from database for project {} ({} files, {} symbols)",
                project_id, cache_data.index.len(), symbol_count);

            // 设置仓库路径
            let engine = state.ast_engine.lock().await;
            engine.use_repository(project_path);
            drop(engine);

            // 加载缓存数据
            let engine = state.ast_engine.lock().await;
            engine.load_from_cache_data(cache_data);

            // 加载后保存到文件系统，以便下次使用
            let _ = engine.save_cache();

            // 更新缓存状态
            let mut cache_state = state.ast_cache_state.lock().await;
            cache_state.current_project_id = Some(project_id);
            cache_state.current_project_path = Some(project_path.to_string());
            cache_state.symbol_count = symbol_count;

            Ok(())
        }
        Ok(None) => {
            tracing::info!("No cached AST data found in database for project {}", project_id);
            Err(format!("No cached AST data found for project {}", project_id))
        }
        Err(e) => {
            tracing::warn!("Failed to load AST cache from database: {}", e);
            Err(format!("Failed to load AST cache: {}", e))
        }
    }
}

pub async fn get_knowledge_graph(
    state: web::Data<AppState>,
    req: web::Json<KnowledgeGraphRequest>,
) -> impl Responder {
    tracing::info!("get_knowledge_graph called with project_id={:?}, project_path={:?}",
        req.project_id, req.project_path);

    // 如果提供了项目信息，确保缓存已加载
    if let (Some(project_id), Some(project_path)) = (req.project_id, &req.project_path) {
        let _ = ensure_cache_loaded(&state, project_id, project_path).await;
    }

    let mut engine = state.ast_engine.lock().await;

    let limit = req.limit.unwrap_or(500);

    // 获取所有符号作为节点
    let symbols = match engine.get_all_symbols() {
        Ok(symbols) => {
            tracing::info!("get_knowledge_graph: loaded {} symbols from engine", symbols.len());
            symbols
        }
        Err(e) => {
            // 没有缓存，返回空图谱而不是错误
            tracing::info!("No AST cache loaded, returning empty graph: {}", e);
            return HttpResponse::Ok().json(KnowledgeGraphResponse {
                graph: GraphData { nodes: vec![], edges: vec![] },
            });
        }
    };

    // 限制节点数量
    let symbols: Vec<_> = symbols.into_iter().take(limit).collect();

    tracing::info!("get_knowledge_graph: using {} symbols (limited from {})", symbols.len(), limit);

    // 创建节点 - 使用唯一 ID (文件路径:符号名:行号)
    let nodes: Vec<GraphNode> = symbols
        .iter()
        .map(|s| {
            let unique_id = format!("{}:{}:{}", s.file_path, s.name, s.line);
            GraphNode {
                id: unique_id.clone(),
                label: s.name.clone(),
                node_type: format!("{:?}", s.kind),
            }
        })
        .collect();

    // 构建符号名到节点ID的映射（支持同名符号）
    let mut name_to_ids: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for s in &symbols {
        let unique_id = format!("{}:{}:{}", s.file_path, s.name, s.line);
        name_to_ids.entry(s.name.clone()).or_default().push(unique_id);
    }

    // 创建边（基于实际的代码关系）
    let mut edges = Vec::new();
    let mut edge_id = 0;

    // 按文件分组符号，用于建立包含关系
    let mut file_symbols: std::collections::HashMap<String, Vec<&deepaudit_core::Symbol>> = std::collections::HashMap::new();
    for s in &symbols {
        file_symbols.entry(s.file_path.clone()).or_default().push(s);
    }

    for symbol in &symbols {
        let source_id = format!("{}:{}:{}", symbol.file_path, symbol.name, symbol.line);

        match symbol.kind {
            // 类/接口/结构体：包含方法和字段的关系
            deepaudit_core::SymbolKind::Class | deepaudit_core::SymbolKind::Interface | deepaudit_core::SymbolKind::Struct => {
                // 继承关系
                for parent_class in &symbol.parent_classes {
                    if let Some(parent_ids) = name_to_ids.get(parent_class) {
                        for parent_id in parent_ids {
                            edges.push(GraphEdge {
                                id: format!("edge_{}", edge_id),
                                source: source_id.clone(),
                                target: parent_id.clone(),
                                label: Some("extends".to_string()),
                                edge_type: "inheritance".to_string(),
                            });
                            edge_id += 1;
                        }
                    }
                }

                // 查找同一文件中属于这个类的方法
                if let Some(file_syms) = file_symbols.get(&symbol.file_path) {
                    for other in file_syms {
                        if other.line > symbol.line && other.line < symbol.line + 100 {
                            match other.kind {
                                deepaudit_core::SymbolKind::Method | deepaudit_core::SymbolKind::Function => {
                                    // 检查是否可能是这个类的成员
                                    let other_code_lower = other.code.to_lowercase();
                                    let symbol_name_lower = symbol.name.to_lowercase();
                                    if other_code_lower.contains(&symbol_name_lower) || other.package.contains(&symbol.name) {
                                        let target_id = format!("{}:{}:{}", other.file_path, other.name, other.line);
                                        edges.push(GraphEdge {
                                            id: format!("edge_{}", edge_id),
                                            source: source_id.clone(),
                                            target: target_id,
                                            label: Some("contains".to_string()),
                                            edge_type: "containment".to_string(),
                                        });
                                        edge_id += 1;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            // 方法调用关系
            deepaudit_core::SymbolKind::MethodCall => {
                // 从 metadata 中获取调用者信息
                let caller = symbol.metadata.get("callerMethod")
                    .or_else(|| symbol.metadata.get("callerFunction"))
                    .and_then(|v| v.as_str());

                if let Some(caller_name) = caller {
                    if let Some(caller_ids) = name_to_ids.get(caller_name) {
                        for caller_id in caller_ids {
                            edges.push(GraphEdge {
                                id: format!("edge_{}", edge_id),
                                source: caller_id.clone(),
                                target: source_id.clone(),
                                label: Some("calls".to_string()),
                                edge_type: "call".to_string(),
                            });
                            edge_id += 1;
                        }
                    }
                }
            }

            // 函数/方法：查找它们调用的其他函数
            deepaudit_core::SymbolKind::Function | deepaudit_core::SymbolKind::Method => {
                // 分析代码中的函数调用（简单模式：查找可能的调用）
                for (other_name, other_ids) in &name_to_ids {
                    if other_name != &symbol.name {
                        // 检查代码中是否包含对这个函数/方法的引用
                        let pattern = format!("{}(", other_name);
                        if symbol.code.contains(&pattern) {
                            for target_id in other_ids {
                                edges.push(GraphEdge {
                                    id: format!("edge_{}", edge_id),
                                    source: source_id.clone(),
                                    target: target_id.clone(),
                                    label: Some("calls".to_string()),
                                    edge_type: "call".to_string(),
                                });
                                edge_id += 1;
                            }
                        }
                    }
                }
            }

            _ => {}
        }
    }

    HttpResponse::Ok().json(KnowledgeGraphResponse {
        graph: GraphData { nodes, edges },
    })
}

/// 获取项目的 AST 索引历史
pub async fn get_index_history(
    state: web::Data<AppState>,
    path: web::Path<i64>,
    query: web::Query<GetHistoryRequest>,
) -> impl Responder {
    let project_id = path.into_inner();
    let limit = query.limit.unwrap_or(20) as i64;

    let indices = match sqlx::query_as::<_, (i64, String, i64, i64, String)>(
        "SELECT id, index_version, total_symbols, total_files, datetime(created_at) as created_at
         FROM ast_indices
         WHERE project_id = ?
         ORDER BY created_at DESC
         LIMIT ?"
    )
    .bind(project_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    {
        Ok(indices) => indices,
        Err(e) => {
            tracing::error!("Failed to fetch index history: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to fetch index history: {}", e)
            }));
        }
    };

    let history: Vec<AstIndexHistory> = indices
        .into_iter()
        .map(|(id, index_version, total_symbols, total_files, created_at)| AstIndexHistory {
            id,
            index_version,
            total_symbols,
            total_files,
            created_at,
        })
        .collect();

    HttpResponse::Ok().json(history)
}

/// 获取项目的代码图谱历史
pub async fn get_graph_history(
    state: web::Data<AppState>,
    path: web::Path<i64>,
    query: web::Query<GetHistoryRequest>,
) -> impl Responder {
    let project_id = path.into_inner();
    let limit = query.limit.unwrap_or(20) as i64;

    let graphs = match sqlx::query_as::<_, (i64, String, Option<String>, i64, i64, String)>(
        "SELECT id, graph_type, entry_point, node_count, edge_count, datetime(created_at) as created_at
         FROM code_graphs
         WHERE project_id = ?
         ORDER BY created_at DESC
         LIMIT ?"
    )
    .bind(project_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    {
        Ok(graphs) => graphs,
        Err(e) => {
            tracing::error!("Failed to fetch graph history: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to fetch graph history: {}", e)
            }));
        }
    };

    let history: Vec<CodeGraphHistory> = graphs
        .into_iter()
        .map(|(id, graph_type, entry_point, node_count, edge_count, created_at)| CodeGraphHistory {
            id,
            graph_type,
            entry_point,
            node_count,
            edge_count,
            created_at,
        })
        .collect();

    HttpResponse::Ok().json(history)
}

/// 获取 AST 上下文
pub async fn get_ast_context(
    state: web::Data<AppState>,
    req: web::Json<AstContextRequest>,
) -> impl Responder {
    tracing::info!(
        "[AST:get_ast_context] 获取AST上下文 - file_path: {}, line_range: {:?}",
        req.file_path,
        req.line_range
    );

    // 读取文件内容
    let code_snippet = match std::fs::read_to_string(&req.file_path) {
        Ok(content) => {
            // 提取指定行范围
            let lines: Vec<&str> = content.lines().collect();
            let start = if let Some(&s) = req.line_range.first() { s - 1 } else { 0 };
            let end = if let Some(&e) = req.line_range.get(1) { e } else { lines.len() };

            if start >= lines.len() {
                return HttpResponse::BadRequest().json(serde_json::json!({
                    "error": format!("Invalid line range: start {} exceeds file length {}", start + 1, lines.len())
                }));
            }

            let actual_end = end.min(lines.len());
            let range_lines = &lines[start..actual_end];
            range_lines.join("\n")
        }
        Err(e) => {
            tracing::error!("[AST:get_ast_context] 读取文件失败: {}", e);
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Failed to read file: {}", e)
            }));
        }
    };

    // 获取AST引擎
    let engine = state.ast_engine.lock().await;

    // 尝试从数据库加载索引（如果提供了project_id或project_path）
    if let Some(project_id) = req.project_id {
        if let Some(project_path) = &req.project_path {
            match load_ast_index_from_db(&state, project_id, project_path).await {
                Ok(Some(cache_data)) => {
                    tracing::info!("[AST:get_ast_context] 从数据库加载了索引");
                    engine.load_from_cache_data(cache_data);
                }
                Ok(None) => {
                    tracing::info!("[AST:get_ast_context] 数据库中未找到索引，使用现有缓存");
                }
                Err(e) => {
                    tracing::warn!("[AST:get_ast_context] 加载索引失败: {}", e);
                }
            }
        }
    }

    // 查找函数名 - 通过搜索符号来确定
    let start_line = if let Some(&s) = req.line_range.first() { s } else { 1 };
    let function_name: Option<String> = None;  // 简化实现，暂不查找函数名

    // 收集调用者 - 使用find_call_sites方法
    let mut callers = Vec::new();
    if req.include_callers {
        // 由于没有具体的函数名，我们搜索文件中的所有函数符号
        if let Ok(all_symbols) = engine.get_all_symbols() {
            for symbol in all_symbols {
                // 只查找同一文件中的函数符号
                if symbol.file_path == req.file_path {
                    // 使用matches!宏检查SymbolKind
                    if matches!(symbol.kind, deepaudit_core::SymbolKind::Function) {
                        // 尝试查找调用该函数的位置
                        if let Ok(call_sites) = engine.find_call_sites(&symbol.name) {
                            for site in call_sites {
                                callers.push(CallerInfo {
                                    file_path: site.file_path.clone(),
                                    function_name: site.name.clone(),
                                    line: site.line as usize,  // u32转usize
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // 收集被调用者 - 由于没有具体的函数调用分析，简化为查找文件中的符号
    let mut callees = Vec::new();
    if req.include_callees {
        // 查找文件中的函数符号作为潜在的被调用者
        if let Ok(all_symbols) = engine.get_all_symbols() {
            for symbol in all_symbols {
                if symbol.file_path == req.file_path {
                    if matches!(symbol.kind, deepaudit_core::SymbolKind::Function) {
                        // 只添加在目标行之后的函数作为潜在的被调用者
                        if symbol.line as usize >= start_line {
                            callees.push(CalleeInfo {
                                name: symbol.name.clone(),
                                file_path: symbol.file_path.clone(),
                                line: symbol.line as usize,
                            });
                        }
                    }
                }
            }
        }
    }

    // 获取指定行范围内的符号
    let mut symbols = Vec::new();
    let end_line = if let Some(&e) = req.line_range.get(1) { e } else { start_line };

    if let Ok(all_symbols) = engine.get_all_symbols() {
        for symbol in all_symbols {
            if symbol.file_path == req.file_path {
                let symbol_line = symbol.line as usize;
                if symbol_line >= start_line && symbol_line <= end_line {
                    symbols.push(ContextSymbol {
                        name: symbol.name,
                        kind: format!("{:?}", symbol.kind),
                        line: symbol_line,
                        column: 0,  // Symbol没有column字段，使用默认值0
                    });
                }
            }
        }
    }

    drop(engine);

    let response = AstContextResponse {
        file_path: req.file_path.clone(),
        line_range: req.line_range.clone(),
        context: AstContextData {
            code_snippet,
            function_name: function_name.clone(),
            callers,
            callees,
            symbols,
        },
    };

    tracing::info!(
        "[AST:get_ast_context] 返回上下文 - 函数: {:?}, 调用者: {}, 被调用者: {}, 符号: {}",
        function_name,
        response.context.callers.len(),
        response.context.callees.len(),
        response.context.symbols.len()
    );

    HttpResponse::Ok().json(response)
}
