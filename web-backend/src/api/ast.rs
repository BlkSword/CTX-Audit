use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use crate::state::AppState;

#[derive(Serialize, Deserialize)]
pub struct BuildIndexRequest {
    pub project_path: String,
}

#[derive(Serialize)]
pub struct BuildIndexResponse {
    pub files_processed: usize,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct SearchSymbolRequest {
    pub symbol_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetCallGraphRequest {
    pub entry_function: String,
    pub max_depth: Option<usize>,
}

#[derive(Serialize)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub file_path: String,
    pub line: usize,
}

pub fn configure_ast_routes(cfg: &mut web::ServiceConfig) {
    cfg
        .route("/build_index", web::post().to(build_index))
        .route("/search_symbol/{name}", web::get().to(search_symbol))
        .route("/get_call_graph", web::post().to(get_call_graph))
        .route("/get_code_structure/{file_path}", web::get().to(get_code_structure))
        .route("/get_knowledge_graph", web::post().to(get_knowledge_graph));
}

pub async fn build_index(
    state: web::Data<AppState>,
    req: web::Json<BuildIndexRequest>,
) -> impl Responder {
    let mut engine = state.ast_engine.lock().await;

    // 设置仓库路径
    engine.use_repository(&req.project_path);

    // 扫描项目
    let files_processed = match engine.scan_project(&req.project_path) {
        Ok(count) => count,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to scan project: {}", e)
            }));
        }
    };

    drop(engine);

    HttpResponse::Ok().json(BuildIndexResponse {
        files_processed,
        message: format!("Successfully indexed {} files", files_processed),
    })
}

pub async fn search_symbol(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let name = path.into_inner();
    let mut engine = state.ast_engine.lock().await;

    let results = match engine.search_symbols(&name) {
        Ok(results) => results,
        Err(_) => {
            // 没有缓存，返回空结果
            tracing::info!("No AST cache loaded, returning empty search results");
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

    match serde_json::to_value(call_graph) {
        Ok(value) => HttpResponse::Ok().json(value),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to serialize call graph: {}", e)
        }))
    }
}

pub async fn get_code_structure(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let file_path = path.into_inner();
    let mut engine = state.ast_engine.lock().await;

    let structure = match engine.get_file_structure(&file_path) {
        Ok(structure) => structure,
        Err(_) => {
            // 没有缓存，返回空结果
            tracing::info!("No AST cache loaded, returning empty structure");
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
}

pub async fn get_knowledge_graph(
    state: web::Data<AppState>,
    req: web::Json<KnowledgeGraphRequest>,
) -> impl Responder {
    let mut engine = state.ast_engine.lock().await;

    let limit = req.limit.unwrap_or(100);

    // 获取所有符号作为节点 - 如果没有缓存，返回空图谱
    let symbols = match engine.get_all_symbols() {
        Ok(symbols) => symbols,
        Err(_) => {
            // 没有缓存，返回空图谱而不是错误
            tracing::info!("No AST cache loaded, returning empty graph");
            return HttpResponse::Ok().json(KnowledgeGraphResponse {
                graph: GraphData { nodes: vec![], edges: vec![] },
            });
        }
    };

    // 限制节点数量
    let symbols: Vec<_> = symbols.into_iter().take(limit).collect();

    // 创建节点
    let nodes: Vec<GraphNode> = symbols
        .iter()
        .map(|s| GraphNode {
            id: s.name.clone(),
            label: s.name.clone(),
            node_type: format!("{:?}", s.kind),
        })
        .collect();

    // 创建边（基于实际的调用关系和继承关系）
    let mut edges = Vec::new();
    let mut edge_id = 0;

    // 构建符号名到符号的映射，用于快速查找
    let symbol_map: std::collections::HashMap<String, &_> = symbols
        .iter()
        .map(|s| (s.name.clone(), s))
        .collect();

    for symbol in &symbols {
        match symbol.kind {
            // 对于方法调用，创建调用关系的边
            deepaudit_core::SymbolKind::MethodCall => {
                // 从 metadata 中获取调用者信息
                if let Some(caller) = symbol.metadata.get("callerMethod")
                    .or_else(|| symbol.metadata.get("callerFunction"))
                    .and_then(|v| v.as_str()) {
                    // 创建从调用者到被调用者的边
                    edges.push(GraphEdge {
                        id: format!("call_edge_{}", edge_id),
                        source: caller.to_string(),
                        target: symbol.name.clone(),
                        label: Some("calls".to_string()),
                    });
                    edge_id += 1;
                }
            }
            // 对于类，创建继承关系的边
            deepaudit_core::SymbolKind::Class | deepaudit_core::SymbolKind::Interface => {
                for parent_class in &symbol.parent_classes {
                    if symbol_map.contains_key(parent_class) {
                        edges.push(GraphEdge {
                            id: format!("inherit_edge_{}", edge_id),
                            source: symbol.name.clone(),
                            target: parent_class.clone(),
                            label: Some("extends".to_string()),
                        });
                        edge_id += 1;
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
