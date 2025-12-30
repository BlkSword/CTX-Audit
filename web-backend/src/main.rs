use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use actix_cors::Cors;
use actix_files::Files;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod state;

use api::create_api_router;
use state::AppState;

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "version": "1.0.0"
    }))
}

#[actix_web::main]
async fn main() -> Result<()> {
    // 初始化日志
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "deepaudit_web=debug,actix_web=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 初始化状态
    let state = AppState::new().await?;

    // 启动服务器
    let bind_address = "0.0.0.0:8000";
    tracing::info!("CTX-Audit Web server listening on {}", bind_address);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(
                Cors::permissive()
            )
            // API 路由
            .service(create_api_router())
            // 健康检查
            .route("/health", web::get().to(health_check))
            // 静态文件服务
            .service(Files::new("/", "./dist").index_file("index.html"))
    })
    .bind(bind_address)?
    .run()
    .await?;

    Ok(())
}
