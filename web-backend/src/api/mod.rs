use actix_web::{web, Scope};

pub mod ast;
pub mod project;
pub mod scanner;
pub mod files;
pub mod rules;

pub fn create_api_router() -> Scope {
    web::scope("/api")
        .service(project_routes())
        .service(ast_routes())
        .service(scanner_routes())
        .service(files_routes())
        .service(rules_routes())
}

fn project_routes() -> Scope {
    web::scope("/projects")
        .configure(project::configure_project_routes)
}

fn ast_routes() -> Scope {
    web::scope("/ast")
        .configure(ast::configure_ast_routes)
}

fn scanner_routes() -> Scope {
    web::scope("/scanner")
        .configure(scanner::configure_scanner_routes)
}

fn files_routes() -> Scope {
    web::scope("/files")
        .configure(files::configure_files_routes)
}

fn rules_routes() -> Scope {
    web::scope("/rules")
        .configure(rules::configure_rules_routes)
}
