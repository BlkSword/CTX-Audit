use std::fs;
use std::path::Path;
use tree_sitter::{Language, Parser};

#[allow(dead_code)]
pub fn scan_file(path: &Path) -> Result<String, String> {
    let code = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut parser = Parser::new();

    let language: Language = if let Some(ext) = path.extension() {
        match ext.to_str() {
            Some("js") => tree_sitter_javascript::LANGUAGE.into(),
            Some("py") => tree_sitter_python::LANGUAGE.into(),
            Some("java") => tree_sitter_java::LANGUAGE.into(),
            Some("rs") => tree_sitter_rust::LANGUAGE.into(),
            Some("go") => tree_sitter_go::LANGUAGE.into(),
            Some("ts") => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Some("tsx") => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Some("html") | Some("htm") | Some("vue") => tree_sitter_html::LANGUAGE.into(),
            Some("css") => tree_sitter_css::LANGUAGE.into(),
            Some("json") => tree_sitter_json::LANGUAGE.into(),
            Some("c") | Some("h") => tree_sitter_c::LANGUAGE.into(),
            Some("cpp") | Some("hpp") | Some("cc") => tree_sitter_cpp::LANGUAGE.into(),
            _ => return Ok("不支持的语言".to_string()),
        }
    } else {
        return Ok("无扩展名".to_string());
    };

    parser.set_language(&language).map_err(|e| e.to_string())?;
    let tree = parser.parse(&code, None).ok_or("解析失败")?;

    let root_node = tree.root_node();
    Ok(format!(
        "已解析 {} 个节点。根节点类型: {}",
        root_node.child_count(),
        root_node.kind()
    ))
}
