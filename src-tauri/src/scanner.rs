use std::fs;
use std::path::Path;
use tree_sitter::{Language, Parser};

pub fn scan_file(path: &Path) -> Result<String, String> {
    let code = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut parser = Parser::new();

    let language: Language = if let Some(ext) = path.extension() {
        match ext.to_str() {
            Some("js") => tree_sitter_javascript::LANGUAGE.into(),
            Some("py") => tree_sitter_python::LANGUAGE.into(),
            _ => return Ok("Unsupported language".to_string()),
        }
    } else {
        return Ok("No extension".to_string());
    };

    parser.set_language(&language).map_err(|e| e.to_string())?;
    let tree = parser.parse(&code, None).ok_or("Failed to parse")?;

    let root_node = tree.root_node();
    Ok(format!(
        "Parsed {} nodes. Root kind: {}",
        root_node.child_count(),
        root_node.kind()
    ))
}
