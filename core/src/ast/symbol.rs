use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind, // "class", "function", "method", "method_call", "interface"
    pub file_path: String,
    pub line: u32,
    pub start_line: u32,
    pub end_line: u32,
    pub code: String,
    pub parent_classes: Vec<String>,
    pub package: String,
    pub modifiers: Vec<String>,
    pub fields: Vec<Field>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub subclasses: Vec<String>, // Populated post-analysis
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymbolKind {
    Class,
    Function,
    Method,
    MethodCall,
    Interface,
    Struct,
}

impl Symbol {
    pub fn new(
        name: String,
        kind: SymbolKind,
        file_path: String,
        start_line: u32,
        code: String,
    ) -> Self {
        let end_line = start_line;
        Self {
            name,
            kind,
            file_path,
            line: start_line,
            start_line,
            end_line,
            code,
            parent_classes: Vec::new(),
            package: String::new(),
            modifiers: Vec::new(),
            fields: Vec::new(),
            metadata: HashMap::new(),
            subclasses: Vec::new(),
        }
    }

    pub fn with_end_line(mut self, end_line: u32) -> Self {
        self.end_line = end_line;
        self.line = end_line; // Update line for compatibility
        self
    }

    pub fn with_parent_classes(mut self, parent_classes: Vec<String>) -> Self {
        self.parent_classes = parent_classes;
        self
    }

    pub fn with_package(mut self, package: String) -> Self {
        self.package = package;
        self
    }

    pub fn with_modifiers(mut self, modifiers: Vec<String>) -> Self {
        self.modifiers = modifiers;
        self
    }

    pub fn with_fields(mut self, fields: Vec<Field>) -> Self {
        self.fields = fields;
        self
    }

    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn to_dict(&self) -> serde_json::Value {
        // Determine language from file extension
        let ext = std::path::Path::new(&self.file_path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        let language = match ext.as_str() {
            "rs" => "rust",
            "py" => "python",
            "js" => "javascript",
            "ts" | "tsx" => "typescript",
            _ => &ext,
        };

        // Generate ID
        let node_id = format!("{}:{}:{}", self.file_path, self.name, self.start_line);

        let node_type = match self.kind {
            SymbolKind::MethodCall => "MethodCall".to_string(),
            SymbolKind::Method => "Method".to_string(),
            SymbolKind::Function => "Function".to_string(),
            SymbolKind::Class => "Class".to_string(),
            SymbolKind::Interface => "Interface".to_string(),
            SymbolKind::Struct => "Struct".to_string(),
        };

        let mut meta = serde_json::Map::new();
        if matches!(self.kind, SymbolKind::Class | SymbolKind::Interface) {
            meta.insert(
                "superClasses".to_string(),
                serde_json::Value::String(self.parent_classes.join(", ")),
            );
        }
        // Add existing metadata
        for (k, v) in &self.metadata {
            meta.insert(k.clone(), v.clone());
        }

        serde_json::json!({
            "id": node_id,
            "language": language,
            "type": node_type,
            "name": self.name,
            "file": self.file_path,
            "package": self.package,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "code": self.code, // Keep for display
            "modifiers": self.modifiers,
            "fields": self.fields,
            "fullClassName": if self.package.is_empty() {
                self.name.clone()
            } else {
                format!("{}.{}", self.package, self.name)
            },
            "metadata": meta,
            // Compatibility fields for existing tools
            "kind": self.kind_to_string(),
            "line": self.start_line,
            "parent_classes": self.parent_classes,
            "subclasses": self.subclasses
        })
    }

    pub fn kind_to_string(&self) -> String {
        match self.kind {
            SymbolKind::Class => "class".to_string(),
            SymbolKind::Function => "function".to_string(),
            SymbolKind::Method => "method".to_string(),
            SymbolKind::MethodCall => "method_call".to_string(),
            SymbolKind::Interface => "interface".to_string(),
            SymbolKind::Struct => "struct".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub field_type: String,
    pub start_line: u32,
    pub end_line: u32,
    pub modifiers: Vec<String>,
    pub metadata: HashMap<String, serde_json::Value>,
}
