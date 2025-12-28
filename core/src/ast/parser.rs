use crate::ast::symbol::{Field, Symbol, SymbolKind};
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Language, Node, Parser, Query};

pub struct ASTParser {
    parsers: HashMap<String, Parser>,
}

impl ASTParser {
    pub fn new() -> Self {
        let mut parsers = HashMap::new();

        // Initialize parsers for supported languages
        let supported_extensions: Vec<(&str, Language)> = vec![
            (".js", tree_sitter_javascript::LANGUAGE.into()),
            (".jsx", tree_sitter_javascript::LANGUAGE.into()),
            (".py", tree_sitter_python::LANGUAGE.into()),
            (".java", tree_sitter_java::LANGUAGE.into()),
            (".rs", tree_sitter_rust::LANGUAGE.into()),
            (".go", tree_sitter_go::LANGUAGE.into()),
            (".ts", tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
            (".tsx", tree_sitter_typescript::LANGUAGE_TSX.into()),
            (".html", tree_sitter_html::LANGUAGE.into()),
            (".htm", tree_sitter_html::LANGUAGE.into()),
            (".vue", tree_sitter_html::LANGUAGE.into()),
            (".css", tree_sitter_css::LANGUAGE.into()),
            (".json", tree_sitter_json::LANGUAGE.into()),
            (".c", tree_sitter_c::LANGUAGE.into()),
            (".h", tree_sitter_c::LANGUAGE.into()),
            (".cpp", tree_sitter_cpp::LANGUAGE.into()),
            (".hpp", tree_sitter_cpp::LANGUAGE.into()),
            (".cc", tree_sitter_cpp::LANGUAGE.into()),
        ];

        for (ext, language) in supported_extensions {
            let mut parser = Parser::new();
            if let Err(_) = parser.set_language(&language) {
                log::warn!("Failed to load parser for extension: {}", ext);
                continue;
            }
            parsers.insert(ext.to_string(), parser);
        }

        Self { parsers }
    }

    pub fn parse_file(&mut self, file_path: &Path, content: &str) -> Result<Vec<Symbol>, String> {
        let ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s))
            .unwrap_or_default();

        let parser = self
            .parsers
            .get_mut(&ext)
            .ok_or_else(|| format!("Unsupported file extension: {}", ext))?;

        let tree = parser
            .parse(content, None)
            .ok_or_else(|| "Failed to parse file".to_string())?;

        let root_node = tree.root_node();

        match ext.as_str() {
            ".java" => self.extract_java_symbols(file_path, content, root_node),
            ".py" => self.extract_python_symbols(file_path, content, root_node),
            ".rs" => self.extract_rust_symbols(file_path, content, root_node),
            ".ts" | ".tsx" => self.extract_typescript_symbols(file_path, content, root_node),
            ".js" | ".jsx" => self.extract_javascript_symbols(file_path, content, root_node),
            _ => self.extract_generic_symbols(file_path, content, &ext, root_node),
        }
    }

    fn extract_java_symbols(
        &self,
        file_path: &Path,
        content: &str,
        root_node: Node,
    ) -> Result<Vec<Symbol>, String> {
        let mut symbols = Vec::new();
        let mut package_name = String::new();

        // Find package declaration
        let language: Language = tree_sitter_java::LANGUAGE.into();
        let query = Query::new(&language, "(package_declaration (scoped_identifier) @name)")
            .map_err(|e| format!("Query error: {}", e))?;

        let mut cursor = tree_sitter::QueryCursor::new();
        let matches = cursor.matches(&query, root_node, content.as_bytes());
        for m in matches {
            for capture in m.captures {
                if capture.index == 0 {
                    package_name = content[capture.node.byte_range()].to_string();
                    break;
                }
            }
        }

        let mut class_stack: Vec<String> = Vec::new();
        let mut method_stack: Vec<String> = Vec::new();

        fn visit_node(
            node: Node,
            content: &str,
            file_path: &Path,
            symbols: &mut Vec<Symbol>,
            class_stack: &mut Vec<String>,
            method_stack: &mut Vec<String>,
            package_name: &str,
        ) {
            match node.kind() {
                "class_declaration" | "interface_declaration" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();
                        class_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 500 {
                            format!("{}...", &code[..500])
                        } else {
                            code
                        };

                        let kind = if node.kind() == "class_declaration" {
                            SymbolKind::Class
                        } else {
                            SymbolKind::Interface
                        };

                        // Extract modifiers
                        let mut modifiers = Vec::new();
                        if let Some(modifiers_node) = node.child_by_field_name("modifiers") {
                            for child in modifiers_node.children(&mut modifiers_node.walk()) {
                                modifiers.push(content[child.byte_range()].to_string());
                            }
                        }

                        // Extract superclass
                        let mut parent_classes = Vec::new();
                        if let Some(super_node) = node.child_by_field_name("superclass") {
                            parent_classes.push(content[super_node.byte_range()].to_string());
                        }

                        // Extract interfaces
                        if let Some(interfaces_node) = node.child_by_field_name("interfaces") {
                            let interfaces_text = content[interfaces_node.byte_range()].to_string();
                            for interface in interfaces_text.split(',').map(|s| s.trim()) {
                                if !interface.is_empty() {
                                    parent_classes.push(interface.to_string());
                                }
                            }
                        }

                        // Extract fields
                        let mut fields = Vec::new();
                        if let Some(body_node) = node.child_by_field_name("body") {
                            for child in body_node.children(&mut body_node.walk()) {
                                if child.kind() == "field_declaration" {
                                    if let Ok(field) = extract_java_field(&child, content) {
                                        fields.push(field);
                                    }
                                }
                            }
                        }

                        let symbol = Symbol::new(
                            name,
                            kind,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32)
                        .with_package(package_name.to_string())
                        .with_modifiers(modifiers)
                        .with_parent_classes(parent_classes)
                        .with_fields(fields);

                        symbols.push(symbol);
                    }
                }
                "method_declaration" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();
                        method_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 300 {
                            format!("{}...", &code[..300])
                        } else {
                            code
                        };

                        let mut metadata = HashMap::new();
                        if let Some(class_name) = class_stack.last() {
                            metadata.insert(
                                "ownerClass".to_string(),
                                serde_json::Value::String(class_name.clone()),
                            );
                        }

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Method,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32)
                        .with_package(package_name.to_string())
                        .with_metadata(metadata);

                        symbols.push(symbol);
                    }
                }
                "method_invocation" => {
                    let name = extract_method_name(&node, content);
                    if !name.is_empty() {
                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            format!("{}...", &code[..200])
                        } else {
                            code
                        };

                        let mut metadata = HashMap::new();
                        if let Some(class_name) = class_stack.last() {
                            metadata.insert(
                                "callerClass".to_string(),
                                serde_json::Value::String(class_name.clone()),
                            );
                        }
                        if let Some(method_name) = method_stack.last() {
                            metadata.insert(
                                "callerMethod".to_string(),
                                serde_json::Value::String(method_name.clone()),
                            );
                        }

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::MethodCall,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32)
                        .with_package(package_name.to_string())
                        .with_metadata(metadata);

                        symbols.push(symbol);
                    }
                }
                _ => {}
            }

            for child in node.children(&mut node.walk()) {
                visit_node(
                    child,
                    content,
                    file_path,
                    symbols,
                    class_stack,
                    method_stack,
                    package_name,
                );
            }

            if node.kind() == "class_declaration" || node.kind() == "interface_declaration" {
                class_stack.pop();
            }
            if node.kind() == "method_declaration" {
                method_stack.pop();
            }
        }

        visit_node(
            root_node,
            content,
            file_path,
            &mut symbols,
            &mut class_stack,
            &mut method_stack,
            &package_name,
        );
        Ok(symbols)
    }

    fn extract_python_symbols(
        &self,
        file_path: &Path,
        content: &str,
        root_node: Node,
    ) -> Result<Vec<Symbol>, String> {
        let mut symbols = Vec::new();
        let mut class_stack: Vec<String> = Vec::new();
        let mut func_stack: Vec<String> = Vec::new();

        fn visit_node(
            node: Node,
            content: &str,
            file_path: &Path,
            symbols: &mut Vec<Symbol>,
            class_stack: &mut Vec<String>,
            func_stack: &mut Vec<String>,
        ) {
            match node.kind() {
                "class_definition" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();
                        class_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            format!("{}...", &code[..200])
                        } else {
                            code
                        };

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Class,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32);

                        symbols.push(symbol);
                    }
                }
                "function_definition" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();
                        func_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            format!("{}...", &code[..200])
                        } else {
                            code
                        };

                        let kind = if class_stack.is_empty() {
                            SymbolKind::Function
                        } else {
                            SymbolKind::Method
                        };

                        let mut metadata = HashMap::new();
                        if let Some(class_name) = class_stack.last() {
                            metadata.insert(
                                "ownerClass".to_string(),
                                serde_json::Value::String(class_name.clone()),
                            );
                        }
                        if let Some(func_name) = func_stack.last() {
                            metadata.insert(
                                "callerFunction".to_string(),
                                serde_json::Value::String(func_name.clone()),
                            );
                        }

                        let symbol = Symbol::new(
                            name,
                            kind,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32)
                        .with_metadata(metadata);

                        symbols.push(symbol);
                    }
                }
                "call" => {
                    if let Some(function_node) = node.child_by_field_name("function") {
                        let name = extract_last_name(&function_node, content);
                        if !name.is_empty() {
                            let start_line = node.start_position().row + 1;
                            let end_line = node.end_position().row + 1;
                            let code = content[node.byte_range()].to_string();
                            let code = if code.len() > 200 {
                                format!("{}...", &code[..200])
                            } else {
                                code
                            };

                            let mut metadata = HashMap::new();
                            if let Some(class_name) = class_stack.last() {
                                metadata.insert(
                                    "callerClass".to_string(),
                                    serde_json::Value::String(class_name.clone()),
                                );
                            }
                            if let Some(func_name) = func_stack.last() {
                                metadata.insert(
                                    "callerFunction".to_string(),
                                    serde_json::Value::String(func_name.clone()),
                                );
                            }

                            let symbol = Symbol::new(
                                name,
                                SymbolKind::MethodCall,
                                file_path.to_string_lossy().to_string(),
                                start_line as u32,
                                code,
                            )
                            .with_end_line(end_line as u32)
                            .with_metadata(metadata);

                            symbols.push(symbol);
                        }
                    }
                }
                _ => {}
            }

            for child in node.children(&mut node.walk()) {
                visit_node(child, content, file_path, symbols, class_stack, func_stack);
            }

            if node.kind() == "class_definition" {
                class_stack.pop();
            }
            if node.kind() == "function_definition" {
                func_stack.pop();
            }
        }

        visit_node(
            root_node,
            content,
            file_path,
            &mut symbols,
            &mut class_stack,
            &mut func_stack,
        );
        Ok(symbols)
    }

    fn extract_rust_symbols(
        &self,
        file_path: &Path,
        content: &str,
        root_node: Node,
    ) -> Result<Vec<Symbol>, String> {
        let mut symbols = Vec::new();
        let mut func_stack: Vec<String> = Vec::new();

        fn visit_node(
            node: Node,
            content: &str,
            file_path: &Path,
            symbols: &mut Vec<Symbol>,
            func_stack: &mut Vec<String>,
        ) {
            match node.kind() {
                "struct_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            format!("{}...", &code[..200])
                        } else {
                            code
                        };

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Struct,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32);

                        symbols.push(symbol);
                    }
                }
                "function_item" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();
                        func_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            format!("{}...", &code[..200])
                        } else {
                            code
                        };

                        let mut metadata = HashMap::new();
                        if let Some(func_name) = func_stack.last() {
                            metadata.insert(
                                "callerFunction".to_string(),
                                serde_json::Value::String(func_name.clone()),
                            );
                        }

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Function,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32)
                        .with_metadata(metadata);

                        symbols.push(symbol);
                    }
                }
                "call_expression" => {
                    if let Some(function_node) = node.child_by_field_name("function") {
                        let name = extract_last_name(&function_node, content);
                        if !name.is_empty() {
                            let start_line = node.start_position().row + 1;
                            let end_line = node.end_position().row + 1;
                            let code = content[node.byte_range()].to_string();
                            let code = if code.len() > 200 {
                                format!("{}...", &code[..200])
                            } else {
                                code
                            };

                            let mut metadata = HashMap::new();
                            if let Some(func_name) = func_stack.last() {
                                metadata.insert(
                                    "callerFunction".to_string(),
                                    serde_json::Value::String(func_name.clone()),
                                );
                            }

                            let symbol = Symbol::new(
                                name,
                                SymbolKind::MethodCall,
                                file_path.to_string_lossy().to_string(),
                                start_line as u32,
                                code,
                            )
                            .with_end_line(end_line as u32)
                            .with_metadata(metadata);

                            symbols.push(symbol);
                        }
                    }
                }
                _ => {}
            }

            for child in node.children(&mut node.walk()) {
                visit_node(child, content, file_path, symbols, func_stack);
            }

            if node.kind() == "function_item" {
                func_stack.pop();
            }
        }

        visit_node(root_node, content, file_path, &mut symbols, &mut func_stack);
        Ok(symbols)
    }

    fn extract_typescript_symbols(
        &self,
        file_path: &Path,
        content: &str,
        root_node: Node,
    ) -> Result<Vec<Symbol>, String> {
        // Similar to JavaScript but with TypeScript-specific features
        self.extract_javascript_symbols(file_path, content, root_node)
    }

    fn extract_javascript_symbols(
        &self,
        file_path: &Path,
        content: &str,
        root_node: Node,
    ) -> Result<Vec<Symbol>, String> {
        let mut symbols = Vec::new();
        let mut class_stack: Vec<String> = Vec::new();
        let mut func_stack: Vec<String> = Vec::new();

        fn visit_node(
            node: Node,
            content: &str,
            file_path: &Path,
            symbols: &mut Vec<Symbol>,
            class_stack: &mut Vec<String>,
            func_stack: &mut Vec<String>,
        ) {
            match node.kind() {
                "class_declaration" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();
                        class_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            format!("{}...", &code[..200])
                        } else {
                            code
                        };

                        let symbol = Symbol::new(
                            name,
                            SymbolKind::Class,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32);

                        symbols.push(symbol);
                    }
                }
                "function_declaration" | "method_definition" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();
                        func_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            format!("{}...", &code[..200])
                        } else {
                            code
                        };

                        let kind = if class_stack.is_empty() {
                            SymbolKind::Function
                        } else {
                            SymbolKind::Method
                        };

                        let mut metadata = HashMap::new();
                        if let Some(class_name) = class_stack.last() {
                            metadata.insert(
                                "callerClass".to_string(),
                                serde_json::Value::String(class_name.clone()),
                            );
                        }
                        if let Some(func_name) = func_stack.last() {
                            metadata.insert(
                                "callerFunction".to_string(),
                                serde_json::Value::String(func_name.clone()),
                            );
                        }

                        let symbol = Symbol::new(
                            name,
                            kind,
                            file_path.to_string_lossy().to_string(),
                            start_line as u32,
                            code,
                        )
                        .with_end_line(end_line as u32)
                        .with_metadata(metadata);

                        symbols.push(symbol);
                    }
                }
                "call_expression" => {
                    if let Some(function_node) = node.child_by_field_name("function") {
                        let name = extract_last_name(&function_node, content);
                        if !name.is_empty() {
                            let start_line = node.start_position().row + 1;
                            let end_line = node.end_position().row + 1;
                            let code = content[node.byte_range()].to_string();
                            let code = if code.len() > 200 {
                                format!("{}...", &code[..200])
                            } else {
                                code
                            };

                            let mut metadata = HashMap::new();
                            if let Some(class_name) = class_stack.last() {
                                metadata.insert(
                                    "callerClass".to_string(),
                                    serde_json::Value::String(class_name.clone()),
                                );
                            }
                            if let Some(func_name) = func_stack.last() {
                                metadata.insert(
                                    "callerFunction".to_string(),
                                    serde_json::Value::String(func_name.clone()),
                                );
                            }

                            let symbol = Symbol::new(
                                name,
                                SymbolKind::MethodCall,
                                file_path.to_string_lossy().to_string(),
                                start_line as u32,
                                code,
                            )
                            .with_end_line(end_line as u32)
                            .with_metadata(metadata);

                            symbols.push(symbol);
                        }
                    }
                }
                _ => {}
            }

            for child in node.children(&mut node.walk()) {
                visit_node(child, content, file_path, symbols, class_stack, func_stack);
            }

            if node.kind() == "class_declaration" {
                class_stack.pop();
            }
            if node.kind() == "function_declaration" || node.kind() == "method_definition" {
                func_stack.pop();
            }
        }

        visit_node(
            root_node,
            content,
            file_path,
            &mut symbols,
            &mut class_stack,
            &mut func_stack,
        );
        Ok(symbols)
    }

    fn extract_generic_symbols(
        &self,
        _file_path: &Path,
        _content: &str,
        _ext: &str,
        _root_node: Node,
    ) -> Result<Vec<Symbol>, String> {
        // Fallback for unsupported languages - just extract basic structure
        let symbols = Vec::new();

        // This is a simplified implementation
        // In a real scenario, you'd want to implement language-specific parsers
        Ok(symbols)
    }
}

fn extract_java_field(node: &Node, content: &str) -> Result<Field, String> {
    if let Some(name_node) = node.child_by_field_name("declarator") {
        if let Some(name_node) = name_node.child_by_field_name("name") {
            let name = content[name_node.byte_range()].to_string();

            let field_type = if let Some(type_node) = node.child_by_field_name("type") {
                content[type_node.byte_range()].to_string()
            } else {
                "Unknown".to_string()
            };

            let start_line = node.start_position().row + 1;
            let end_line = node.end_position().row + 1;

            let mut modifiers = Vec::new();
            if let Some(modifiers_node) = node.child_by_field_name("modifiers") {
                for child in modifiers_node.children(&mut modifiers_node.walk()) {
                    modifiers.push(content[child.byte_range()].to_string());
                }
            }

            let mut metadata = HashMap::new();
            metadata.insert(
                "fullType".to_string(),
                serde_json::Value::String(field_type.clone()),
            );

            Ok(Field {
                name,
                field_type,
                start_line: start_line as u32,
                end_line: end_line as u32,
                modifiers,
                metadata,
            })
        } else {
            Err("Could not extract field name".to_string())
        }
    } else {
        Err("Could not extract field declarator".to_string())
    }
}

fn extract_method_name(node: &Node, content: &str) -> String {
    if let Some(name_node) = node.child_by_field_name("name") {
        content[name_node.byte_range()].to_string()
    } else {
        extract_last_name(node, content)
    }
}

fn extract_last_name(node: &Node, content: &str) -> String {
    let text = content[node.byte_range()].to_string();
    let text = text.trim();

    if text.is_empty() {
        return String::new();
    }

    // Handle different access patterns
    let text = text
        .replace("?.", ".")
        .replace("::", ".")
        .replace("->", ".");

    // Get the last part after splitting by dots
    text.split('.').last().unwrap_or(&text).to_string()
}
