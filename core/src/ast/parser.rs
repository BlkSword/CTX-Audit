use crate::ast::symbol::{
    ArgInfo, Assignment, CallInfo, CallbackArg, Field, FunctionBody, NodeInfo, ReturnInfo, Symbol,
    SymbolKind,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use tree_sitter::{Language, Node, Parser, Query};

/// 线程本地 ASTParser 池
///
/// tree-sitter Parser 初始化（set_language）成本较高，
/// 每个线程保持一份复用，可显著降低多文件解析开销。
thread_local! {
    static THREAD_LOCAL_PARSER: RefCell<ASTParser> = RefCell::new(ASTParser::new());
}

/// 在线程本地 ASTParser 上执行操作
pub fn with_thread_local_parser<F, R>(f: F) -> R
where
    F: FnOnce(&mut ASTParser) -> R,
{
    THREAD_LOCAL_PARSER.with(|p| f(&mut *p.borrow_mut()))
}

/// Safely truncate a string to a maximum byte length, respecting UTF-8 character boundaries.
/// This prevents panics when the truncation point falls inside a multi-byte character.
fn truncate_string_safe(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }

    // Find the character boundary at or before max_bytes
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }

    if boundary == 0 {
        return String::new();
    }

    format!("{}...", &s[..boundary])
}

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

    /// 解析一段代码片段（如函数体文本），返回 tree-sitter Tree。
    ///
    /// 用于函数级并行场景：由于 tree-sitter Node 不能跨线程，每个任务单独解析函数体，
    /// 得到局部 Tree 后再构建 CFG，避免使用较慢的 text-based CFG。
    pub fn parse_fragment(&mut self, code: &str, ext: &str) -> Option<tree_sitter::Tree> {
        let key = format!(".{}", ext);
        self.parsers.get_mut(&key)?.parse(code, None)
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
            // 追踪本次访问是否向类栈中压入新作用域（含匿名类），用于在访问完子树后弹出。
            let mut pushed_class = false;

            match node.kind() {
                "class_declaration" | "interface_declaration" => {
                    if let Some(name_node) = node.child_by_field_name("name") {
                        let name = content[name_node.byte_range()].to_string();
                        class_stack.push(name.clone());
                        pushed_class = true;

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 500 {
                            truncate_string_safe(&code, 497) // 497 + 3 for "..."
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
                "object_creation_expression" => {
                    // Java 匿名类：new SomeType() { ... }，其 method_declaration 需要独立作用域
                    let has_class_body = node
                        .children(&mut node.walk())
                        .any(|child| child.kind() == "class_body");
                    if has_class_body {
                        let anon_name = format!("<anonymous@{}>", node.start_position().row + 1);
                        class_stack.push(anon_name);
                        pushed_class = true;
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
                            truncate_string_safe(&code, 297) // 297 + 3 for "..."
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

                        // 提取方法参数名，供 Stage C 调用图构建使用
                        if let Some(params_node) = node.child_by_field_name("parameters") {
                            let param_names: Vec<serde_json::Value> =
                                ASTParser::extract_param_names(&params_node, content)
                                    .into_iter()
                                    .map(serde_json::Value::String)
                                    .collect();
                            if !param_names.is_empty() {
                                metadata.insert(
                                    "params".to_string(),
                                    serde_json::Value::Array(param_names),
                                );
                            }
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
                            truncate_string_safe(&code, 197) // 197 + 3 for "..."
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

            if pushed_class {
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
                            truncate_string_safe(&code, 197) // 197 + 3 for "..."
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

                        // Read the caller BEFORE pushing the function name onto the stack
                        let caller = func_stack.last().cloned().unwrap_or_default();

                        func_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            truncate_string_safe(&code, 197) // 197 + 3 for "..."
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
                        if !caller.is_empty() {
                            metadata.insert(
                                "callerFunction".to_string(),
                                serde_json::Value::String(caller),
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
                                truncate_string_safe(&code, 197) // 197 + 3 for "..."
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
                            truncate_string_safe(&code, 197) // 197 + 3 for "..."
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

                        // Read the caller BEFORE pushing the function name onto the stack
                        let caller = func_stack.last().cloned().unwrap_or_default();

                        func_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            truncate_string_safe(&code, 197) // 197 + 3 for "..."
                        } else {
                            code
                        };

                        let mut metadata = HashMap::new();
                        if !caller.is_empty() {
                            metadata.insert(
                                "callerFunction".to_string(),
                                serde_json::Value::String(caller),
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
                                truncate_string_safe(&code, 197) // 197 + 3 for "..."
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
                            truncate_string_safe(&code, 197) // 197 + 3 for "..."
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

                        // Read the caller BEFORE pushing the function name onto the stack
                        let caller = func_stack.last().cloned().unwrap_or_default();

                        func_stack.push(name.clone());

                        let start_line = node.start_position().row + 1;
                        let end_line = node.end_position().row + 1;
                        let code = content[node.byte_range()].to_string();
                        let code = if code.len() > 200 {
                            truncate_string_safe(&code, 197) // 197 + 3 for "..."
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
                        if !caller.is_empty() {
                            metadata.insert(
                                "callerFunction".to_string(),
                                serde_json::Value::String(caller),
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
                "assignment_expression" => {
                    // 处理 this.method = (args) => {} / obj.method = function() {} 模式
                    // Node.js 最常见的模块/类方法定义；原 extract_javascript_symbols 只认
                    // function_declaration|method_definition，导致大量方法漏提取
                    // （NodeGoat user-dao.js 2/7，research.js 1/1）。
                    if let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) {
                        let rk = right.kind();
                        if (rk == "arrow_function" || rk == "function_expression")
                            && left.kind() == "member_expression"
                        {
                            let method_name = extract_last_name(&left, content);
                            if !method_name.is_empty() && method_name != "this" {
                                let start_line = right.start_position().row + 1;
                                let end_line = right.end_position().row + 1;
                                let code = content[node.byte_range()].to_string();
                                let code = if code.len() > 200 {
                                    truncate_string_safe(&code, 197)
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
                                    method_name,
                                    SymbolKind::Method,
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
                }
                "call_expression" => {
                    if let Some(function_node) = node.child_by_field_name("function") {
                        let name = extract_last_name(&function_node, content);
                        if !name.is_empty() {
                            let start_line = node.start_position().row + 1;
                            let end_line = node.end_position().row + 1;
                            let code = content[node.byte_range()].to_string();
                            let code = if code.len() > 200 {
                                truncate_string_safe(&code, 197) // 197 + 3 for "..."
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

    // ============================================================
    // 细粒度 AST 提取方法（用于污点分析）
    // ============================================================

    /// 提取文件中的所有赋值语句
    pub fn extract_assignments(&mut self, file_path: &Path, content: &str) -> Vec<Assignment> {
        let ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s))
            .unwrap_or_default();

        let parser = match self.parsers.get_mut(&ext) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let root = tree.root_node();
        let mut assignments = Vec::new();
        Self::collect_assignments_generic(&root, content, &mut assignments);
        assignments
    }

    /// 提取文件中的所有函数调用
    pub fn extract_calls(&mut self, file_path: &Path, content: &str) -> Vec<CallInfo> {
        let ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s))
            .unwrap_or_default();

        let parser = match self.parsers.get_mut(&ext) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let root = tree.root_node();
        let mut calls = Vec::new();
        Self::collect_calls_recursive(&root, content, &mut calls);
        calls
    }

    /// 提取文件中的所有返回语句
    pub fn extract_returns(&mut self, file_path: &Path, content: &str) -> Vec<ReturnInfo> {
        let ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s))
            .unwrap_or_default();

        let parser = match self.parsers.get_mut(&ext) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let root = tree.root_node();
        let mut returns = Vec::new();
        Self::collect_returns_recursive(&root, content, &mut returns);
        returns
    }

    /// 提取文件中的所有函数体（按函数粒度）
    pub fn extract_function_bodies(
        &mut self,
        file_path: &Path,
        content: &str,
    ) -> Vec<FunctionBody> {
        let ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s))
            .unwrap_or_default();

        let parser = match self.parsers.get_mut(&ext) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let root = tree.root_node();
        let mut bodies = Vec::new();
        Self::collect_function_bodies_recursive(&root, content, &mut bodies);
        bodies
    }

    /// 一次 AST 解析同时提取函数体、赋值和调用（避免重复解析）
    pub fn extract_all_for_taint(
        &mut self,
        file_path: &Path,
        content: &str,
    ) -> (Vec<FunctionBody>, Vec<Assignment>, Vec<CallInfo>) {
        if let Some((_, _symbols, bodies, assignments, calls)) =
            self.extract_all_for_taint_with_tree(file_path, content)
        {
            (bodies, assignments, calls)
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        }
    }

    /// 单次解析提取所有数据，同时返回 Tree 供 AST-based CFG 使用。
    /// 调用者必须在 Tree 存活期间使用任何从中派生的节点。
    /// 额外返回 symbols，供 Stage C 调用图构建复用，避免二次 parse。
    pub fn extract_all_for_taint_with_tree(
        &mut self,
        file_path: &Path,
        content: &str,
    ) -> Option<(
        tree_sitter::Tree,
        Vec<Symbol>,
        Vec<FunctionBody>,
        Vec<Assignment>,
        Vec<CallInfo>,
    )> {
        let ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s))
            .unwrap_or_default();

        let parser = match self.parsers.get_mut(&ext) {
            Some(p) => p,
            None => return None,
        };

        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return None,
        };

        let root = tree.root_node();

        let symbols = match ext.as_str() {
            ".java" => self
                .extract_java_symbols(file_path, content, root)
                .unwrap_or_default(),
            ".py" => self
                .extract_python_symbols(file_path, content, root)
                .unwrap_or_default(),
            ".rs" => self
                .extract_rust_symbols(file_path, content, root)
                .unwrap_or_default(),
            ".ts" | ".tsx" => self
                .extract_typescript_symbols(file_path, content, root)
                .unwrap_or_default(),
            ".js" | ".jsx" => self
                .extract_javascript_symbols(file_path, content, root)
                .unwrap_or_default(),
            _ => self
                .extract_generic_symbols(file_path, content, &ext, root)
                .unwrap_or_default(),
        };

        let mut bodies = Vec::new();
        Self::collect_function_bodies_recursive(&root, content, &mut bodies);

        let mut assignments = Vec::new();
        Self::collect_assignments_generic(&root, content, &mut assignments);

        let mut calls = Vec::new();
        Self::collect_calls_recursive(&root, content, &mut calls);

        Some((tree, symbols, bodies, assignments, calls))
    }

    fn collect_assignments_generic(node: &Node, content: &str, results: &mut Vec<Assignment>) {
        let kind = node.kind();
        if matches!(
            kind,
            "assignment_expression" | "assignment" | "augmented_assignment"
        ) {
            if let Some(lhs) = node.child_by_field_name("left") {
                if let Some(rhs) = node.child_by_field_name("right") {
                    let target = content[lhs.byte_range()].to_string();
                    let source_expr = content[rhs.byte_range()].to_string();
                    let source_vars = Self::collect_identifiers(&rhs, content);

                    results.push(Assignment {
                        target,
                        target_node: NodeInfo {
                            line: lhs.start_position().row + 1,
                            column: lhs.start_position().column,
                            byte_start: lhs.start_byte(),
                            byte_end: lhs.end_byte(),
                        },
                        source_expr,
                        source_vars,
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                    });
                }
            }
        }

        // let 声明（Rust）与 Go 短变量声明
        if matches!(kind, "let_declaration" | "let_statement") {
            if let Some(pattern) = node.child_by_field_name("pattern") {
                if let Some(value) = node.child_by_field_name("value") {
                    let target = content[pattern.byte_range()].to_string();
                    let source_expr = content[value.byte_range()].to_string();
                    let source_vars = Self::collect_identifiers(&value, content);

                    results.push(Assignment {
                        target,
                        target_node: NodeInfo {
                            line: pattern.start_position().row + 1,
                            column: pattern.start_position().column,
                            byte_start: pattern.start_byte(),
                            byte_end: pattern.end_byte(),
                        },
                        source_expr,
                        source_vars,
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                    });
                }
            }
        }

        // Go 短变量声明：id := expr
        if kind == "short_var_declaration" {
            if let Some(left) = node.child_by_field_name("left") {
                if let Some(right) = node.child_by_field_name("right") {
                    let target = content[left.byte_range()].to_string();
                    let source_expr = content[right.byte_range()].to_string();
                    let source_vars = Self::collect_identifiers(&right, content);

                    results.push(Assignment {
                        target,
                        target_node: NodeInfo {
                            line: left.start_position().row + 1,
                            column: left.start_position().column,
                            byte_start: left.start_byte(),
                            byte_end: left.end_byte(),
                        },
                        source_expr,
                        source_vars,
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                    });
                }
            }
        }

        // JS/TS const/let/var 声明（支持解构）
        // tree-sitter: lexical_declaration > variable_declarator > [name, value]
        if matches!(kind, "lexical_declaration" | "variable_declaration") {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Some(value_node) = child.child_by_field_name("value") {
                            let target = content[name_node.byte_range()].to_string();
                            let source_expr = content[value_node.byte_range()].to_string();
                            let source_vars = Self::collect_identifiers(&value_node, content);

                            results.push(Assignment {
                                target,
                                target_node: NodeInfo {
                                    line: name_node.start_position().row + 1,
                                    column: name_node.start_position().column,
                                    byte_start: name_node.start_byte(),
                                    byte_end: name_node.end_byte(),
                                },
                                source_expr,
                                source_vars,
                                line: child.start_position().row + 1,
                                column: child.start_position().column,
                            });
                        }
                    }
                }
            }
        }

        // Java 局部变量声明：Type name = value;
        if kind == "local_variable_declaration" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Some(value_node) = child.child_by_field_name("value") {
                            let target = content[name_node.byte_range()].to_string();
                            let source_expr = content[value_node.byte_range()].to_string();
                            let source_vars = Self::collect_identifiers(&value_node, content);

                            results.push(Assignment {
                                target,
                                target_node: NodeInfo {
                                    line: name_node.start_position().row + 1,
                                    column: name_node.start_position().column,
                                    byte_start: name_node.start_byte(),
                                    byte_end: name_node.end_byte(),
                                },
                                source_expr,
                                source_vars,
                                line: child.start_position().row + 1,
                                column: child.start_position().column,
                            });
                        }
                    }
                }
            }
        }

        // C/C++ 变量声明：Type name = value;
        if kind == "declaration" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "init_declarator" {
                    if let Some(declarator_node) = child.child_by_field_name("declarator") {
                        if let Some(value_node) = child.child_by_field_name("value") {
                            let target =
                                Self::extract_declarator_identifier(&declarator_node, content)
                                    .unwrap_or_else(|| {
                                        content[declarator_node.byte_range()].to_string()
                                    });
                            let source_expr = content[value_node.byte_range()].to_string();
                            let source_vars = Self::collect_identifiers(&value_node, content);

                            results.push(Assignment {
                                target,
                                target_node: NodeInfo {
                                    line: declarator_node.start_position().row + 1,
                                    column: declarator_node.start_position().column,
                                    byte_start: declarator_node.start_byte(),
                                    byte_end: declarator_node.end_byte(),
                                },
                                source_expr,
                                source_vars,
                                line: child.start_position().row + 1,
                                column: child.start_position().column,
                            });
                        }
                    }
                }
            }
        }

        // 递归遍历子节点
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::collect_assignments_generic(&child, content, results);
        }
    }

    /// 从 C/C++ 声明符中提取最内层标识符名。
    ///
    /// 例如 `char *user = argv[1];` 的声明符是 `pointer_declarator > identifier`，
    /// 需要返回 `"user"` 而非 `"*user"`，否则后续污点传播会把变量名识别错。
    fn extract_declarator_identifier(node: &Node, content: &str) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(content[node.byte_range()].to_string());
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(name) = Self::extract_declarator_identifier(&child, content) {
                return Some(name);
            }
        }
        None
    }

    fn collect_calls_recursive(node: &Node, content: &str, results: &mut Vec<CallInfo>) {
        let kind = node.kind();
        if matches!(
            kind,
            "call_expression"
                | "call"
                | "method_invocation"
                | "function_call"
                | "object_creation_expression"
        ) {
            let func_node = node
                .child_by_field_name("function")
                .or_else(|| node.child_by_field_name("name"))
                .or_else(|| node.child_by_field_name("type"));

            let args_node = node.child_by_field_name("arguments");

            if let Some(func_node) = func_node {
                let callee_text = content[func_node.byte_range()].to_string();

                // Java method_invocation 的字段在节点本身（object/name），
                // 而不是 function/name 子节点，需要特殊处理以保留接收者信息。
                // object_creation_expression 的构造函数名在 type 字段（如 File）。
                let (is_method, receiver, callee_name) = if kind == "method_invocation" {
                    let recv = node
                        .child_by_field_name("object")
                        .map(|n| content[n.byte_range()].to_string());
                    let name = node
                        .child_by_field_name("name")
                        .map(|n| content[n.byte_range()].to_string())
                        .unwrap_or_else(|| callee_text.clone());
                    (recv.is_some(), recv, name)
                } else if kind == "object_creation_expression" {
                    (false, None, callee_text)
                } else {
                    Self::parse_callee(&func_node, &callee_text, content)
                };

                let arguments = if let Some(args_node) = args_node {
                    Self::parse_arguments(&args_node, content)
                } else {
                    Vec::new()
                };

                // 检测回调参数（箭头函数、函数表达式等）
                let callback_args = if let Some(args_node) = args_node {
                    Self::detect_callback_args(&args_node, content)
                } else {
                    Vec::new()
                };

                results.push(CallInfo {
                    callee: callee_name,
                    arguments,
                    line: node.start_position().row + 1,
                    column: node.start_position().column,
                    is_method,
                    receiver,
                    callback_args,
                });
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::collect_calls_recursive(&child, content, results);
        }
    }

    fn parse_callee(
        func_node: &Node,
        callee_text: &str,
        content: &str,
    ) -> (bool, Option<String>, String) {
        let kind = func_node.kind();

        if kind == "member_expression"
            || kind == "attribute"
            || kind == "field_expression"
            || kind == "selector_expression"
        {
            // 不同语言对“对象.方法”的字段命名不同：
            // - JS/TS: member_expression -> object / property
            // - Python: attribute -> object / attribute
            // - Rust: field_expression -> value / field
            // - Go: selector_expression -> operand / field
            if let Some(obj) = func_node
                .child_by_field_name("object")
                .or_else(|| func_node.child_by_field_name("value"))
                .or_else(|| func_node.child_by_field_name("operand"))
            {
                if let Some(prop) = func_node
                    .child_by_field_name("field")
                    .or_else(|| func_node.child_by_field_name("property"))
                    .or_else(|| func_node.child_by_field_name("attribute"))
                {
                    let receiver = content[obj.byte_range()].to_string();
                    let method = content[prop.byte_range()].to_string();
                    return (true, Some(receiver), method);
                }
            }
        }

        (false, None, callee_text.to_string())
    }

    fn parse_arguments(args_node: &Node, content: &str) -> Vec<ArgInfo> {
        let mut args = Vec::new();
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            let kind = child.kind();
            if kind == "(" || kind == ")" || kind == "," || kind == "argument_list" {
                continue;
            }
            let text = content[child.byte_range()].to_string();
            if text.is_empty() || text == "(" || text == ")" {
                continue;
            }
            let referenced_vars = Self::collect_identifiers(&child, content);
            args.push(ArgInfo {
                text,
                referenced_vars,
            });
        }
        args
    }

    /// 检测调用参数中的内联回调函数（箭头函数、函数表达式等）
    fn detect_callback_args(args_node: &Node, content: &str) -> Vec<CallbackArg> {
        let mut callbacks = Vec::new();
        let mut cursor = args_node.walk();
        for child in args_node.children(&mut cursor) {
            let kind = child.kind();
            if kind == "(" || kind == ")" || kind == "," || kind == "argument_list" {
                continue;
            }

            // JS/TS: arrow_function, function_expression, function_declaration
            // Python: lambda, function_definition (nested def)
            // Java: lambda_expression
            let is_callback = matches!(
                kind,
                "arrow_function"
                    | "function_expression"
                    | "function_declaration"
                    | "function_definition"
                    | "lambda"
                    | "lambda_expression"
            );

            if is_callback {
                let params = Self::extract_callback_params(&child, content, kind);
                let start_line = child.start_position().row + 1;
                let end_line = child.end_position().row + 1;
                let byte_range = child.byte_range();
                let body_range = (byte_range.start, byte_range.end);
                let body_text = content[byte_range].to_string();
                // 截断至 500 字符
                let body_text = if body_text.len() > 500 {
                    format!("{}...", &body_text[..500])
                } else {
                    body_text
                };

                callbacks.push(CallbackArg {
                    params,
                    start_line,
                    end_line,
                    body_range,
                    body_text,
                });
            }
        }
        callbacks
    }

    /// 从回调 AST 节点中提取参数名列表
    fn extract_callback_params(node: &Node, content: &str, kind: &str) -> Vec<String> {
        // 查找 parameters / formal_parameters 子节点
        let params_node = node
            .child_by_field_name("parameters")
            .or_else(|| node.child_by_field_name("params"));

        if let Some(params_node) = params_node {
            let mut params = Vec::new();
            let mut cursor = params_node.walk();
            let param_kinds = if kind == "lambda" || kind == "lambda_expression" {
                // lambda 的参数可能是裸标识符，不是嵌套在 parameter 节点中
                Self::collect_lambda_params(&params_node, content)
            } else {
                for child in params_node.children(&mut cursor) {
                    let ck = child.kind();
                    if ck == "(" || ck == ")" || ck == "," {
                        continue;
                    }
                    // JS/TS: "identifier" 在 "required_parameter" / "optional_parameter" 内
                    // Python: "identifier" 在 "typed_parameter" / "default_parameter" 内
                    // 提取最内层的标识符
                    Self::extract_identifier_text(&child, content)
                        .into_iter()
                        .for_each(|p| params.push(p));
                }
                params
            };
            param_kinds
        } else {
            Vec::new()
        }
    }

    /// 提取 Python lambda 的参数（lambda x, y: expr → params = ["x", "y"]）
    fn collect_lambda_params(params_node: &Node, content: &str) -> Vec<String> {
        let mut params = Vec::new();
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            if child.kind() == "identifier" {
                params.push(content[child.byte_range()].to_string());
            }
        }
        params
    }

    /// 从参数子节点中提取标识符文本
    fn extract_identifier_text(node: &Node, content: &str) -> Vec<String> {
        let mut names = Vec::new();
        if node.kind() == "identifier" {
            names.push(content[node.byte_range()].to_string());
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            names.extend(Self::extract_identifier_text(&child, content));
        }
        names
    }

    fn collect_returns_recursive(node: &Node, content: &str, results: &mut Vec<ReturnInfo>) {
        let kind = node.kind();
        if matches!(kind, "return_statement" | "return") {
            let expr = content[node.byte_range()].to_string();
            let referenced_vars = Self::collect_identifiers(node, content);
            results.push(ReturnInfo {
                expr,
                referenced_vars,
                line: node.start_position().row + 1,
            });
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::collect_returns_recursive(&child, content, results);
        }
    }

    fn collect_function_bodies_recursive(
        node: &Node,
        content: &str,
        results: &mut Vec<FunctionBody>,
    ) {
        let kind = node.kind();

        // Unwrap export_statement: recurse into children to find the actual function.
        // e.g. "export default function handler(req, res) { ... }"
        if kind == "export_statement" || kind == "export_default_expression" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let ck = child.kind();
                if ck != "export" && ck != "default" {
                    Self::collect_function_bodies_recursive(&child, content, results);
                }
            }
            return;
        }

        // Unwrap lexical_declaration / variable_declaration to find arrow_function
        // e.g. "const handler = (req, res) => { ... }"
        if kind == "lexical_declaration" || kind == "variable_declaration" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(value) = child.child_by_field_name("value") {
                        let vk = value.kind();
                        if vk == "arrow_function" || vk == "function_expression" {
                            Self::collect_function_bodies_recursive(&value, content, results);
                        }
                    }
                }
            }
            return;
        }

        // Unwrap assignment_expression to find this.method = arrow_function / obj.method = function
        // e.g. "this.displayResearch = (req, res) => { ... }"
        // This is the most common module method pattern in Node.js; without it,
        // taint analysis misses every method defined via assignment.
        if kind == "assignment_expression" {
            if let Some(left) = node.child_by_field_name("left") {
                if let Some(right) = node.child_by_field_name("right") {
                    let rk = right.kind();
                    if rk == "arrow_function" || rk == "function_expression" {
                        // Extract method name from left side for the FunctionBody name
                        let method_name = extract_last_name(&left, content);
                        if !method_name.is_empty() && method_name != "this" {
                            let typed_params = if let Some(params_node) =
                                right.child_by_field_name("parameters")
                            {
                                Self::extract_typed_params(&params_node, content)
                            } else {
                                Vec::new()
                            };
                            let params: Vec<String> =
                                typed_params.iter().map(|tp| tp.name.clone()).collect();

                            let body_node = right.child_by_field_name("body");
                            let (body_text, body_start_line) = if let Some(body) = body_node {
                                (
                                    content[body.byte_range()].to_string(),
                                    body.start_position().row + 1,
                                )
                            } else {
                                (
                                    content[right.byte_range()].to_string(),
                                    right.start_position().row + 1,
                                )
                            };

                            results.push(FunctionBody {
                                name: method_name,
                                params,
                                start_line: right.start_position().row + 1,
                                end_line: right.end_position().row + 1,
                                body_start_line,
                                body_text,
                                typed_params,
                            });
                            // Recurse into the body to find nested callbacks (e.g., HTTP response callbacks)
                            if let Some(body_node) = right.child_by_field_name("body") {
                                Self::collect_function_bodies_recursive(
                                    &body_node, content, results,
                                );
                            }
                            return; // Don't recurse further — already extracted the function
                        }
                    }
                }
            }
        }

        let is_function = matches!(
            kind,
            "function_declaration"
                | "function"
                | "function_definition"
                | "method_declaration"
                | "function_item"
                | "method_definition"
                | "arrow_function"
                | "generator_function_declaration"
                | "function_expression"
        );

        if is_function {
            let name = node
                .child_by_field_name("name")
                .map(|n| content[n.byte_range()].to_string())
                .unwrap_or_else(|| format!("<anonymous@{}>", node.start_position().row + 1));

            let typed_params = if let Some(params_node) = node.child_by_field_name("parameters") {
                Self::extract_typed_params(&params_node, content)
            } else {
                Vec::new()
            };
            let params: Vec<String> = typed_params.iter().map(|tp| tp.name.clone()).collect();

            let body_node = node.child_by_field_name("body");
            let (body_text, body_start_line) = if let Some(body) = body_node {
                (
                    content[body.byte_range()].to_string(),
                    body.start_position().row + 1,
                )
            } else {
                (
                    content[node.byte_range()].to_string(),
                    node.start_position().row + 1,
                )
            };

            // 使用函数声明节点的起止行号，以便上层通过 AST 定位到完整函数节点
            // （body 的起止行号会导致 AST-based CFG 无法匹配）。
            results.push(FunctionBody {
                name,
                params,
                start_line: node.start_position().row + 1,
                end_line: node.end_position().row + 1,
                body_start_line,
                body_text,
                typed_params,
            });
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::collect_function_bodies_recursive(&child, content, results);
        }
    }

    fn extract_param_names(params_node: &Node, content: &str) -> Vec<String> {
        Self::extract_typed_params(params_node, content)
            .into_iter()
            .map(|tp| tp.name)
            .collect()
    }

    /// 提取带类型注解的参数列表
    fn extract_typed_params(
        params_node: &Node,
        content: &str,
    ) -> Vec<crate::ast::symbol::TypedParam> {
        use crate::ast::symbol::TypedParam;
        let mut params = Vec::new();
        let mut cursor = params_node.walk();
        for child in params_node.children(&mut cursor) {
            let kind = child.kind();
            if matches!(
                kind,
                "identifier"
                    | "typed_identifier"
                    | "parameter"
                    | "simple_parameter"
                    | "default_parameter"
                    | "identifier_pattern"
                    | "required_parameter"
                    | "optional_parameter"
                    | "rest_parameter"
                    | "pattern"
                    | "formal_parameter"
                    | "spread_parameter"
            ) {
                let name = child
                    .child_by_field_name("name")
                    .map(|n| content[n.byte_range()].to_string())
                    .unwrap_or_else(|| {
                        let text = content[child.byte_range()].to_string();
                        text.split(':').next().unwrap_or(&text).trim().to_string()
                    });

                // 提取类型注解
                let type_annotation = Self::extract_type_annotation(&child, content);

                // 提取参数注解（如 Java 的 @RequestParam）
                let annotations = Self::extract_parameter_annotations(&child, content);

                if !name.is_empty() && name != "self" && name != "this" {
                    params.push(TypedParam {
                        name,
                        type_annotation,
                        annotations,
                    });
                }
            }
        }
        params
    }

    /// 从参数节点中提取类型注解
    fn extract_type_annotation(param_node: &Node, content: &str) -> Option<String> {
        // TypeScript: required_parameter → identifier : type_annotation → type_identifier
        // Python: typed_identifier → name : type
        // Java: formal_parameter → modifiers type identifier
        let text = content[param_node.byte_range()].to_string();

        // Java / Go / Rust 等：类型是直接子节点
        let mut cursor = param_node.walk();
        for child in param_node.children(&mut cursor) {
            let kind = child.kind();
            if matches!(
                kind,
                "type_identifier"
                    | "integral_type"
                    | "floating_point_type"
                    | "boolean_type"
                    | "predefined_type"
                    | "generic_type"
                    | "array_type"
                    | "type"
            ) {
                return Some(content[child.byte_range()].to_string());
            }
        }

        // 查找 type_annotation 子节点（TypeScript 等）
        let mut cursor = param_node.walk();
        for child in param_node.children(&mut cursor) {
            if child.kind() == "type_annotation" {
                // type_annotation 节点内部有 type_identifier 或 predefined_type
                let mut inner_cursor = child.walk();
                for inner_child in child.children(&mut inner_cursor) {
                    if matches!(
                        inner_child.kind(),
                        "type_identifier"
                            | "predefined_type"
                            | "generic_type"
                            | "union_type"
                            | "array_type"
                    ) {
                        return Some(content[inner_child.byte_range()].to_string());
                    }
                }
                // 如果没有子类型节点，取整个 type_annotation 内容（去掉冒号）
                let ann_text = content[child.byte_range()].to_string();
                let cleaned = ann_text.trim_start_matches(':').trim();
                if !cleaned.is_empty() {
                    return Some(cleaned.to_string());
                }
            }
        }

        // 回退: 文本中包含冒号（Python typed_identifier 等）
        if text.contains(':') {
            let parts: Vec<&str> = text.splitn(2, ':').collect();
            if parts.len() == 2 {
                let type_str = parts[1].trim();
                // 清理: 去掉默认值等
                let type_str = type_str.split('=').next().unwrap_or(type_str).trim();
                if !type_str.is_empty()
                    && type_str
                        .chars()
                        .next()
                        .map(|c| c.is_alphabetic())
                        .unwrap_or(false)
                {
                    return Some(type_str.to_string());
                }
            }
        }

        None
    }

    /// 从参数节点中提取注解列表
    ///
    /// 主要服务于 Java 的 `formal_parameter`：
    /// `@RequestParam String query` 中 `marker_annotation` 是 `formal_parameter` 的直接子节点，
    /// 提取后供污点分析把带 Spring 注解的参数识别为 source。
    fn extract_parameter_annotations(param_node: &Node, content: &str) -> Vec<String> {
        let mut annotations = Vec::new();

        // Java formal_parameter 的注解封装在 kind="modifiers" 的子节点里
        // （注意：这不是 named field，而是 anonymous child node）。
        // 也兼容注解作为直接子节点的形式。
        let collect_from_node = |node: &Node, annotations: &mut Vec<String>| {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                let kind = child.kind();
                if kind == "marker_annotation" || kind == "annotation" {
                    let ann_text = content[child.byte_range()].to_string();
                    let ann_text = ann_text.trim();
                    if !ann_text.is_empty() {
                        annotations.push(ann_text.to_string());
                    }
                }
            }
        };

        // 先查找 kind="modifiers" 的子节点
        let mut cursor = param_node.walk();
        for child in param_node.children(&mut cursor) {
            if child.kind() == "modifiers" {
                collect_from_node(&child, &mut annotations);
            }
        }

        // 兜底：直接子节点
        if annotations.is_empty() {
            collect_from_node(param_node, &mut annotations);
        }

        annotations
    }

    /// 从 AST 节点中收集所有标识符（变量引用）
    fn collect_identifiers(node: &Node, content: &str) -> Vec<String> {
        let mut vars = Vec::new();
        let mut seen = std::collections::HashSet::new();
        Self::collect_identifiers_inner(node, content, &mut vars, &mut seen);
        vars
    }

    fn collect_identifiers_inner(
        node: &Node,
        content: &str,
        vars: &mut Vec<String>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        let kind = node.kind();
        if matches!(
            kind,
            "identifier"
                | "identifier_pattern"
                | "variable_name"
                | "property_identifier"
                | "field_identifier"
        ) {
            let name = content[node.byte_range()].to_string();
            let keywords = [
                "true",
                "false",
                "null",
                "None",
                "undefined",
                "self",
                "this",
                "super",
                "class",
                "function",
                "return",
                "if",
                "else",
                "for",
                "while",
                "let",
                "const",
                "var",
                "new",
                "typeof",
                "instanceof",
                "async",
                "await",
                "import",
                "export",
                "from",
                "as",
            ];
            if !keywords.contains(&name.as_str()) && !seen.contains(&name) {
                seen.insert(name.clone());
                vars.push(name);
            }
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            Self::collect_identifiers_inner(&child, content, vars, seen);
        }
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

impl ASTParser {
    /// 一次解析同时提取 symbols 和 calls（避免双重解析）
    pub fn parse_and_extract_calls(
        &mut self,
        file_path: &Path,
        content: &str,
    ) -> (Result<Vec<Symbol>, String>, Vec<CallInfo>) {
        let ext = file_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| format!(".{}", s))
            .unwrap_or_default();

        let parser = match self.parsers.get_mut(&ext) {
            Some(p) => p,
            None => {
                return (
                    Err(format!("Unsupported file extension: {}", ext)),
                    Vec::new(),
                )
            }
        };

        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return (Err("Failed to parse file".to_string()), Vec::new()),
        };

        let root = tree.root_node();

        let mut calls = Vec::new();
        Self::collect_calls_recursive(&root, content, &mut calls);

        let symbols = match ext.as_str() {
            ".java" => self.extract_java_symbols(file_path, content, root),
            ".py" => self.extract_python_symbols(file_path, content, root),
            ".rs" => self.extract_rust_symbols(file_path, content, root),
            ".ts" | ".tsx" => self.extract_typescript_symbols(file_path, content, root),
            ".js" | ".jsx" => self.extract_javascript_symbols(file_path, content, root),
            _ => self.extract_generic_symbols(file_path, content, &ext, root),
        };

        (symbols, calls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_string_safe_ascii() {
        let s = "Hello, World!";
        assert_eq!(truncate_string_safe(s, 100), "Hello, World!");
        assert_eq!(truncate_string_safe(s, 5), "Hello...");
    }

    #[test]
    fn test_truncate_string_safe_chinese() {
        // Each Chinese character is 3 bytes in UTF-8
        let s = "你好世界这是测试";
        // Don't truncate
        assert_eq!(truncate_string_safe(s, 100), s);
        // Truncate at char boundary
        let result = truncate_string_safe(s, 10); // Should be "你好世..." (9 bytes + 3)
        assert!(result.starts_with("你好世"));
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_string_safe_mixed() {
        // Mix of ASCII and Chinese
        let s = "Hello你好World世界";
        let result = truncate_string_safe(s, 10);
        // Should not panic and should be valid UTF-8
        assert!(result.is_char_boundary(result.len()));
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_string_safe_emoji() {
        // Emoji is 4 bytes in UTF-8
        let s = "Hello😀World🎉";
        let result = truncate_string_safe(s, 8);
        assert!(result.is_char_boundary(result.len()));
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_truncate_string_safe_tree_chars() {
        // Special tree drawing characters
        let s = "├── DataEase (10)";
        let result = truncate_string_safe(s, 10);
        assert!(result.is_char_boundary(result.len()));
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_java_method_param_metadata() {
        let code = r#"
public class Test {
    void bad(HttpServletRequest request, HttpServletResponse response) {}
    void badSink(String data, HttpServletResponse response) {}
}
"#;
        let mut parser = ASTParser::new();
        let (symbols_result, _) = parser.parse_and_extract_calls(Path::new("Test.java"), code);
        let symbols = symbols_result.unwrap();
        for s in &symbols {
            eprintln!(
                "symbol {} kind={:?} metadata={:?}",
                s.name, s.kind, s.metadata
            );
        }
        let bad = symbols.iter().find(|s| s.name == "bad").unwrap();
        let params = bad
            .metadata
            .get("params")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(params.len(), 2);
        assert!(params.iter().any(|v| v.as_str() == Some("request")));
        assert!(params.iter().any(|v| v.as_str() == Some("response")));
    }

    #[test]
    fn test_java_local_variable_assignment() {
        let code = r#"
import javax.servlet.http.*;

public class Test extends HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getHeader("x");
        String sql = "{call " + param + "}";
    }
}
"#;
        let mut parser = ASTParser::new();
        let (_bodies, assignments, _calls) =
            parser.extract_all_for_taint(Path::new("Test.java"), code);
        eprintln!("assignments:");
        for a in &assignments {
            eprintln!(
                "  line={} target={} source_expr={} source_vars={:?}",
                a.line, a.target, a.source_expr, a.source_vars
            );
        }
        assert!(assignments
            .iter()
            .any(|a| a.target == "param" && a.source_vars.iter().any(|v| v == "request")));
        assert!(assignments
            .iter()
            .any(|a| a.target == "sql" && a.source_vars.iter().any(|v| v == "param")));
    }

    #[test]
    fn test_java_request_param_annotation_extraction() {
        let code = r#"
import org.springframework.web.bind.annotation.*;

public class Test {
    @PostMapping("/test")
    public String query(@RequestParam String q, @PathVariable int id, String normal) {
        return q + id;
    }
}
"#;
        let mut parser = ASTParser::new();
        let (bodies, _assignments, _calls) =
            parser.extract_all_for_taint(Path::new("Test.java"), code);
        let func = bodies.iter().find(|b| b.name == "query").unwrap();
        assert_eq!(func.typed_params.len(), 3);

        let q_param = func.typed_params.iter().find(|p| p.name == "q").unwrap();
        assert_eq!(q_param.annotations, vec!["@RequestParam"]);

        let id_param = func.typed_params.iter().find(|p| p.name == "id").unwrap();
        assert_eq!(id_param.annotations, vec!["@PathVariable"]);

        let normal_param = func
            .typed_params
            .iter()
            .find(|p| p.name == "normal")
            .unwrap();
        assert!(normal_param.annotations.is_empty());
    }
}
