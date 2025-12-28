use crate::ast::cache::CacheData;
use crate::ast::symbol::Symbol;
use serde_json::Value;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct QueryEngine {
    pub cache: CacheData,
}

impl QueryEngine {
    pub fn new(cache: CacheData) -> Self {
        Self { cache }
    }

    pub fn search_symbols(&self, query: &str) -> Vec<&Symbol> {
        let query = query.to_lowercase();
        let mut results = Vec::new();

        for file_index in self.cache.index.values() {
            for symbol in &file_index.symbols {
                if symbol.name.to_lowercase().contains(&query) {
                    results.push(symbol);
                }
            }
        }

        results
    }

    pub fn find_call_sites(&self, callee_name: &str) -> Vec<&Symbol> {
        let needle = callee_name.trim();
        if needle.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();
        for file_index in self.cache.index.values() {
            for symbol in &file_index.symbols {
                if matches!(symbol.kind, crate::ast::symbol::SymbolKind::MethodCall)
                    && symbol.name == needle
                {
                    results.push(symbol);
                }
            }
        }

        results
    }

    pub fn get_call_graph(&self, entry: &str, max_depth: usize) -> Value {
        let entry = entry.trim();
        if entry.is_empty() {
            return serde_json::json!({
                "entry": entry,
                "nodes": [],
                "edges": []
            });
        }

        let mut edges = Vec::new();
        let mut nodes = HashMap::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(entry.to_string());
        let mut depth = 0;

        while !queue.is_empty() && depth < max_depth {
            let mut next_queue = VecDeque::new();

            while let Some(current) = queue.pop_front() {
                if visited.contains(&current) {
                    continue;
                }
                visited.insert(current.clone());

                // Add node
                nodes.entry(current.clone()).or_insert_with(|| {
                    serde_json::json!({
                        "id": current,
                        "label": current
                    })
                });

                // Find calls from current function
                for file_index in self.cache.index.values() {
                    for symbol in &file_index.symbols {
                        if !matches!(symbol.kind, crate::ast::symbol::SymbolKind::MethodCall) {
                            continue;
                        }

                        let metadata = &symbol.metadata;
                        let caller = metadata
                            .get("callerMethod")
                            .or_else(|| metadata.get("callerFunction"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        let callee = &symbol.name;

                        if caller == current {
                            let caller_id = current.clone();
                            let callee_id = callee.to_string();

                            // Add callee node
                            nodes.entry(callee_id.clone()).or_insert_with(|| {
                                serde_json::json!({
                                    "id": callee_id,
                                    "label": callee_id
                                })
                            });

                            // Add edge
                            edges.push(serde_json::json!({
                                "from": caller_id,
                                "to": callee_id,
                                "file": symbol.file_path,
                                "line": symbol.start_line
                            }));

                            if !visited.contains(callee) {
                                next_queue.push_back(callee_id);
                            }
                        }
                    }
                }
            }

            queue = next_queue;
            depth += 1;
        }

        serde_json::json!({
            "entry": entry,
            "nodes": nodes.into_values().collect::<Vec<_>>(),
            "edges": edges
        })
    }

    pub fn get_class_hierarchy(&self, class_name: &str) -> Value {
        // Find the class symbol
        let target_symbol = self.find_class_symbol(class_name);
        let target_file = self.cache.class_map.get(class_name);

        if target_symbol.is_none() || target_file.is_none() {
            return serde_json::json!({
                "error": format!("在索引中未找到类 '{}'", class_name)
            });
        }

        let _target_symbol = target_symbol.unwrap();
        let target_file = target_file.unwrap();

        // Build upward hierarchy (parents)
        let mut parents = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(class_name.to_string());

        while let Some(current_name) = queue.pop_front() {
            if visited.contains(&current_name) {
                continue;
            }
            visited.insert(current_name.clone());

            // Find symbol for current_name
            if let Some(current_file) = self.cache.class_map.get(&current_name) {
                if let Some(current_sym) =
                    self.find_class_symbol_in_file(&current_name, current_file)
                {
                    if current_name != class_name {
                        parents.push(serde_json::json!({
                            "name": current_name,
                            "file": current_file,
                            "line": current_sym.start_line
                        }));
                    }

                    // Add parents to queue
                    for parent in &current_sym.parent_classes {
                        if !visited.contains(parent) {
                            queue.push_back(parent.clone());
                        }
                    }
                }
            }
        }

        // Build downward hierarchy (children)
        let mut children = Vec::new();
        for file_path in self.cache.index.keys() {
            for symbol in self.cache.index.get(file_path).unwrap().symbols.iter() {
                if matches!(symbol.kind, crate::ast::symbol::SymbolKind::Class) {
                    if symbol.parent_classes.contains(&class_name.to_string()) {
                        children.push(serde_json::json!({
                            "name": symbol.name,
                            "file": file_path,
                            "line": symbol.start_line
                        }));
                    }
                }
            }
        }

        serde_json::json!({
            "class": class_name,
            "file": target_file,
            "parents": parents,
            "children": children
        })
    }

    pub fn get_file_structure(&self, file_path: &str) -> Vec<&Symbol> {
        if let Some(file_index) = self.cache.index.get(file_path) {
            file_index.symbols.iter().collect()
        } else {
            Vec::new()
        }
    }

    pub fn get_statistics(&self) -> Value {
        let mut total_nodes = 0;
        let mut type_counts = HashMap::new();

        for file_data in self.cache.index.values() {
            total_nodes += file_data.symbols.len();
            for symbol in &file_data.symbols {
                let display_kind = match symbol.kind {
                    crate::ast::symbol::SymbolKind::Function => "Method/Function".to_string(),
                    crate::ast::symbol::SymbolKind::Class => "Class".to_string(),
                    crate::ast::symbol::SymbolKind::Interface => "Interface".to_string(),
                    crate::ast::symbol::SymbolKind::Method => "Method".to_string(),
                    crate::ast::symbol::SymbolKind::MethodCall => "MethodCall".to_string(),
                    crate::ast::symbol::SymbolKind::Struct => "Struct".to_string(),
                };

                *type_counts.entry(display_kind).or_insert(0) += 1;
            }
        }

        serde_json::json!({
            "total_nodes": total_nodes,
            "type_counts": type_counts
        })
    }

    pub fn generate_report(&self, repository_path: &str) -> Value {
        let mut nodes = serde_json::Map::new();

        for (_file_path, data) in &self.cache.index {
            for symbol in &data.symbols {
                let symbol_dict = symbol.to_dict();
                if let Some(id) = symbol_dict.get("id").and_then(|v| v.as_str()) {
                    nodes.insert(id.to_string(), symbol_dict);
                }
            }
        }

        serde_json::json!({
            "metadata": {
                "build_time": chrono::Utc::now().to_rfc3339(),
                "cache_version": "1.0",
                "node_count": nodes.len(),
                "repository_path": repository_path
            },
            "nodes": nodes
        })
    }

    fn find_class_symbol(&self, class_name: &str) -> Option<&Symbol> {
        if let Some(file_path) = self.cache.class_map.get(class_name) {
            self.find_class_symbol_in_file(class_name, file_path)
        } else {
            None
        }
    }

    fn find_class_symbol_in_file(&self, class_name: &str, file_path: &str) -> Option<&Symbol> {
        if let Some(file_index) = self.cache.index.get(file_path) {
            file_index.symbols.iter().find(|symbol| {
                matches!(symbol.kind, crate::ast::symbol::SymbolKind::Class)
                    && symbol.name == class_name
            })
        } else {
            None
        }
    }

    pub fn rebuild_class_map(&mut self) {
        self.cache.class_map.clear();

        for (file_path, data) in &self.cache.index {
            for symbol in &data.symbols {
                if matches!(symbol.kind, crate::ast::symbol::SymbolKind::Class) {
                    self.cache
                        .class_map
                        .insert(symbol.name.clone(), file_path.clone());
                }
            }
        }
    }
}
