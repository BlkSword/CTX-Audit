// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 类型层次结构
//!
//! 从 tree-sitter AST 提取的 Class/Interface/Struct 符号构建类型层次 DAG，
//! 支持面向对象语言的 extends/implements 关系和方法签名查询。

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// 类型层次结构 — 聚合项目中所有类/接口定义
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeHierarchy {
    /// 类型名 → TypeInfo
    pub types: HashMap<String, TypeInfo>,
    /// 子类型 → 父类型列表
    pub extends_map: HashMap<String, Vec<String>>,
    /// 接口 → 实现该接口的类列表
    pub implementations: HashMap<String, Vec<String>>,
}

/// 类型信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeInfo {
    pub name: String,
    pub kind: TypeKind,
    pub methods: Vec<MethodSignature>,
    pub file_path: String,
    pub start_line: usize,
    pub end_line: usize,
}

/// 类型种类
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeKind {
    Class,
    AbstractClass,
    Interface,
    Struct,
}

/// 方法签名
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodSignature {
    pub name: String,
    pub file_path: String,
    pub start_line: usize,
    pub is_static: bool,
}

impl TypeHierarchy {
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            extends_map: HashMap::new(),
            implementations: HashMap::new(),
        }
    }

    /// 注册一个类型（类/接口/结构体）
    pub fn register_type(
        &mut self,
        name: &str,
        kind: TypeKind,
        parent_classes: &[String],
        file_path: &str,
        start_line: usize,
        end_line: usize,
    ) {
        let type_name = name.to_string();
        // 更新 extends_map
        if !parent_classes.is_empty() {
            self.extends_map
                .insert(type_name.clone(), parent_classes.to_vec());
        }
        // 对于接口，记录在 implementations 中
        for parent in parent_classes {
            if kind == TypeKind::Class || kind == TypeKind::AbstractClass {
                self.implementations
                    .entry(parent.clone())
                    .or_default()
                    .push(type_name.clone());
            }
        }
        self.types
            .entry(type_name.clone())
            .or_insert_with(|| TypeInfo {
                name: type_name,
                kind,
                methods: Vec::new(),
                file_path: file_path.to_string(),
                start_line,
                end_line,
            });
    }

    /// 注册方法的所属类
    pub fn register_method(&mut self, class_name: &str, method: MethodSignature) {
        if let Some(type_info) = self.types.get_mut(class_name) {
            type_info.methods.push(method);
        }
    }

    /// 解析虚方法调用：返回接收者类型及其所有父类型中定义的方法
    pub fn resolve_virtual_method(
        &self,
        receiver_type: &str,
        method_name: &str,
    ) -> Vec<ResolvedMethod> {
        let mut results = Vec::new();
        let mut visited = HashSet::new();

        // 从 receiver_type 出发，沿 extends 链向上遍历
        self.collect_methods_upward(receiver_type, method_name, &mut results, &mut visited);

        // 如果 receiver_type 是接口，也查找所有实现类
        if let Some(impls) = self.implementations.get(receiver_type) {
            for impl_type in impls {
                self.collect_methods_upward(impl_type, method_name, &mut results, &mut visited);
            }
        }

        results
    }

    fn collect_methods_upward(
        &self,
        type_name: &str,
        method_name: &str,
        results: &mut Vec<ResolvedMethod>,
        visited: &mut HashSet<String>,
    ) {
        if !visited.insert(type_name.to_string()) {
            return;
        }

        if let Some(type_info) = self.types.get(type_name) {
            for method in &type_info.methods {
                if method.name == method_name {
                    results.push(ResolvedMethod {
                        type_name: type_name.to_string(),
                        file_path: method.file_path.clone(),
                        line: method.start_line,
                        is_direct: !results.iter().any(|r| r.file_path == method.file_path),
                    });
                }
            }
        }

        // 沿继承链向上
        if let Some(parents) = self.extends_map.get(type_name) {
            for parent in parents {
                self.collect_methods_upward(parent, method_name, results, visited);
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    pub fn len(&self) -> usize {
        self.types.len()
    }
}

/// 解析后的方法位置
#[derive(Debug, Clone)]
pub struct ResolvedMethod {
    pub type_name: String,
    pub file_path: String,
    pub line: usize,
    pub is_direct: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_hierarchy() {
        let h = TypeHierarchy::new();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert!(h.resolve_virtual_method("Animal", "speak").is_empty());
    }

    #[test]
    fn test_register_type_with_parent() {
        let mut h = TypeHierarchy::new();
        h.register_type(
            "Dog",
            TypeKind::Class,
            &["Animal".to_string()],
            "animals.js",
            1,
            10,
        );
        h.register_type("Animal", TypeKind::Class, &[], "animals.js", 15, 25);

        assert_eq!(h.len(), 2);
        assert!(h.extends_map.contains_key("Dog"));
        assert_eq!(h.extends_map["Dog"], vec!["Animal"]);
    }

    #[test]
    fn test_resolve_virtual_method_inheritance() {
        let mut h = TypeHierarchy::new();
        h.register_type("Animal", TypeKind::Class, &[], "animals.js", 1, 10);
        h.register_type(
            "Dog",
            TypeKind::Class,
            &["Animal".to_string()],
            "animals.js",
            15,
            30,
        );
        h.register_type(
            "Cat",
            TypeKind::Class,
            &["Animal".to_string()],
            "animals.js",
            35,
            50,
        );

        h.register_method(
            "Animal",
            MethodSignature {
                name: "speak".into(),
                file_path: "animals.js".into(),
                start_line: 5,
                is_static: false,
            },
        );
        h.register_method(
            "Dog",
            MethodSignature {
                name: "speak".into(),
                file_path: "animals.js".into(),
                start_line: 20,
                is_static: false,
            },
        );
        h.register_method(
            "Cat",
            MethodSignature {
                name: "meow".into(),
                file_path: "animals.js".into(),
                start_line: 40,
                is_static: false,
            },
        );

        // Dog.speak() — should find Dog.speak and Animal.speak
        let methods = h.resolve_virtual_method("Dog", "speak");
        assert_eq!(methods.len(), 2, "Dog inherits speak from Animal");
        assert!(methods.iter().any(|m| m.type_name == "Dog" && m.is_direct));
        assert!(methods.iter().any(|m| m.type_name == "Animal"));

        // Cat.speak() — should find only Animal.speak (Cat doesn't override)
        let methods = h.resolve_virtual_method("Cat", "speak");
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].type_name, "Animal");

        // Cat.meow() — should find only Cat.meow
        let methods = h.resolve_virtual_method("Cat", "meow");
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].type_name, "Cat");
    }

    #[test]
    fn test_resolve_virtual_method_interface() {
        let mut h = TypeHierarchy::new();
        h.register_type("Speaker", TypeKind::Interface, &[], "types.ts", 1, 5);
        h.register_type(
            "Dog",
            TypeKind::Class,
            &["Speaker".to_string()],
            "dog.ts",
            1,
            20,
        );
        h.register_type(
            "Cat",
            TypeKind::Class,
            &["Speaker".to_string()],
            "cat.ts",
            1,
            20,
        );

        h.register_method(
            "Dog",
            MethodSignature {
                name: "speak".into(),
                file_path: "dog.ts".into(),
                start_line: 10,
                is_static: false,
            },
        );
        h.register_method(
            "Cat",
            MethodSignature {
                name: "speak".into(),
                file_path: "cat.ts".into(),
                start_line: 10,
                is_static: false,
            },
        );

        // Speaker.speak() — should find all implementations
        let methods = h.resolve_virtual_method("Speaker", "speak");
        assert_eq!(methods.len(), 2);
        assert!(methods.iter().any(|m| m.type_name == "Dog"));
        assert!(methods.iter().any(|m| m.type_name == "Cat"));
    }

    #[test]
    fn test_resolve_virtual_method_not_found() {
        let mut h = TypeHierarchy::new();
        h.register_type("Animal", TypeKind::Class, &[], "test.js", 1, 10);

        let methods = h.resolve_virtual_method("Animal", "nonexistent");
        assert!(methods.is_empty());
    }
}
