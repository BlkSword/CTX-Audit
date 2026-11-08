// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Spring 依赖注入绑定：接口 → 实现类、字段 → 声明类型。
//!
//! 只做"零构建"的轻量解析：注解 + 类声明 + 字段/构造器参数。用于名字级图上
//! 的**收窄**（receivers with a resolvable type），而不是替代类型系统。

use super::chain;
use std::collections::BTreeMap;

#[derive(Default, Clone, Debug)]
pub(crate) struct DiIndex {
    /// 文件 → (变量名 → 声明类型)
    pub var_types: BTreeMap<String, BTreeMap<String, String>>,
    /// 接口简单名 → 实现类简单名
    pub impls: BTreeMap<String, Vec<String>>,
    /// 类/接口简单名 → 文件列表
    pub type_files: BTreeMap<String, Vec<String>>,
    /// 接口简单名 → 方法名列表
    pub iface_methods: BTreeMap<String, Vec<String>>,
    /// 文件 → 被 @Autowired/@Resource/@Inject 注入的字段名
    pub injected: BTreeMap<String, std::collections::BTreeSet<String>>,
}

impl DiIndex {
    pub(crate) fn bindings_count(&self) -> usize {
        self.impls.values().map(|v| v.len()).sum()
    }

    /// 若接收者是"单实现 Bean 接口"且 callee 属于该接口，返回实现类型所在文件（不读盘）。
    ///
    /// 只做安全的收窄：类类型、多实现、接口未声明该方法一律不收窄（回退名字级）。
    pub(crate) fn resolve_type_file(&self, file: &str, receiver: &str, callee: &str) -> Option<String> {
        if !self.injected.get(file)?.contains(receiver) {
            return None;
        }
        let ty = self.var_types.get(file)?.get(receiver)?;
        let methods = self.iface_methods.get(ty)?;
        if !methods.iter().any(|m| m == callee) {
            return None;
        }
        let impl_list = self.impls.get(ty)?;
        if impl_list.len() != 1 {
            return None;
        }
        let files = self.type_files.get(&impl_list[0])?;
        if files.len() == 1 {
            Some(files[0].clone())
        } else {
            None
        }
    }
}

fn method_name(line: &str) -> Option<String> {
    let pos = line.find('(')?;
    let head = &line[..pos];
    if head.contains('=') || head.trim_start().starts_with('@') {
        return None;
    }
    let name = head
        .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'))
        .filter(|w| !w.is_empty())
        .last()?;
    if ["if", "for", "while", "switch", "catch", "return", "new"].contains(&name) {
        return None;
    }
    Some(name.to_string())
}

fn is_java(file: &str) -> bool {
    file.ends_with(".java")
}

fn is_bean_annotation(line: &str) -> bool {
    const ANNS: [&str; 7] = [
        "@Service", "@Component", "@Repository", "@Controller", "@RestController", "@Configuration", "@Bean",
    ];
    ANNS.iter().any(|a| line.contains(a))
}

fn simple_type(token: &str) -> Option<String> {
    let t = token
        .trim()
        .trim_start_matches('@')
        .trim_end_matches(';')
        .trim_end_matches(',')
        .trim_end_matches(')')
        .trim_end_matches('{');
    if t.is_empty() || !t.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
        return None;
    }
    if t.contains('(') || t.contains('=') || t == "class" || t == "interface" {
        return None;
    }
    let base = t.split('<').next().unwrap_or("").trim();
    let base = base.split('.').last().unwrap_or("").trim();
    if base.is_empty() || !base.chars().next().map(|c| c.is_ascii_alphabetic()).unwrap_or(false) {
        return None;
    }
    Some(base.to_string())
}

/// 解析注入绑定与字段声明类型。
pub(crate) fn parse(files: &[(String, String)]) -> DiIndex {
    let mut idx = DiIndex::default();
    for (path, content) in files.iter() {
        if !is_java(path) {
            continue;
        }
        let lang = "java";
        let defs = chain::definitions(content, lang);
        let lines: Vec<&str> = content.lines().collect();
        // 接口：收集方法名
        for (i, raw) in lines.iter().enumerate() {
            let t = raw.trim();
            if t.contains("interface ") {
                if let Some(name) = t
                    .split_whitespace()
                    .skip_while(|w| *w != "interface")
                    .nth(1)
                    .map(|w| w.split('<').next().unwrap_or(w).to_string())
                {
                    let mut methods: Vec<String> = Vec::new();
                    for sub in lines.iter().skip(i + 1) {
                        let st = sub.trim();
                        if st.starts_with('}') {
                            break;
                        }
                        if let Some(m) = method_name(st) {
                            methods.push(m);
                        }
                    }
                    if methods.is_empty() {
                        let fallback: Vec<String> = defs
                            .iter()
                            .filter(|(_, l)| *l as usize > i + 1)
                            .map(|(n, _)| n.clone())
                            .collect();
                        methods = fallback;
                    }
                    if !methods.is_empty() {
                        idx.iface_methods.entry(name).or_default().extend(methods);
                    }
                }
            }
        }
        // 类声明：implements + 是否 bean
        let mut class_name: Option<String> = None;
        for (i, raw) in lines.iter().enumerate() {
            let t = raw.trim();
            let class_pos = match t.find("class ") {
                Some(p) if p == 0 || t.as_bytes()[p - 1].is_ascii_whitespace() => Some(p),
                _ => None,
            };
            if let Some(pos) = class_pos {
                let after = &t[pos + 6..];
                let name = after
                    .split(|c: char| c.is_whitespace() || c == '{' || c == '<' || c == '(')
                    .next()
                    .unwrap_or("");
                if !name.is_empty() {
                    class_name = Some(name.to_string());
                    idx.type_files.entry(name.to_string()).or_default().push(path.clone());
                    if let Some(impos) = t.find("implements ") {
                        let tail = &t[impos + 11..];
                        let tail = tail.split('{').next().unwrap_or(tail);
                        let bean = (0..=i)
                            .rev()
                            .take(6)
                            .any(|j| lines.get(j).map(|l| is_bean_annotation(l)).unwrap_or(false));
                        for iface in tail.split(',') {
                            if let Some(simple) = simple_type(iface) {
                                idx.type_files.entry(simple.clone()).or_default().push(path.clone());
                                if bean {
                                    idx.impls.entry(simple).or_default().push(name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        // 字段/构造器参数类型：`Type var;` 或 `(Type var, ...)`
        for (line_idx, raw) in lines.iter().enumerate() {
            let t = raw.trim();
            if t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
                continue;
            }
            if t.contains('(') && !t.contains(';') {
                // 构造器参数注入：public Controller(Service service) {
                for part in t.split('(').nth(1).unwrap_or("").split(')').next().unwrap_or("").split(',') {
                    let toks: Vec<&str> = part.split_whitespace().collect();
                    if toks.len() == 2 {
                        if let (Some(ty), true) = (simple_type(toks[0]), toks[1].chars().all(|c| c.is_ascii_alphanumeric() || c == '_')) {
                            idx.var_types.entry(path.clone()).or_default().insert(toks[1].to_string(), ty);
                        }
                    }
                }
                continue;
            }
            if t.contains(';') && !t.contains('(') {
                // 字段声明：private final Foo foo = ...;
                let head = t.split('=').next().unwrap_or(t).trim_end_matches(';').trim();
                let toks: Vec<&str> = head.split_whitespace().collect();
                if toks.len() >= 2 {
                    let var = toks[toks.len() - 1];
                    let ty = toks[toks.len() - 2];
                    if var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !var.is_empty() {
                        if let Some(ty) = simple_type(ty) {
                            if !var.starts_with('@') && var != "return" {
                                idx.var_types.entry(path.clone()).or_default().insert(var.to_string(), ty);
                                let injected = (0..=line_idx)
                                    .rev()
                                    .take(4)
                                    .any(|j| lines.get(j).map(|l| {
                                        l.contains("@Autowired") || l.contains("@Resource") || l.contains("@Inject")
                                    }).unwrap_or(false))
                                    || t.contains("@Autowired");
                                if injected {
                                    idx.injected.entry(path.clone()).or_default().insert(var.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        let _ = class_name;
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("ctx-di-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parses_interface_impl_and_field_type() {
        let dir = tmp("parse");
        let p = dir.join("App.java");
        std::fs::write(
            &p,
            "package app;\ninterface Svc {\n  void run(String s);\n}\n@Service\nclass Good implements Svc {\n  public void run(String s) { sink(s); }\n  @Autowired\n  private Svc svc;\n}\n",
        )
        .unwrap();
        let files = vec![(p.to_string_lossy().to_string(), std::fs::read_to_string(&p).unwrap())];
        let idx = parse(&files);
        assert!(idx.impls.contains_key("Svc"), "{idx:?}");
        assert_eq!(idx.var_types[&files[0].0]["svc"], "Svc");
        let r = idx.resolve_type_file(&files[0].0, "svc", "run");
        assert_eq!(r.as_deref(), Some(files[0].0.as_str()), "{idx:?}");
    }
}
