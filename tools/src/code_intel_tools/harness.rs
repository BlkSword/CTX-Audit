// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 路线 B：Harness 生成可行性验证。
//!
//! 输入一个 route handler（file:line），静态生成"最小验证骨架"：
//! - 路由/方法/参数绑定（query/path/body）
//! - 现存守卫清单（来自链层同一套 guard 规则）
//! - curl 请求骨架 + Spring MockMvc 测试骨架
//! - 人工验证计划（把"候选"变成"可执行验证"的下一步）
//!
//! 边界：只生成骨架，不执行、不保证可编译、不替代人工业务约束。

use super::chain;
use super::index;
use super::probe;
use serde_json::{json, Value};
use std::path::Path;

fn join_route(prefix: &str, path: &str) -> String {
    let mut p = format!("{}{}", prefix.trim_end_matches('/'), path);
    if p.is_empty() {
        p = "/".to_string();
    }
    if !p.starts_with('/') {
        p = format!("/{p}");
    }
    p
}

fn annotation_path(line: &str) -> Option<String> {
    let pos = line.find('"')?;
    let rest = &line[pos + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn mapping_of_line(line: &str) -> Option<(String, String)> {
    let kinds = [
        ("@GetMapping", "GET"),
        ("@PostMapping", "POST"),
        ("@PutMapping", "PUT"),
        ("@DeleteMapping", "DELETE"),
        ("@PatchMapping", "PATCH"),
        ("@RequestMapping", "ANY"),
    ];
    for (k, m) in kinds {
        if line.contains(k) {
            return Some((m.to_string(), annotation_path(line).unwrap_or_default()));
        }
    }
    None
}

fn split_params(inner: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in inner.chars() {
        match ch {
            '<' | '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            '>' | ')' | ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn ident_tail(s: &str) -> String {
    s.trim()
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

/// 生成 route handler 的最小验证骨架。
pub fn harness_skeleton_report(project: &Path, file: &str, line: u32) -> Result<Value, String> {
    let loaded = index::load_files(project);
    let Some((_, content)) = loaded.files.iter().find(|(p, _)| p == file) else {
        return Err(format!("文件不在索引中: {file}"));
    };
    let lang = chain::chain_language_of(file);
    let defs = probe::definitions_multi(content, lang);
    let enclosing = defs
        .iter()
        .filter(|(_, l)| *l <= line)
        .max_by_key(|(_, l)| *l)
        .cloned()
        .or_else(|| {
            defs.iter()
                .min_by_key(|(_, l)| l.abs_diff(line))
                .cloned()
        });
    let Some((symbol, def_line)) = enclosing else {
        return Err(format!("{file}:{line} 不在任何函数定义内"));
    };
    let lines: Vec<&str> = content.lines().collect();

    // 方法签名（从定义行开始多行合并，遇到首个 '(' 的配对 ')' 结束）
    let mut sig = String::new();
    let mut depth = 0i32;
    let mut opened = false;
    for i in (def_line.saturating_sub(1) as usize)..lines.len().min(def_line as usize + 8) {
        let t = lines[i];
        sig.push_str(t);
        sig.push('\n');
        for ch in t.chars() {
            if ch == '(' {
                depth += 1;
                opened = true;
            } else if ch == ')' {
                depth -= 1;
            }
        }
        if opened && depth <= 0 {
            break;
        }
    }
    let inner = {
        let bytes: Vec<char> = sig.chars().collect();
        let sym_pos = sig.find(&symbol).unwrap_or(0);
        let mut start = None;
        let mut depth = 0i32;
        let mut end = None;
        for (i, ch) in bytes.iter().enumerate().skip(sym_pos) {
            if *ch == '(' {
                if start.is_none() {
                    start = Some(i);
                }
                depth += 1;
            } else if *ch == ')' {
                depth -= 1;
                if depth == 0 && start.is_some() {
                    end = Some(i);
                    break;
                }
            }
        }
        match (start, end) {
            (Some(a), Some(b)) if b > a => bytes[a + 1..b].iter().collect(),
            _ => String::new(),
        }
    };

    // 路由：类声明之前的 @RequestMapping 作为类级前缀；类声明之后到 handler 之间找方法级映射
    let class_decl = lines
        .iter()
        .position(|l| {
            let t = l.trim();
            t.starts_with("public class ")
                || t.starts_with("class ")
                || t.contains(" class ")
        })
        .unwrap_or(0);
    let mut class_prefix = String::new();
    for raw in lines.iter().take(class_decl) {
        let t = raw.trim();
        if t.contains("@RequestMapping") {
            if let Some(p) = annotation_path(t) {
                class_prefix = p;
            }
        }
    }
    let mut method_mapping: Option<(String, String)> = None;
    for raw in lines.iter().take(def_line as usize).skip(class_decl) {
        let t = raw.trim();
        if let Some(m) = mapping_of_line(t) {
            method_mapping = Some(m);
        }
    }
    let (method, method_path) = method_mapping.unwrap_or(("ANY".to_string(), String::new()));
    let route = join_route(&class_prefix, &method_path);

    // 参数绑定
    let mut params: Vec<Value> = Vec::new();
    for raw in split_params(&inner) {
        let part = raw.trim();
        if part.is_empty() || part == "self" || part == "cls" {
            continue;
        }
        let binding = if part.contains("@RequestBody") {
            "body"
        } else if part.contains("@PathVariable") {
            "path"
        } else if part.contains("@RequestParam") || part.contains("@RequestHeader") {
            "query"
        } else {
            // Spring 简单类型参数（无注解）默认按 query 处理
            "query"
        };
        let name = ident_tail(part);
        if name.is_empty() || name == "Context" {
            continue;
        }
        params.push(json!({"name": name, "binding": binding, "raw": part}));
    }

    // 守卫（与链层同一套规则）
    let range_start = lines
        .iter()
        .enumerate()
        .take(def_line as usize)
        .filter(|(_, l)| mapping_of_line(l.trim()).is_some())
        .map(|(i, _)| (i + 1) as u32)
        .max()
        .unwrap_or(def_line);
    let def_end = defs
        .iter()
        .filter(|(_, l)| *l > def_line)
        .map(|(_, l)| *l)
        .min()
        .map(|n| n.saturating_sub(1))
        .unwrap_or(lines.len() as u32);
    let guards: Vec<Value> = chain::guards_range(content, range_start, def_end, file)
        .into_iter()
        .map(|g| json!({"kind": g.get("kind"), "evidence": g.get("evidence")}))
        .collect();

    // curl / mockmvc 骨架
    let mut path_route = route.clone();
    let mut query_parts: Vec<String> = Vec::new();
    let mut body_fields: Vec<String> = Vec::new();
    for p in params.iter() {
        let name = p["name"].as_str().unwrap_or("");
        match p["binding"].as_str().unwrap_or("") {
            "path" => {
                path_route = path_route.replace(&format!("{{{name}}}"), "MARKER");
            }
            "body" => body_fields.push(format!("\"{name}\": \"MARKER\"")),
            _ => query_parts.push(format!("{name}=MARKER")),
        }
    }
    let mut url = format!("http://localhost:8080{path_route}");
    if !query_parts.is_empty() {
        url = format!("{url}?{}", query_parts.join("&"));
    }
    let curl = if body_fields.is_empty() {
        format!("curl -X {method} '{url}'")
    } else {
        format!(
            "curl -X {method} '{url}' -H 'Content-Type: application/json' -d '{{{}}}'",
            body_fields.join(", ")
        )
    };
    let test_skeleton = format!(
        r#"@Test
void {symbol}_smoke() throws Exception {{
    mockMvc.perform({req}.uri("{path_route}")
        {params})
        .andExpect(status().isOk());
}}"#,
        symbol = symbol,
        req = if method == "GET" { "get" } else { "post" },
        path_route = path_route,
        params = if body_fields.is_empty() {
            query_parts
                .iter()
                .map(|q| format!(".param(\"{}\", \"MARKER\")", q.split('=').next().unwrap_or("")))
                .collect::<Vec<_>>()
                .join("\n        ")
        } else {
            format!(
                ".contentType(MediaType.APPLICATION_JSON)\n        .content(\"{{{}}}\")",
                body_fields.join(", ")
            )
        }
    );

    Ok(json!({
        "schema": "harness-skeleton/v1",
        "file": file,
        "line": line,
        "symbol": symbol,
        "def_line": def_line,
        "method": method,
        "route": route,
        "params": params,
        "guards": guards,
        "curl": curl,
        "test_skeleton": test_skeleton,
        "verification_plan": [
            "1) 用 curl/MockMvc 发送 MARKER 值，确认到达目标 sink（观察响应、日志或下游副作用）",
            "2) 若 sink 无外部可见副作用，为 sink 处临时加日志/断点（仅本地）",
            "3) 逐一移除/绕过守卫，对比请求是否仍被拦截（验证 guard 是否有效）",
            "4) 结论回填 controlled/guarded/reachable 三事实，并标注未验证项"
        ],
        "limits": [
            "静态生成，未编译未执行",
            "参数类型/业务约束需人工补全",
            "Spring/Body 解析为启发式，非框架语义",
        ],
        "uncertainty": {"level": "medium", "reasons": ["static_skeleton", "heuristic_param_binding"]},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tree(root: &Path, files: &[(&str, &str)]) {
        for (p, c) in files {
            let full = root.join(p);
            if let Some(parent) = full.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            let mut f = std::fs::File::create(&full).unwrap();
            f.write_all(c.as_bytes()).unwrap();
        }
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ctx-harness-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn builds_curl_and_test_for_request_param() {
        let dir = tmp("java");
        write_tree(
            &dir,
            &[(
                "AdminController.java",
                r#"
@RestController
@RequestMapping("/admin")
public class AdminController {
    @GetMapping("/run")
    public String run(@RequestParam String cmd) throws Exception {
        return Runtime.getRuntime().exec(cmd).toString();
    }
}
"#,
            )],
        );
        let r = harness_skeleton_report(&dir, "AdminController.java", 5).unwrap();
        assert_eq!(r["route"], "/admin/run");
        assert_eq!(r["method"], "GET");
        assert_eq!(r["params"][0]["name"], "cmd");
        assert_eq!(r["params"][0]["binding"], "query");
        assert!(r["curl"].as_str().unwrap().contains("cmd=MARKER"));
        assert!(r["test_skeleton"].as_str().unwrap().contains("mockMvc"));
    }
}
