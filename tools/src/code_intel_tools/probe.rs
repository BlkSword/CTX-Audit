// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 路线 B 原语：`can_reach` / `slice_between`。
//!
//! 设计意图：不再让 agent 一次性吞下 12KB 链档，而是让 LLM 先提假设，
//! 再用确定性原语按需验证：
//! - `can_reach(from, to)`：拓扑上两点之间是否存在调用路径（名字级图，显式标注不确定性）；
//! - `slice_between(from, to)`：只在 agent 索取时切出路径上每一步的关键代码窗口。
//!
//! 这两个原语不宣称漏洞结论，只回答"拓扑上通不通、沿途长什么样"。

use super::chain;
use super::index;
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

const MAX_HOPS: usize = 20;
const MAX_NODES: usize = 3000;
const NEIGHBOR_CAP: usize = 8;

/// 定义抽取加强版：在 chain::definitions 基础上补多行签名
/// （`public Foo bar(\n  String a,\n  int b) {` 这类），并做去重。
fn definitions_multi(content: &str, lang: &str) -> Vec<(String, u32)> {
    let mut out = chain::definitions(content, lang);
    const KW: [&str; 12] = [
        "if", "for", "while", "switch", "catch", "return", "new", "throw", "else", "try", "do",
        "case",
    ];
    let lines: Vec<&str> = content.lines().collect();
    for (i, raw) in lines.iter().enumerate() {
        let t = raw.trim();
        if t.is_empty() || t.starts_with("//") || t.starts_with('*') || t.starts_with("/*") {
            continue;
        }
        let Some(open) = t.find('(') else { continue };
        let before = t[..open].trim_end();
        if before.is_empty() {
            continue;
        }
        let name: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if name.is_empty() || KW.contains(&name.as_str()) {
            continue;
        }
        // 单行定义（同一行有 `)`）交给 chain::definitions；这里只补多行签名
        if t[open..].contains(')') {
            continue;
        }
        let decl_like = before.contains(' ')
            || [
                "public", "private", "protected", "static", "final", "abstract",
                "synchronized", "def ", "func ", "function ", "export ",
            ]
            .iter()
            .any(|k| t.starts_with(k));
        if !decl_like {
            continue;
        }
        let mut ok = false;
        for j in i..(i + 8).min(lines.len()) {
            let tj = lines[j];
            if tj.contains(')') {
                if tj.contains('{')
                    || lines
                        .get(j + 1)
                        .map(|n| n.trim_start().starts_with('{'))
                        .unwrap_or(false)
                {
                    ok = true;
                }
                break;
            }
        }
        if ok {
            out.push((name, (i + 1) as u32));
        }
    }
    out.sort_by_key(|(_, l)| *l);
    out.dedup();
    out
}

struct Graph {
    defs: BTreeMap<String, Vec<(String, u32)>>,
    calls: BTreeMap<String, Vec<(String, u32, bool)>>,
    contents: BTreeMap<String, String>,
    name_index: BTreeMap<String, Vec<(String, u32)>>,
}

impl Graph {
    fn build(project: &Path) -> Graph {
        let loaded = index::load_files(project);
        let mut g = Graph {
            defs: BTreeMap::new(),
            calls: BTreeMap::new(),
            contents: BTreeMap::new(),
            name_index: BTreeMap::new(),
        };
        for (path, content) in loaded.files.iter() {
            let lang = chain::chain_language_of(path);
            let defs = definitions_multi(content, lang);
            let calls: Vec<(String, u32, bool)> = chain::calls(content)
                .into_iter()
                .map(|(name, line, member, _install, _ctor)| (name, line, member))
                .collect();
            for (name, line) in defs.iter() {
                g.name_index
                    .entry(name.clone())
                    .or_default()
                    .push((path.clone(), *line));
            }
            g.defs.insert(path.clone(), defs);
            g.calls.insert(path.clone(), calls);
            g.contents.insert(path.clone(), content.clone());
        }
        g
    }

    fn enclosing(&self, file: &str, line: u32) -> Option<(String, u32)> {
        self.enclosing_with_fallback(file, line).map(|(n, l, _)| (n, l))
    }

    /// 优先取"行号之前的最近定义"；否则退化为"文件中距离最近的定义"，
    /// 用第三个返回值标记 fallback，避免 agent 传入装饰器/调用点行号时直接判失败。
    fn enclosing_with_fallback(&self, file: &str, line: u32) -> Option<(String, u32, bool)> {
        let defs = self.defs.get(file)?;
        if let Some((n, l)) = defs
            .iter()
            .filter(|(_, l)| *l <= line)
            .max_by_key(|(_, l)| *l)
        {
            return Some((n.clone(), *l, false));
        }
        defs.iter()
            .min_by_key(|(_, l)| l.abs_diff(line))
            .map(|(n, l)| (n.clone(), *l, true))
    }

    fn def_end(&self, file: &str, def_line: u32) -> u32 {
        let total = self
            .contents
            .get(file)
            .map(|c| c.lines().count() as u32)
            .unwrap_or(def_line);
        self.defs
            .get(file)
            .and_then(|defs| {
                defs.iter()
                    .filter(|(_, l)| *l > def_line)
                    .map(|(_, l)| *l)
                    .min()
            })
            .map(|n| n.saturating_sub(1))
            .unwrap_or(total)
            .max(def_line)
    }

    fn neighbors(&self, file: &str, def_line: u32) -> Vec<(String, u32, String)> {
        let Some(calls) = self.calls.get(file) else { return Vec::new() };
        let end = self.def_end(file, def_line);
        let mut out: Vec<(String, u32, String)> = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for (name, line, member) in calls.iter() {
            if *line < def_line || *line > end {
                continue;
            }
            if let Some(cands) = self.name_index.get(name) {
                let mut same_file: Vec<&(String, u32)> =
                    cands.iter().filter(|(f, _)| f == file).collect();
                let mut others: Vec<&(String, u32)> =
                    cands.iter().filter(|(f, _)| f != file).collect();
                same_file.extend(others.drain(..));
                for (cf, cl) in same_file.into_iter().take(NEIGHBOR_CAP) {
                    if seen.insert((cf.clone(), *cl)) {
                        let edge = if *member { "call" } else { "dataflow" };
                        out.push((cf.clone(), *cl, edge.to_string()));
                    }
                }
            }
        }
        out
    }
}

/// 两点之间的可达性（名字级调用图 BFS）。
pub fn can_reach_report(
    project: &Path,
    from_file: &str,
    from_line: u32,
    to_file: &str,
    to_line: u32,
) -> Result<Value, String> {
    let graph = Graph::build(project);
    let from_loc = graph.enclosing_with_fallback(from_file, from_line);
    let Some((from_sym, from_def, from_fallback)) = from_loc else {
        return Ok(json!({
            "schema": "probe-reach/v1",
            "reachable": false,
            "error": "from 定位失败（文件/行号不在已知函数内）",
            "from": {"file": from_file, "line": from_line},
            "to": {"file": to_file, "line": to_line},
        }));
    };
    let to_loc = graph.enclosing_with_fallback(to_file, to_line);
    let Some((to_sym, to_def, to_fallback)) = to_loc else {
        return Ok(json!({
            "schema": "probe-reach/v1",
            "reachable": false,
            "error": "to 定位失败（文件/行号不在已知函数内）",
            "from": {"file": from_file, "line": from_line, "symbol": from_sym},
            "to": {"file": to_file, "line": to_line},
        }));
    };
    let start = (from_file.to_string(), from_def);
    let goal = (to_file.to_string(), to_def);
    let mut prev: BTreeMap<(String, u32), (Option<(String, u32)>, String)> = BTreeMap::new();
    let mut queue: VecDeque<(String, u32, usize)> = VecDeque::new();
    prev.insert(start.clone(), (None, from_sym.clone()));
    queue.push_back((start.0.clone(), start.1, 0));
    let mut found = false;
    let mut visited = 0usize;
    while let Some((file, line, depth)) = queue.pop_front() {
        visited += 1;
        if visited > MAX_NODES || depth > MAX_HOPS {
            break;
        }
        if (file.clone(), line) == goal {
            found = true;
            break;
        }
        for (cf, cl, edge) in graph.neighbors(&file, line) {
            let key = (cf.clone(), cl);
            if prev.contains_key(&key) {
                continue;
            }
            let sym = graph
                .defs
                .get(&cf)
                .and_then(|defs| defs.iter().find(|(_, l)| *l == cl).map(|(n, _)| n.clone()))
                .unwrap_or_default();
            prev.insert(key, (Some((file.clone(), line)), format!("{edge}:{sym}")));
            queue.push_back((cf, cl, depth + 1));
        }
    }

    let mut path = Vec::new();
    if found {
        let mut cur = goal.clone();
        let mut guard = 0;
        while guard < MAX_HOPS + 2 {
            guard += 1;
            let (file, line) = cur.clone();
            let sym = graph
                .defs
                .get(&file)
                .and_then(|defs| defs.iter().find(|(_, l)| *l == line).map(|(n, _)| n.clone()))
                .unwrap_or_default();
            let edge = prev
                .get(&cur)
                .map(|(_, e)| e.split(':').next().unwrap_or("").to_string())
                .unwrap_or_default();
            path.push(json!({"file": file, "line": line, "symbol": sym, "edge": edge}));
            match prev.get(&cur).and_then(|(p, _)| p.clone()) {
                Some(p) => cur = p,
                None => break,
            }
        }
        path.reverse();
    }

    Ok(json!({
        "schema": "probe-reach/v1",
        "reachable": found,
        "from": {"file": from_file, "line": from_line, "symbol": from_sym, "def_line": from_def, "nearest_def_fallback": from_fallback},
        "to": {"file": to_file, "line": to_line, "symbol": to_sym, "def_line": to_def, "nearest_def_fallback": to_fallback},
        "hops": path.len().saturating_sub(1),
        "path": path,
        "method": "name_level_bfs",
        "uncertainty": {
            "level": "medium",
            "reasons": ["name_level_graph", "no_type_receiver_resolution"],
        },
    }))
}

/// 沿可达路径切出每一步的代码窗口（按需索取，不主动推送大档）。
pub fn slice_between_report(
    project: &Path,
    from_file: &str,
    from_line: u32,
    to_file: &str,
    to_line: u32,
    radius: u32,
) -> Result<Value, String> {
    let reach = can_reach_report(project, from_file, from_line, to_file, to_line)?;
    let reachable = reach["reachable"].as_bool().unwrap_or(false);
    let graph = Graph::build(project);
    let radius = radius.clamp(2, 60);
    let mut slices: Vec<Value> = Vec::new();
    let mut total = 0usize;
    const MAX_TOTAL: usize = 12_000;

    let points: Vec<(String, u32)> = if reachable {
        reach["path"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|p| {
                        (
                            p["file"].as_str().unwrap_or("").to_string(),
                            p["line"].as_u64().unwrap_or(0) as u32,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![
            (from_file.to_string(), from_line),
            (to_file.to_string(), to_line),
        ]
    };

    for (file, line) in points.into_iter().take(8) {
        let Some(content) = graph.contents.get(&file) else { continue };
        let Some((sym, def_line)) = graph.enclosing(&file, line) else { continue };
        let end = graph.def_end(&file, def_line).min(def_line.saturating_add(radius));
        let lines: Vec<&str> = content.lines().collect();
        let lo = def_line.saturating_sub(2).max(1) as usize;
        let hi = (end as usize).min(lines.len());
        if lo > hi {
            continue;
        }
        let mut text = String::new();
        for (idx, raw) in lines[lo - 1..hi].iter().enumerate() {
            text.push_str(&format!("{:>5} | {}\n", lo + idx, raw));
        }
        if total + text.len() > MAX_TOTAL {
            break;
        }
        total += text.len();
        slices.push(json!({
            "file": file,
            "symbol": sym,
            "from_line": lo,
            "to_line": hi,
            "text": text,
        }));
    }

    Ok(json!({
        "schema": "probe-slice/v1",
        "reachable": reachable,
        "from": {"file": from_file, "line": from_line},
        "to": {"file": to_file, "line": to_line},
        "slices": slices,
        "bytes": total,
        "method": "name_level_bfs",
        "uncertainty": {"level": "medium", "reasons": ["name_level_graph"]},
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
        let dir = std::env::temp_dir().join(format!("ctx-probe-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn can_reach_finds_call_chain() {
        let dir = tmp("reach");
        write_tree(
            &dir,
            &[
                (
                    "A.java",
                    r#"
public class A {
    public void entry() {
        B b = new B();
        b.mid();
    }
}
"#,
                ),
                (
                    "B.java",
                    r#"
public class B {
    public void mid() {
        C c = new C();
        c.sink();
    }
}
"#,
                ),
                (
                    "C.java",
                    r#"
public class C {
    public void sink() {
        Runtime.getRuntime().exec("x");
    }
}
"#,
                ),
            ],
        );
        let r = can_reach_report(&dir, "A.java", 3, "C.java", 3).unwrap();
        assert_eq!(r["reachable"], true);
        let hops = r["hops"].as_u64().unwrap_or(0);
        assert!(hops >= 2, "hops={hops} path={:?}", r["path"]);
        let slice = slice_between_report(&dir, "A.java", 3, "C.java", 3, 10).unwrap();
        assert_eq!(slice["reachable"], true);
        assert!(!(slice["slices"].as_array().unwrap().is_empty()));
    }

    #[test]
    fn can_reach_reports_unreachable() {
        let dir = tmp("noreach");
        write_tree(
            &dir,
            &[
                (
                    "A.java",
                    r#"
public class A {
    public void a() { int x = 1; }
}
"#,
                ),
                (
                    "B.java",
                    r#"
public class B {
    public void b() { int y = 2; }
}
"#,
                ),
            ],
        );
        let r = can_reach_report(&dir, "A.java", 3, "B.java", 3).unwrap();
        assert_eq!(r["reachable"], false);
    }
}
