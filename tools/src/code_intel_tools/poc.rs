// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! PoC 工件打包：把一条链的证据整理成可直接交付的工件。
//!
//! 输入一条链（chain_id 或 entry/sink 坐标），输出：
//! - **Mermaid 拓扑图**：入口 → 中间步骤 → 汇，守卫以旁注标出；
//! - **curl / MockMvc 请求骨架**（复用 harness 的启发式绑定）；
//! - **Guard Gap 分析**：哪些守卫存在、判定为有效/无效/未知；
//! - **修复建议**：按 archetype 给出具体改法（不是泛泛而谈）；
//! - **复现步骤**：从静态证据到动态验证的完整命令序列。
//!
//! 只打包证据，不执行任何请求。

use serde_json::{json, Value};
use std::path::Path;

/// 按 archetype 给出修复建议（具体到 API 级别）。
fn remediation_for(archetype: &str, sink_kind: &str) -> Value {
    let (summary, steps, references): (&str, Vec<&str>, Vec<&str>) = match archetype {
        "sql" => (
            "改用参数化查询，禁止把外部输入拼进 SQL 文本",
            vec![
                "把字符串拼接改为 PreparedStatement 占位符（? / :name）",
                "动态表名/列名/ORDER BY 用白名单枚举，不接受原始输入",
                "LIKE 查询对 % 和 _ 做转义，并限制长度",
            ],
            vec!["CWE-89", "OWASP A03:2021"],
        ),
        "command" => (
            "避免 shell 解释，改用参数数组并做白名单校验",
            vec![
                "Runtime.exec(String) 改为 exec(String[]) 或 ProcessBuilder(List)",
                "禁止 sh -c / cmd /c 包装外部输入",
                "对可执行文件名与参数分别做白名单",
            ],
            vec!["CWE-78", "OWASP A03:2021"],
        ),
        "path" => (
            "规范化后校验前缀，拒绝越界路径",
            vec![
                "先 Paths.get(base).resolve(input).normalize()，再 startsWith(base) 校验",
                "拒绝包含 .. 的输入，或改用文件名白名单",
                "注意校验顺序：normalize 必须在校验之前",
            ],
            vec!["CWE-22", "OWASP A01:2021"],
        ),
        "deser" | "deserialize" => (
            "禁止反序列化不可信数据，或强制类型白名单",
            vec![
                "设置 ObjectInputFilter 只允许预期类型（拒绝一切非白名单类）",
                "改用 JSON/Protobuf 等数据格式替代原生序列化",
                "如必须反序列化，加签名校验并限制输入长度",
            ],
            vec!["CWE-502", "OWASP A08:2021"],
        ),
        "jndi" => (
            "禁止把外部输入作为 JNDI 名称，或限制协议与主机",
            vec![
                "只允许 ldap:// / rmi:// 到受信主机的固定前缀",
                "升级 JDK 并设置 com.sun.jndi.ldap.object.trustURLCodebase=false",
                "对外部输入做协议与主机白名单校验",
            ],
            vec!["CWE-074", "CVE-2021-44228 类"],
        ),
        "template" => (
            "禁止把外部输入作为模板源码，只作为数据传入",
            vec![
                "模板源码固定，外部输入通过上下文变量传入",
                "使用 Sandboxed 模板引擎（如 SpEL 的 SimpleEvaluationContext）",
                "对表达式长度与关键字做限制",
            ],
            vec!["CWE-1336", "OWASP A03:2021"],
        ),
        "ssrf" => (
            "对目标地址做协议/主机/端口白名单，并阻断内网地址",
            vec![
                "解析 URL 后校验 host 是否在白名单内",
                "拒绝 127.0.0.0/8、10/8、172.16/12、192.168/16、169.254/16 等内网段",
                "禁止跟随重定向，或对每一跳重新校验",
            ],
            vec!["CWE-918", "OWASP A10:2021"],
        ),
        "xss" => (
            "按输出上下文做编码，优先使用框架自动转义",
            vec![
                "HTML 上下文用 HTML 实体编码，JS 上下文用 JS 编码",
                "避免 innerHTML / document.write，改用 textContent",
                "对富文本使用白名单 sanitizer",
            ],
            vec!["CWE-79", "OWASP A03:2021"],
        ),
        "xxe" => (
            "禁用外部实体与 DTD",
            vec![
                "setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)",
                "setFeature(\"http://xml.org/sax/features/external-general-entities\", false)",
                "setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false)",
            ],
            vec!["CWE-611", "OWASP A05:2021"],
        ),
        "redirect" => (
            "只允许跳转到白名单域名或站内相对路径",
            vec![
                "对目标 URL 做 host 白名单校验",
                "拒绝 //evil.com 这类协议相对地址",
                "优先使用站内路径映射而非直接透传 URL",
            ],
            vec!["CWE-601", "OWASP A01:2021"],
        ),
        "header" => (
            "过滤 CR/LF 并限制 header 值字符集",
            vec![
                "写入 header 前移除 \\r 与 \\n",
                "对 header 值做字符白名单校验",
                "避免把外部输入直接作为 header 名",
            ],
            vec!["CWE-113", "OWASP A03:2021"],
        ),
        _ => (
            "按 sink 类型加固输入校验与输出编码",
            vec!["确认该 sink 是否真的接收外部输入", "在 sink 前加入白名单校验"],
            vec!["CWE-20"],
        ),
    };
    json!({
        "archetype": archetype,
        "sink_kind": sink_kind,
        "summary": summary,
        "steps": steps,
        "references": references,
    })
}

/// 生成 Mermaid 流程图。
fn mermaid_for(steps: &[Value], guards: &[Value], entry: &Value, sink: &Value) -> String {
    let mut out = String::from("flowchart TD\n");
    let short = |p: &str| -> String {
        let parts: Vec<&str> = p.split(['/', '\\']).collect();
        let tail = parts.iter().rev().take(2).cloned().collect::<Vec<_>>();
        tail.into_iter().rev().collect::<Vec<_>>().join("/")
    };
    // 节点 id：source→E0，sink→S{n}，中间→P{n}
    let mut ids: Vec<String> = Vec::new();
    if steps.is_empty() {
        let ef = entry["file"].as_str().unwrap_or("");
        let sf = sink["file"].as_str().unwrap_or("");
        out.push_str(&format!(
            "  E0[\"entry<br/>{}\"] --> S0{{\"sink<br/>{}\"}}\n",
            short(ef),
            short(sf)
        ));
        ids.push("E0".to_string());
        ids.push("S0".to_string());
    } else {
        for (i, st) in steps.iter().enumerate() {
            let file = st["file"].as_str().unwrap_or("");
            let symbol = st["symbol"].as_str().unwrap_or("");
            let role = st["role"].as_str().unwrap_or("");
            let (id, node) = match role {
                "source" => (format!("E{i}"), format!("E{i}[\"{symbol}<br/>{}\"]", short(file))),
                "sink" => (format!("S{i}"), format!("S{i}{{\"{symbol}<br/>{}\"}}", short(file))),
                _ => (format!("P{i}"), format!("P{i}[\"{symbol}<br/>{}\"]", short(file))),
            };
            out.push_str(&format!("  {node}\n"));
            if let Some(prev) = ids.last() {
                out.push_str(&format!("  {prev} --> {id}\n"));
            }
            ids.push(id);
        }
    }
    // 守卫挂在最后一个节点（汇）上
    let sink_id = ids.last().cloned().unwrap_or_else(|| "S0".to_string());
    for (i, g) in guards.iter().enumerate() {
        let kind = g["kind"].as_str().unwrap_or("guard");
        let verdict = g["verdict"].as_str().unwrap_or("unknown");
        let line = g["line"].as_u64().unwrap_or(0);
        out.push_str(&format!(
            "  G{i}[\"{kind}<br/>{verdict} @L{line}\"]:::guard\n"
        ));
        out.push_str(&format!("  G{i} -.-> {sink_id}\n"));
    }
    out.push_str("  classDef guard fill:#2a2110,stroke:#d29922,color:#d29922\n");
    out
}

/// 打包一条链的 PoC 工件。
pub fn poc_package_report(
    project: &Path,
    chain_id: Option<&str>,
    entry_file: Option<&str>,
    entry_line: Option<u32>,
    sink_file: Option<&str>,
    sink_line: Option<u32>,
) -> Result<Value, String> {
    // 1) 取链档（含步骤/守卫/断点）
    let dossier = match (chain_id, entry_file, entry_line, sink_file, sink_line) {
        (Some(cid), _, _, _, _) => super::chain_dossier_report(project, cid)?,
        (None, Some(ef), Some(el), Some(sf), Some(sl)) => {
            super::trace_vulnerability_chain_report(
                project,
                None,
                Some(ef),
                Some(el),
                Some(sf),
                Some(sl),
                None,
            )?
        }
        _ => {
            return Err(
                "需要 chain_id，或同时提供 entry_file/entry_line/sink_file/sink_line".to_string(),
            )
        }
    };

    // 链档把 entry/sink/steps 放在顶层；trace 报告把它们放在 chain 下。
    let chain_node = if dossier.get("chain").is_some() {
        dossier["chain"].clone()
    } else {
        dossier.clone()
    };
    let entry = chain_node["entry"].clone();
    let sink = chain_node["sink"].clone();
    let steps = chain_node["steps"].as_array().cloned().unwrap_or_default();
    let guards = dossier["guards"].as_array().cloned().unwrap_or_default();
    let sink_kind = sink["kind"].as_str().unwrap_or("");
    let archetype = super::archetype_for_sink(sink_kind);

    // 2) 载荷判定（决定工件里的"当前结论"）
    let ef = entry["file"].as_str().unwrap_or("");
    let el = entry["handler_line"]
        .as_u64()
        .or_else(|| entry["line"].as_u64())
        .unwrap_or(0) as u32;
    let sf = sink["file"].as_str().unwrap_or("");
    let sl = sink["line"].as_u64().unwrap_or(0) as u32;
    let payload = if !ef.is_empty() && !sf.is_empty() && el > 0 && sl > 0 {
        super::ant::payload_viability_report(project, ef, el, sf, sl, archetype)
            .unwrap_or_else(|e| json!({"tier": "error", "error": e}))
    } else {
        json!({"tier": "unknown", "reason": "incomplete_coordinates"})
    };

    // 3) 请求骨架（仅当入口是 HTTP 路由时可用）
    let harness = if !ef.is_empty() && el > 0 {
        super::harness::harness_skeleton_report(project, ef, el).ok()
    } else {
        None
    };

    // 4) Guard Gap：把守卫按 verdict 分类
    let mut effective: Vec<Value> = Vec::new();
    let mut ineffective: Vec<Value> = Vec::new();
    let mut unknown: Vec<Value> = Vec::new();
    for g in guards.iter() {
        let verdict = g["verdict"].as_str().unwrap_or("unknown");
        match verdict {
            "blocking" | "effective" => effective.push(g.clone()),
            "partial" | "bypassable" => ineffective.push(g.clone()),
            _ => unknown.push(g.clone()),
        }
    }
    // 断点（payload_boundary / ambiguous_chain 等）也是"未解开的守卫/边界"，
    // 归入 unknown，避免 Guard Gap 显示为 0 而实际存在未解项。
    for bp in dossier["breakpoints"].as_array().cloned().unwrap_or_default() {
        unknown.push(json!({
            "kind": bp["kind"].clone(),
            "at": bp["at"].clone(),
            "confidence": bp["confidence"].clone(),
            "source": "breakpoint",
        }));
    }

    let mermaid = mermaid_for(&steps, &guards, &entry, &sink);
    let remediation = remediation_for(archetype, sink_kind);
    let tier = payload["tier"].as_str().unwrap_or("unknown").to_string();

    // 5) 复现步骤
    let mut repro: Vec<String> = Vec::new();
    if let Some(id) = chain_id {
        repro.push(format!("ctx-audit chain . --id {id} -o json"));
    }
    if !ef.is_empty() && !sf.is_empty() {
        repro.push(format!(
            "ctx-audit payload viability . --entry-file {ef} --entry-line {el} --sink-file {sf} --sink-line {sl} --archetype {archetype} -o json"
        ));
    }
    if let Some(h) = harness.as_ref() {
        if let Some(curl) = h["curl"].as_str() {
            repro.push(format!("# 请求骨架（MARKER 占位）：{curl}"));
        }
    }
    repro.push(format!(
        "# 动态验证（需 CTX_AUDIT_VERIFY_DIR 指向 fixture 目录）：ctx-audit verify . --file {ef} --function <handler> --payload MARKER --archetype {archetype} -o json"
    ));

    Ok(json!({
        "schema": "poc-package/v1",
        "project": project.to_string_lossy(),
        "chain": {
            "chain_id": chain_id,
            "entry": entry,
            "sink": sink,
            "steps": steps,
            "step_count": steps.len(),
        },
        "verdict": {
            "payload_tier": tier,
            "viability": payload["viability"].clone(),
            "reachable": payload["reachable"].clone(),
            "killed_at": payload["killed_at"].clone(),
            "taint_lost_at": payload["taint_lost_at"].clone(),
            "archetype": archetype,
        },
        "topology": {
            "format": "mermaid",
            "diagram": mermaid,
        },
        "request": harness.as_ref().map(|h| json!({
            "method": h["method"].clone(),
            "route": h["route"].clone(),
            "params": h["params"].clone(),
            "curl": h["curl"].clone(),
            "test_skeleton": h["test_skeleton"].clone(),
        })),
        "guard_gap": {
            "effective": effective,
            "ineffective": ineffective,
            "unknown": unknown,
            "summary": format!(
                "{} effective / {} ineffective / {} unknown",
                effective.len(), ineffective.len(), unknown.len()
            ),
        },
        "remediation": remediation,
        "reproduce": repro,
        "limits": [
            "静态打包，未执行任何请求",
            "请求骨架为启发式参数绑定，需人工补全类型与业务约束",
            "动态验证需显式开启 CTX_AUDIT_VERIFY_DIR",
        ],
        "uncertainty": {
            "level": "medium",
            "reasons": ["name_level_graph", "heuristic_param_binding", "static_only"],
        },
    }))
}
