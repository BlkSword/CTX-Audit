// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 受限的 Java 动态验证器（本地 fixture 专用）。
//!
//! 与 Python / Node 验证器同一安全边界：必须显式设置 `CTX_AUDIT_VERIFY_DIR`，
//! 目标文件 canonical 后必须在其下；只编译并运行本地 fixture，不做网络/文件系统沙箱。
//!
//! 做法：把 fixture 复制到临时目录，注入桩类型（`CtxAuditStubs`）与桩字段，
//! 用 `javac` 编译、`java` 运行，桩在危险汇被调用时记录调用参数，最后按
//! archetype 判定载荷是否到达汇。

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

/// 桩类型：记录危险汇调用，不产生真实副作用。
const JAVA_STUBS: &str = r#"
import java.util.*;

/** 桩：记录危险汇调用，不产生真实副作用。 */
public class CtxAuditStubs {
    public static final List<String> CALLS = new ArrayList<>();
    public static String PAYLOAD = "";

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }

    static void record(String kind, String key, String value) {
        CALLS.add("{\"kind\":\"" + kind + "\",\"" + key + "\":\"" + esc(value) + "\"}");
    }

    public static class Conn {
        public Statement createStatement() { return new Statement(); }
        public PreparedStatement prepareStatement(String s) { return new PreparedStatement(); }
    }

    public static class Resp {
        public String body() { return "<ok>"; }
        public int statusCode() { return 200; }
    }

    public static class Http {
        public Resp get(String url) { record("http", "url", url); return new Resp(); }
        public Resp post(String url, String body) { return get(url); }
    }

    public static class Expr {
        public String getValue() { return "<v>"; }
        public String getValue(Object root) { return "<v>"; }
    }

    public static class Parser {
        public Expr parseExpression(String s) { record("template", "src", s); return new Expr(); }
    }

    public static class Simple {
        public String render(String s) { record("template", "src", s); return s; }
    }

    public static class Ois {
        private java.io.ObjectInputFilter filter;
        public Ois(java.io.InputStream in) {}
        public void setObjectInputFilter(java.io.ObjectInputFilter f) { this.filter = f; }
        public void close() {}
        public Object readObject() {
            if (filter != null) {
                java.io.ObjectInputFilter.FilterInfo info = new java.io.ObjectInputFilter.FilterInfo() {
                    public Class<?> serialClass() { return null; }
                    public long arrayLength() { return -1; }
                    public long depth() { return 0; }
                    public long references() { return 0; }
                    public long streamBytes() { return 0; }
                };
                java.io.ObjectInputFilter.Status st = filter.checkInput(info);
                if (st == java.io.ObjectInputFilter.Status.REJECTED) {
                    throw new IllegalArgumentException("filter rejected");
                }
            }
            record("deserialize", "data", PAYLOAD);
            return "<obj>";
        }
    }

    public static Ois ois(java.io.InputStream in) { return new Ois(in); }

    public static Process cmd(String c) { record("cmd", "cmd", c); return null; }

    public static Object jndi(String u) { record("jndi", "url", u); return null; }
}
"#;

/// 默认包里的 Statement 桩（fixture 常写 `Statement st = conn.createStatement();`）。
const JAVA_STATEMENT: &str = r#"
public class Statement {
    public void executeQuery(String sql) { CtxAuditStubs.record("sql", "sql", sql); }
    public void execute(String sql) { executeQuery(sql); }
    public void executeUpdate(String sql) { executeQuery(sql); }
    public boolean execute() { return true; }
    public java.sql.ResultSet executeQuery() { return null; }
}
"#;

/// 默认包里的 PreparedStatement 桩（参数化查询：不记录拼接串）。
const JAVA_PREPARED: &str = r#"
public class PreparedStatement {
    public void setString(int i, String v) {}
    public void setInt(int i, int v) {}
    public void setObject(int i, Object v) {}
    public void setLong(int i, long v) {}
    public void executeQuery() {}
    public void executeUpdate() {}
    public boolean execute() { return true; }
}
"#;

/// 运行器：反射调用目标方法，输出桩记录。
const JAVA_HARNESS: &str = r#"
public class CtxAuditHarness {
    public static void main(String[] a) throws Exception {
        String cls = a[0], fn = a[1], payload = a[2];
        CtxAuditStubs.PAYLOAD = payload;
        Class<?> c = Class.forName(cls);
        Object inst = c.getDeclaredConstructor().newInstance();
        java.lang.reflect.Method m = null;
        for (java.lang.reflect.Method cand : c.getDeclaredMethods()) {
            if (cand.getName().equals(fn) && cand.getParameterCount() == 1) { m = cand; break; }
        }
        if (m == null) { System.out.println("{\"error\":\"method_not_found\"}"); return; }
        m.setAccessible(true);
        Class<?> pt = m.getParameterTypes()[0];
        Object arg;
        if (pt == byte[].class) arg = payload.getBytes("UTF-8");
        else if (pt == int.class || pt == Integer.class) arg = Integer.parseInt(payload);
        else arg = payload;
        String raised = null;
        try { m.invoke(inst, arg); }
        catch (Throwable t) {
            Throwable cause = t.getCause() == null ? t : t.getCause();
            raised = cause.getClass().getName() + ": " + String.valueOf(cause.getMessage());
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{\"calls\":[");
        boolean first = true;
        for (String call : CtxAuditStubs.CALLS) {
            if (!first) sb.append(",");
            first = false;
            sb.append(call);
        }
        sb.append("],\"raised\":");
        if (raised == null) sb.append("null");
        else sb.append("\"").append(raised.replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
        sb.append("}");
        System.out.println(sb.toString());
    }
}
"#;

fn java_cmd() -> &'static str {
    "java"
}

fn javac_cmd() -> &'static str {
    "javac"
}

/// 从源码里取第一个类名与可选包名。
fn class_and_package(src: &str) -> (String, Option<String>) {
    let mut package = None;
    for line in src.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("package ") {
            let name = rest.trim_end_matches(';').trim().to_string();
            if !name.is_empty() {
                package = Some(name);
            }
            break;
        }
        if t.starts_with("public class ") || t.starts_with("class ") {
            break;
        }
    }
    let mut class = String::new();
    for line in src.lines() {
        let t = line.trim();
        for kw in ["public class ", "class ", "public final class "] {
            if let Some(rest) = t.strip_prefix(kw) {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    class = name;
                    break;
                }
            }
        }
        if !class.is_empty() {
            break;
        }
    }
    (class, package)
}

/// 注入桩字段：只注入源码里没有声明的标识符。
fn inject_stub_fields(src: &str, class: &str) -> String {
    let mut fields = String::new();
    let candidates = [
        ("conn", "CtxAuditStubs.Conn"),
        ("http", "CtxAuditStubs.Http"),
        ("parser", "CtxAuditStubs.Parser"),
        ("simple", "CtxAuditStubs.Simple"),
    ];
    for (name, ty) in candidates {
        // 已声明（字段/参数/局部变量）则跳过，避免重复定义
        let declared = src.contains(&format!("{ty} {name}"))
            || src.contains(&format!("{name} ="))
            || src.contains(&format!("{name};"))
            || src.contains(&format!("{name},"))
            || src.contains(&format!("{name})"));
        if !declared {
            fields.push_str(&format!("    static {ty} {name} = new {ty}();\n"));
        }
    }
    if fields.is_empty() {
        return src.to_string();
    }
    let needle = format!("class {class}");
    if let Some(pos) = src.find(&needle) {
        if let Some(brace) = src[pos..].find('{') {
            let at = pos + brace + 1;
            let mut out = String::with_capacity(src.len() + fields.len());
            out.push_str(&src[..at]);
            out.push('\n');
            out.push_str(&fields);
            out.push_str(&src[at..]);
            return out;
        }
    }
    src.to_string()
}

/// 补齐 fixture 常缺的 import（只补标准库，不引入第三方依赖）。
fn inject_imports(src: &str) -> String {
    let needed = [
        "java.sql.Connection",
        "java.io.InputStream",
        "java.io.ByteArrayInputStream",
        "java.io.ObjectInputStream",
        "java.io.ObjectInputFilter",
        "java.util.Set",
        "java.util.List",
        "java.util.ArrayList",
        "java.net.URI",
    ];
    let mut missing: Vec<&str> = Vec::new();
    for imp in needed {
        let simple = imp.rsplit('.').next().unwrap_or(imp);
        // 源码里已 import 或已定义同名类则跳过
        if src.contains(&format!("import {imp};")) || src.contains(&format!("class {simple}")) {
            continue;
        }
        // 只有源码确实用到该简单名才补
        if src.contains(simple) {
            missing.push(imp);
        }
    }
    if missing.is_empty() {
        return src.to_string();
    }
    let mut imports = String::new();
    for imp in missing {
        imports.push_str(&format!("import {imp};\n"));
    }
    // 放在 package 之后（若有），否则文件最前
    if let Some(pos) = src.find(';') {
        let head = &src[..=pos];
        if head.trim_start().starts_with("package ") {
            let mut out = String::with_capacity(src.len() + imports.len());
            out.push_str(head);
            out.push('\n');
            out.push_str(&imports);
            out.push_str(&src[pos + 1..]);
            return out;
        }
    }
    format!("{imports}{src}")
}

/// 危险 API 替换为桩调用（保持括号平衡）。
fn instrument_sinks(src: &str) -> String {
    src.replace("java.sql.Statement ", "Statement ")
        .replace("java.sql.PreparedStatement ", "PreparedStatement ")
        .replace("Runtime.getRuntime().exec(", "CtxAuditStubs.cmd(")
        .replace("new javax.naming.InitialContext().lookup(", "CtxAuditStubs.jndi(")
        .replace("new java.io.ObjectInputStream(", "CtxAuditStubs.ois(")
        .replace("new ObjectInputStream(", "CtxAuditStubs.ois(")
        // 类型声明改写成桩类型（readObject 在真实类里是 final，无法继承覆盖）
        .replace("java.io.ObjectInputStream ", "CtxAuditStubs.Ois ")
        .replace("ObjectInputStream ", "CtxAuditStubs.Ois ")
}

fn classify_java(calls: &[Value], raised: Option<&str>, payload: &str, archetype: &str) -> (String, Value) {
    let kind_of = |c: &Value| c.get("kind").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let text_of = |c: &Value| {
        c.get("sql")
            .or_else(|| c.get("url"))
            .or_else(|| c.get("cmd"))
            .or_else(|| c.get("src"))
            .or_else(|| c.get("data"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let expected = match archetype {
        "sql" => "sql",
        "ssrf" => "http",
        "command" => "cmd",
        "template" => "template",
        "deserialize" => "deserialize",
        "jndi" => "jndi",
        "path" => "path",
        _ => "",
    };
    let hit = calls.iter().find(|c| kind_of(c) == expected);
    match hit {
        Some(call) => {
            let text = text_of(call);
            let carries = text.contains(payload);
            let tier = if carries { "payload_verified" } else { "payload_reached_without_marker" };
            (
                tier.to_string(),
                json!({
                    "sink_kind": expected,
                    "sink_argument": text,
                    "payload_in_argument": carries,
                    "raised": raised,
                }),
            )
        }
        None => (
            "verified_killed".to_string(),
            json!({
                "sink_kind": expected,
                "reason": if raised.is_some() { "guard_rejected_before_sink" } else { "sink_not_reached" },
                "raised": raised,
            }),
        ),
    }
}

/// Java 动态验证入口。
pub fn java_verify(
    target: &Path,
    file: &str,
    function: &str,
    payload: &str,
    archetype: &str,
) -> Result<Value, String> {
    let src = std::fs::read_to_string(target).map_err(|e| format!("读取 Java 文件失败: {e}"))?;
    let (class, package) = class_and_package(&src);
    if class.is_empty() {
        return Err("无法从 Java 源码中识别类名".to_string());
    }
    let with_imports = inject_imports(&src);
    let instrumented = instrument_sinks(&inject_stub_fields(&with_imports, &class));

    let dir = std::env::temp_dir().join(format!(
        "ctx-audit-java-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    let pkg_dir = match &package {
        Some(p) => dir.join(p.replace('.', "/")),
        None => dir.clone(),
    };
    std::fs::create_dir_all(&pkg_dir).map_err(|e| format!("创建临时目录失败: {e}"))?;

    // 具名包里的类不能引用默认包类，所以桩与 harness 都要带同样的 package 声明。
    let pkg_line = match &package {
        Some(p) => format!("package {p};\n"),
        None => String::new(),
    };
    let write = |name: &str, body: &str| -> Result<PathBuf, String> {
        let p = pkg_dir.join(name);
        let full = if body.starts_with("package ") {
            body.to_string()
        } else {
            format!("{pkg_line}{body}")
        };
        std::fs::write(&p, full).map_err(|e| format!("写入 {name} 失败: {e}"))?;
        Ok(p)
    };
    write(&format!("{class}.java"), &instrumented)?;
    write("CtxAuditStubs.java", JAVA_STUBS)?;
    write("Statement.java", JAVA_STATEMENT)?;
    write("PreparedStatement.java", JAVA_PREPARED)?;
    write("CtxAuditHarness.java", JAVA_HARNESS)?;

    let out_dir = dir.join("out");
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("创建输出目录失败: {e}"))?;

    let mut sources: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&pkg_dir).map_err(|e| format!("列目录失败: {e}"))? {
        let p = entry.map_err(|e| format!("读目录项失败: {e}"))?.path();
        if p.extension().and_then(|e| e.to_str()) == Some("java") {
            sources.push(p);
        }
    }

    let compile = Command::new(javac_cmd())
        .arg("-nowarn")
        .arg("-d")
        .arg(&out_dir)
        .args(&sources)
        .output()
        .map_err(|e| format!("无法执行 javac: {e}"))?;
    if !compile.status.success() {
        let err = String::from_utf8_lossy(&compile.stderr);
        let _ = std::fs::remove_dir_all(&dir);
        return Ok(json!({
            "schema": "verify/v1",
            "file": file,
            "function": function,
            "archetype": archetype,
            "tier": "compile_failed",
            "evidence": {"stderr": err.chars().take(600).collect::<String>()},
            "sandbox": {"runner": "javac+java", "network_enforced": false},
            "uncertainty": {"level": "high", "reasons": ["fixture_does_not_compile"]},
        }));
    }

    let fqcn = match &package {
        Some(p) => format!("{p}.{class}"),
        None => class.clone(),
    };
    let harness_fqcn = match &package {
        Some(p) => format!("{p}.CtxAuditHarness"),
        None => "CtxAuditHarness".to_string(),
    };
    let run = Command::new(java_cmd())
        .arg("-cp")
        .arg(&out_dir)
        .arg(&harness_fqcn)
        .arg(&fqcn)
        .arg(function)
        .arg(payload)
        .output()
        .map_err(|e| format!("无法执行 java: {e}"))?;
    let _ = std::fs::remove_dir_all(&dir);

    if !run.status.success() {
        return Err(format!(
            "java 执行失败: {}",
            String::from_utf8_lossy(&run.stderr)
                .chars()
                .take(400)
                .collect::<String>()
        ));
    }
    let stdout = String::from_utf8_lossy(&run.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| "Java 动态验证未产生结果".to_string())?;
    let res: Value = serde_json::from_str(line).map_err(|e| format!("结果解析失败: {e}"))?;
    if res.get("error").is_some() {
        return Ok(json!({
            "schema": "verify/v1",
            "file": file,
            "function": function,
            "archetype": archetype,
            "tier": "harness_error",
            "evidence": res,
            "sandbox": {"runner": "javac+java", "network_enforced": false},
            "uncertainty": {"level": "high", "reasons": ["method_not_found_or_signature_mismatch"]},
        }));
    }
    let calls = res["calls"].as_array().cloned().unwrap_or_default();
    let raised = res["raised"].as_str();
    let (tier, evidence) = classify_java(&calls, raised, payload, archetype);
    Ok(json!({
        "schema": "verify/v1",
        "file": file,
        "function": function,
        "archetype": archetype,
        "payload": payload,
        "tier": tier,
        "evidence": evidence,
        "calls": calls,
        "sandbox": {
            "runner": "javac+java",
            "injected": ["CtxAuditStubs.Conn/Stmt/PStmt", "Http", "Parser", "Simple", "Ois", "cmd", "jndi"],
            "network_enforced": false,
            "note": "桩替换危险 API，不产生真实外部调用；只应指向本地 fixture",
        },
        "uncertainty": {"level": "low", "reasons": ["dynamic_execution_of_fixture_only"]},
    }))
}
