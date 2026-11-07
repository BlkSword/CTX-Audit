// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 受限的本地动态验证器（Python fixture 专用）。
//!
//! 安全边界（必须显式开启，默认不可用）：
//! - 环境变量 `CTX_AUDIT_VERIFY_DIR` 必须指向允许目录；目标文件 canonical 后必须在其下；
//! - 仅接受 `.py` 文件；仅支持 sql / ssrf 两类载荷；
//! - 通过 `python3 -c` 执行目标源码，注入 fake DB cursor / fake requests；
//! - 本工具不做网络/文件系统沙箱，只保证注入依赖不产生真实外部调用；
//!   仅应用于本地 fixture，不要指向生产代码。

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

const BOOTSTRAP: &str = r#"
import sys, json, types, os as _os
try:
    import urllib.parse as _up
except Exception:
    _up = None
path, fn, payload, arch = sys.argv[1:5]
calls = []
class Resp:
    def __init__(self, url):
        self.url = url
        self.text = "<ok>"
class Cur:
    def execute(self, sql, *args):
        calls.append({"kind": "sql", "sql": str(sql), "args": [str(a) for a in args]})
        return self
def fake_get(url, *a, **k):
    calls.append({"kind": "http", "url": str(url)})
    return Resp(url)
def fake_open(p, *a, **k):
    calls.append({"kind": "path", "path": str(p)})
    class F:
        def read(self): return "<data>"
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
    return F()
def fake_system(cmd):
    calls.append({"kind": "cmd", "cmd": str(cmd)})
    return 0
fake_requests = types.SimpleNamespace(get=fake_get, post=fake_get)
urllib_mod = types.SimpleNamespace(parse=_up) if _up else types.SimpleNamespace()
os_mod = types.SimpleNamespace(system=fake_system, path=_os.path, sep=_os.sep, getcwd=lambda: "/data")
ns = {"cur": Cur(), "requests": fake_requests, "urllib": urllib_mod, "open": fake_open, "os": os_mod}
src = open(path, encoding="utf-8", errors="replace").read()
exec(compile(src, path, "exec"), ns)
raised = None
try:
    ns[fn](payload)
except Exception as e:
    raised = f"{type(e).__name__}: {e}"
print(json.dumps({"calls": calls, "raised": raised}))
"#;

fn python_cmd() -> &'static str {
    if cfg!(windows) {
        "python"
    } else {
        "python3"
    }
}

pub(crate) fn classify_verify(calls: &[Value], raised: Option<&str>, payload: &str, arch: &str) -> (String, Value) {
    match arch {
        "sql" => {
            let last = calls.iter().rev().find(|c| c["kind"] == "sql");
            match last {
                Some(c) => {
                    let sql = c["sql"].as_str().unwrap_or("");
                    let in_sql = sql.contains(payload);
                    let in_args = c["args"]
                        .as_array()
                        .map(|a| a.iter().any(|v| v.as_str().map(|s| s.contains(payload)).unwrap_or(false)))
                        .unwrap_or(false);
                    if in_sql {
                        ("payload_verified".to_string(), json!({"sql": sql, "payload_in_sql": true}))
                    } else if in_args {
                        ("verified_killed".to_string(), json!({"sql": sql, "payload_bound_as_parameter": true}))
                    } else {
                        ("inconclusive".to_string(), json!({"sql": sql}))
                    }
                }
                None => ("inconclusive".to_string(), json!({"reason": "no_sql_call"})),
            }
        }
        "path" => {
            let last = calls.iter().rev().find(|c| c["kind"] == "path");
            match last {
                Some(c) => {
                    let raw = c["path"].as_str().unwrap_or("");
                    let escaped = raw.contains("/../") || raw.contains("\\..\\") || !raw.starts_with("/data/");
                    if escaped {
                        ("payload_verified".to_string(), json!({"resolved_path": raw, "escaped_base": true}))
                    } else {
                        ("verified_killed".to_string(), json!({"resolved_path": raw, "escaped_base": false}))
                    }
                }
                None => ("verified_killed".to_string(), json!({"raised": raised, "reason": "blocked_before_open"})),
            }
        }
        "command" => {
            let hit = calls
                .iter()
                .any(|c| c["cmd"].as_str().map(|v| v.contains(payload)).unwrap_or(false));
            if hit {
                ("payload_verified".to_string(), json!({"command_contains_payload": true}))
            } else {
                ("verified_killed".to_string(), json!({"raised": raised, "reason": "not_executed"}))
            }
        }
        "ssrf" => {
            let sent = calls.iter().any(|c| c["url"].as_str() == Some(payload));
            if sent {
                ("payload_verified".to_string(), json!({"request_sent": true}))
            } else if raised.is_some() && calls.is_empty() {
                ("verified_killed".to_string(), json!({"raised": raised}))
            } else {
                ("inconclusive".to_string(), json!({"calls": calls.len()}))
            }
        }
        _ => ("unsupported_archetype".to_string(), json!({})),
    }
}

pub fn verify_payload_report(
    project: &Path,
    file: &str,
    function: &str,
    payload: &str,
    archetype: &str,
) -> Result<Value, String> {
    let allow_env = match std::env::var("CTX_AUDIT_VERIFY_DIR") {
        Ok(v) => v,
        Err(_) => {
            return Ok(json!({
                "schema": "verify/v1",
                "tier": "disabled",
                "reason": "dynamic_verification_not_enabled",
                "enable": "设置 CTX_AUDIT_VERIFY_DIR 指向允许的本地 fixture 目录",
                "sandbox": {"network_enforced": false},
            }));
        }
    };
    let allow = PathBuf::from(&allow_env)
        .canonicalize()
        .map_err(|e| format!("CTX_AUDIT_VERIFY_DIR 无效: {e}"))?;
    if !file.ends_with(".py") {
        return Err("动态验证仅支持 Python 文件".to_string());
    }
    let target = project
        .join(file)
        .canonicalize()
        .map_err(|e| format!("目标文件无效: {e}"))?;
    if !target.starts_with(&allow) {
        return Err(format!(
            "目标文件不在允许目录内：{} 不在 {} 下",
            target.display(),
            allow.display()
        ));
    }
    let arch = match archetype {
        "sql" | "ssrf" | "path" | "command" => archetype,
        _ => return Err("动态验证支持的载荷类型：sql / ssrf / path / command".to_string()),
    };
    let out = Command::new(python_cmd())
        .arg("-c")
        .arg(BOOTSTRAP)
        .arg(&target)
        .arg(function)
        .arg(payload)
        .arg(arch)
        .output()
        .map_err(|e| format!("无法执行 python: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "python 执行失败: {}",
            String::from_utf8_lossy(&out.stderr).chars().take(300).collect::<String>()
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| "动态验证未产生结果".to_string())?;
    let res: Value = serde_json::from_str(line).map_err(|e| format!("结果解析失败: {e}"))?;
    let calls = res["calls"].as_array().cloned().unwrap_or_default();
    let raised = res["raised"].as_str();
    let (tier, evidence) = classify_verify(&calls, raised, payload, arch);
    Ok(json!({
        "schema": "verify/v1",
        "file": file,
        "function": function,
        "archetype": arch,
        "payload": payload,
        "tier": tier,
        "evidence": evidence,
        "sandbox": {
            "runner": "python3",
            "injected": ["fake cur", "fake requests", "urllib.parse"],
            "network_enforced": false,
            "note": "仅保证注入依赖不产生真实外部调用；只应指向本地 fixture",
        },
        "uncertainty": {"level": "low", "reasons": ["dynamic_execution_of_fixture_only"]},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_classification() {
        let calls = vec![json!({"kind": "sql", "sql": "SELECT * FROM t WHERE n = 'x'", "args": []})];
        let (t, _) = classify_verify(&calls, None, "x", "sql");
        assert_eq!(t, "payload_verified");
        let calls2 = vec![json!({"kind": "sql", "sql": "SELECT * FROM t WHERE n = ?", "args": ["x"]})];
        let (t2, _) = classify_verify(&calls2, None, "x", "sql");
        assert_eq!(t2, "verified_killed");
    }

    #[test]
    fn path_classification() {
        let calls = vec![json!({"kind": "path", "path": "/data/../../etc/passwd"})];
        let (t, _) = classify_verify(&calls, None, "../../etc/passwd", "path");
        assert_eq!(t, "payload_verified");
        let calls2 = vec![json!({"kind": "path", "path": "/data/safe.txt"})];
        let (t2, _) = classify_verify(&calls2, None, "../../etc/passwd", "path");
        assert_eq!(t2, "verified_killed");
        let (t3, _) = classify_verify(&[], Some("ValueError: blocked"), "../../etc/passwd", "path");
        assert_eq!(t3, "verified_killed");
    }

    #[test]
    fn command_classification() {
        let calls = vec![json!({"kind": "cmd", "cmd": "echo pwned"})];
        let (t, _) = classify_verify(&calls, None, "pwned", "command");
        assert_eq!(t, "payload_verified");
        let (t2, _) = classify_verify(&[], Some("ValueError: blocked"), "pwned", "command");
        assert_eq!(t2, "verified_killed");
    }

    #[test]
    fn ssrf_classification() {
        let calls = vec![json!({"kind": "http", "url": "http://evil/"})];
        let (t, _) = classify_verify(&calls, None, "http://evil/", "ssrf");
        assert_eq!(t, "payload_verified");
        let (t2, _) = classify_verify(&[], Some("ValueError: blocked"), "http://evil/", "ssrf");
        assert_eq!(t2, "verified_killed");
    }
}
