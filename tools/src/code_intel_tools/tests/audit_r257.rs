// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0
//! R257 审计驾驶舱测试：覆盖率摘要、排序、证据包写盘。

use super::*;
use crate::code_intel_tools::audit_bundle;
use crate::code_intel_tools::audit_write;
use serde_json::json;
use std::path::PathBuf;

fn write_file(root: &PathBuf, rel: &str, content: &str) {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(p, content).unwrap();
}

fn fixture(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ctx-audit-r257-audit-{tag}"));
    let _ = std::fs::remove_dir_all(&root);
    write_file(
        &root,
        "src/main/java/app/SaTokenConfigure.java",
        concat!(
            "package app;\n",
            "@Configuration\n",
            "public class SaTokenConfigure {\n",
            "  public void addInterceptors(InterceptorRegistry registry) {\n",
            "    registry.addInterceptor(new SaInterceptor(h -> {\n",
            "      SaRouter.match(\"/admin/**\", () -> StpUtil.checkLogin());\n",
            "    })).addPathPatterns(\"/**\");\n",
            "  }\n",
            "}\n",
        ),
    );
    write_file(
        &root,
        "src/main/java/app/AdminController.java",
        concat!(
            "package app;\n",
            "@RestController\n",
            "@RequestMapping(\"/admin\")\n",
            "public class AdminController {\n",
            "  @PostMapping(\"/export\")\n",
            "  public String export() { return \"ok\"; }\n",
            "}\n",
        ),
    );
    write_file(
        &root,
        "src/main/java/app/PublicController.java",
        concat!(
            "package app;\n",
            "@RestController\n",
            "@RequestMapping(value = {\"/a\", \"/b\"})\n",
            "public class PublicController {\n",
            "  @PostMapping(\"/danger\")\n",
            "  public String danger() { return \"ok\"; }\n",
            "  @GetMapping(\"/ping\")\n",
            "  public String ping() { return \"ok\"; }\n",
            "}\n",
        ),
    );
    root
}

#[test]
fn test_audit_bundle_lists_uncovered_and_ranks_writes_first() {
    let root = fixture("bundle");
    let bundle = audit_bundle(&root).expect("bundle");
    let cov = &bundle["coverage"];
    assert_eq!(cov["method_routes"].as_u64().unwrap(), 5, "{cov}");
    assert_eq!(cov["uncovered"].as_u64().unwrap(), 4, "{cov}");
    let items = bundle["worklist"].as_array().unwrap();
    assert_eq!(items.len(), 4, "{items:?}");
    // 写方法应排在读方法前
    assert_eq!(items[0]["method"], "POST");
    assert_eq!(items[0]["signals"][0], "state_changing");
    // 多前缀展开：/a/danger 与 /b/danger 都要有
    let routes: Vec<&str> = items.iter().filter_map(|i| i["route"].as_str()).collect();
    assert!(routes.contains(&"/a/danger"), "{routes:?}");
    assert!(routes.contains(&"/b/danger"), "{routes:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn test_audit_write_creates_cockpit_artifacts() {
    let root = fixture("write");
    let out = root.join("report");
    let written = audit_write(&root, &out, 0).expect("write");
    for name in ["coverage.md", "worklist.md", "worklist.json", "snapshot.json"] {
        assert!(
            written.iter().any(|p| p.ends_with(name)),
            "缺少 {name}: {written:?}"
        );
    }
    let wl = std::fs::read_to_string(out.join("worklist.md")).unwrap();
    assert!(wl.contains("/a/danger"), "{wl}");
    assert!(wl.contains("evidence/"), "{wl}");
    assert!(out.join("evidence/F001.md").exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn test_dynamic_registration_signal_reported() {
    let root = std::env::temp_dir().join("ctx-audit-r257-dynamic");
    let _ = std::fs::remove_dir_all(&root);
    write_file(
        &root,
        "src/main/java/app/DynamicRegistrar.java",
        concat!(
            "package app;\n",
            "public class DynamicRegistrar {\n",
            "  @EventListener(ApplicationReadyEvent.class)\n",
            "  public void init() {\n",
            "    RequestMappingInfo info = RequestMappingInfo.paths(\"/x\").build();\n",
            "    mapping.registerMapping(info, this, method);\n",
            "  }\n",
            "}\n",
        ),
    );
    let bundle = audit_bundle(&root).expect("bundle");
    assert!(
        bundle["coverage"]["dynamic_endpoint_registrations"]
            .as_u64()
            .unwrap_or(0)
            >= 1,
        "必须报告动态注册端点: {}",
        bundle["coverage"]
    );
    let _ = std::fs::remove_dir_all(&root);
}
