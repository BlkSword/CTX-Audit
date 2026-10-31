// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0
//! 工具面与通用辅助类测试（续）。

use super::super::*;

    /// 工具级：`get_incremental_status` 的 pending 与命中来源必须来自真实状态。
    #[tokio::test]
    async fn test_incremental_status_reports_real_pending() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-incremental");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/a.rs"), "fn a() {}").unwrap();
        crate::index_cache::invalidate(&root);

        let project = root.to_string_lossy().to_string();
        let tool = CodeIntelTool::new(project.clone(), IntelKind::IncrementalStatus);

        let first = tool.execute(json!({})).await.unwrap();
        let first_env = first.data.clone().expect("应有 envelope data");
        let probe_on = crate::index_cache::probe_enabled();
        assert_eq!(
            first_env["data"]["mode"],
            if probe_on {
                "stat+mtime-probe+ttl-cache"
            } else {
                "stat+ttl-cache"
            }
        );
        assert_eq!(first_env["data"]["cache"]["hit"], false);
        assert_eq!(first_env["data"]["cache"]["hit_source"], "miss");
        assert_eq!(first_env["data"]["pending_recompile"], 0);
        assert!(
            first_env["data"]["fingerprint"]["files"].as_u64().unwrap() >= 1,
            "应记录文件指纹: {first_env}"
        );
        assert!(
            first_env["data"]["slo"]["index_build_ms"].as_u64().is_some(),
            "首次构建后应有构建耗时: {first_env}"
        );

        // 第二次调用：TTL 内应命中，并如实报告命中来源
        let second = tool.execute(json!({})).await.unwrap();
        let second_env = second.data.clone().expect("应有 envelope data");
        assert_eq!(second_env["data"]["cache"]["hit"], true);
        let second_source = second_env["data"]["cache"]["hit_source"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(
            second_source == "ttl" || second_source == "probe",
            "命中来源应为 ttl/probe（取决于 CTX_AUDIT_INDEX_TTL_MS）: {second_source}"
        );

        let status = crate::index_cache::changed_since_build(std::path::Path::new(&project))
            .expect("构建后应有缓存条目");
        assert!(status.is_empty(), "刚构建时不应有待重编译条目: {status:?}");

        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(root.join("src/a.rs"), "fn a() { longer_body(); }").unwrap();
        let status2 = crate::index_cache::changed_since_build(std::path::Path::new(&project))
            .expect("缓存条目仍在");
        assert!(
            status2.iter().any(|p| p == "src/a.rs"),
            "改动文件应进入待重编译: {status2:?}"
        );

        crate::index_cache::invalidate(&root);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_envelope_serializes() {
        let env = IntelEnvelope {
            data: json!({"ok": true}),
            provenance: vec![prov("a.py", 1, "statv1:1f:1b")],
            uncertainty: Uncertainty::new("medium", &["x"], 0),
        };
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["data"]["ok"], true);
        assert_eq!(v["provenance"][0]["file"], "a.py");
        assert_eq!(v["uncertainty"]["level"], "medium");
    }

    #[test]
    fn test_tool_surface_shape() {
        // R257：默认面收敛为 9 个协议工具；其余 7 个细粒度工具进 legacy 面
        assert_eq!(CODE_INTEL_TOOL_SURFACE.len(), 12);
        assert_eq!(IntelKind::all().len(), 18);
        assert_eq!(CODE_INTEL_LEGACY_SURFACE.len(), 7);
        assert!(CODE_INTEL_TOOL_SURFACE.contains(&"get_project_routes"));
        assert!(CODE_INTEL_TOOL_SURFACE.contains(&"coverage_summary"));
        assert!(CODE_INTEL_TOOL_SURFACE.contains(&"coverage_triage"));
        assert!(CODE_INTEL_TOOL_SURFACE.contains(&"assert_verdict"));
        assert!(CODE_INTEL_LEGACY_SURFACE.contains(&"get_incremental_status"));
    }

    /// 缩进语言：callee 扫描必须止于函数体（同文件无关函数不得计入）
    #[test]
    fn test_body_span_indent_language() {
        let src = "def target(request):\n    a = helper_one(request)\n    return helper_two(a)\n\n\ndef unrelated():\n    return other_call()\n";
        let lines: Vec<&str> = src.lines().collect();
        let (start, end) = body_span(&lines, 0, false);
        assert_eq!(start, 0);
        let body = lines[start..=end].join("\n");
        assert!(body.contains("helper_one"), "{body}");
        assert!(body.contains("helper_two"), "{body}");
        assert!(
            !body.contains("other_call"),
            "函数体外的调用不应计入: {body}"
        );
    }

    /// 花括号语言：按配对花括号取体范围
    #[test]
    fn test_body_span_brace_language() {
        let src = "function target(req) {\n    const s = new Store();\n    return s.get(\"k\");\n}\n\nfunction unrelated() {\n    return other();\n}\n";
        let lines: Vec<&str> = src.lines().collect();
        assert_eq!(body_span(&lines, 0, true), (0, 3));
        assert!(is_brace_language("a.js") && is_brace_language("a.go"));
        assert!(!is_brace_language("a.py"));
    }

    /// Go 的匿名函数字面量不是调用点（真实仓库实测：callees 里混进名为 "func" 的条目）
    #[test]
    fn test_callee_names_skips_structural_keywords() {
        let names = callee_names("go func(c *Config) { Validate(c) }()");
        assert!(!names.contains(&"func".to_string()), "{names:?}");
        assert!(!names.contains(&"go".to_string()), "{names:?}");
        assert!(names.contains(&"Validate".to_string()), "{names:?}");

        let names = callee_names("defer func() { cleanup() }()");
        assert_eq!(names, vec!["cleanup".to_string()], "{names:?}");
    }

    /// 缩进语言：多行签名不得把函数体截断（签名收尾行 `) -> int:` 常从第 0 列开始）
    #[test]
    fn test_body_span_indent_multiline_signature() {
        let src = "def outer(\n    a: int,\n) -> int:\n    x = a + 1\n    return x\n\n\ndef other():\n    return 0\n";
        let lines: Vec<&str> = src.lines().collect();
        let (start, end) = body_span(&lines, 0, false);
        assert_eq!(start, 0);
        assert!(
            end >= 4 && end < 7,
            "函数体应覆盖 `return x`(idx 4) 且止于下一个顶层 def(idx 7)：实际 end={end}"
        );
    }

    /// 命名导入别名：JS/TS 花括号清单与 Python `from ... import`
    #[test]
    fn test_import_aliases() {
        let js = "import Store, { put as save, get } from \"./store.js\";\nconst x = 1;\n";
        let aliases = import_aliases(js);
        assert!(
            aliases.contains(&("put".to_string(), "save".to_string())),
            "{aliases:?}"
        );
        assert!(
            aliases.contains(&("get".to_string(), "get".to_string())),
            "{aliases:?}"
        );

        let py = "from pkg.util import Loader as Ldr\nimport os\n";
        let aliases = import_aliases(py);
        assert!(
            aliases.contains(&("Loader".to_string(), "Ldr".to_string())),
            "{aliases:?}"
        );

        // 默认导入 / 命名空间导入不产生别名对
        assert!(import_aliases("import Store from \"./store.js\";\n").is_empty());
        assert!(import_aliases("import * as ns from \"./m.js\";\n").is_empty());
    }

    /// 接口方法声明不是调用点
    #[test]
    fn test_in_interface_block() {
        let src = "type Reader interface {\n    Read(p []byte) (int, error)\n}\n\nfunc run(r Reader) int {\n    n, _ := r.Read(nil)\n    return n\n}\n";
        let lines: Vec<&str> = src.lines().collect();
        assert!(
            in_interface_block(&lines, 1),
            "接口方法声明应判为在 interface 块内"
        );
        assert!(
            !in_interface_block(&lines, 5),
            "函数体里的真实调用点不应被判为接口块"
        );
    }

    /// 标识符边界：`App` 不得命中 `_AppCtxGlobals`，`copy` 不得命中 `deepcopy`
    #[test]
    fn test_contains_identifier_boundaries() {
        assert!(contains_identifier("    const s = new Store();", "Store"));
        assert!(!contains_identifier("class _AppCtxGlobals:", "App"));
        assert!(!contains_identifier("import deepcopy", "copy"));
        assert!(contains_identifier("x = copy.copy(y)", "copy"));
        // 带点/其它符号的查询退化为子串匹配（保持旧语义）
        assert!(contains_identifier("a.b.c", "b.c"));
    }

    /// 调用点左边界：`myread(` 不算 `read(` 的调用点
    #[test]
    fn test_call_site_match_left_boundary() {
        assert!(call_site_match("    return loader.load(request)", "load"));
        assert!(!call_site_match("    return myread(buf)", "read"));
        assert!(call_site_match("n, _ := r.Read(buf)", "Read"));
    }
    /// **函数体内局部声明不得夺取函数归属**（同族缺陷在"局部声明的体覆盖成立"形态上的复现）：
    /// 符号索引的 `struct` 关键字路径若把 `struct X *p = NULL;`（函数体内、缩进）记为定义，
    /// 而该行之后最近的 `{`（`} else if (…) {`）让它的 body_span 覆盖目标行，则
    /// `max_by_key(def_line)` 会选中这一行、盖过真正的函数头 ⇒ `function` 变成类型名。
    /// 期望：`function` 是真正的函数名，`function_def_line` 是函数头行。
    #[tokio::test]
    async fn test_slice_local_declaration_does_not_steal_function_scope() {
        let root = std::env::temp_dir().join("ctx-audit-slice-c-localdecl");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = concat!(
            "static char *reverse_rewrite_url(struct reversepath *reverse, char *url)\n",
            "{\n",
            "    char *reversepath = NULL;\n",
            "    struct reversepath *rp = NULL;\n",
            "    if (reverse == NULL) {\n",
            "        return NULL;\n",
            "    } else if (reverse->path != NULL) {\n",
            "        rp = reverse;\n",
            "        reversepath = rewrite_url(rp->path, url);\n",
            "    }\n",
            "    return reversepath;\n",
            "}\n",
        );
        std::fs::write(root.join("src/rev.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/rev.c", "line": 9, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(
            d["data"]["function"], "reverse_rewrite_url",
            "局部声明行不得夺取归属: {d}"
        );
        assert_eq!(d["data"]["function_def_line"], 1, "{d}");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        assert_eq!(d["data"]["includes_function_header"], true, "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 索引期上报的源码侧条件编译宏：只报字面事实（出现次数、是否在源码里被定义），
    /// 非 C 类文件不参与统计，构建配置的取值不由本字段推断。
    #[test]
    fn source_conditionals_reports_branch_macros() {
        let files = vec![
            (
                "src/a.c".to_string(),
                concat!(
                    "#define WITH_TEST 1\n",
                    "#if defined(WITH_TEST) && HAVE_ZLIB\n",
                    "int x;\n",
                    "#elif defined(OTHER_MACRO)\n",
                    "#endif\n",
                    "#ifdef FALLBACK_X\n",
                    "#endif\n",
                )
                .to_string(),
            ),
            ("README.md".to_string(), "#if not_c_code\n".to_string()),
        ];
        let v = collect_source_conditionals(&files);
        assert_eq!(v["scanned_files"], 1, "只有 C 类文件参与统计: {v}");
        let branches = v["branches"].as_array().unwrap();
        let names: Vec<&str> = branches
            .iter()
            .map(|b| b["macro"].as_str().unwrap())
            .collect();
        for expected in ["WITH_TEST", "HAVE_ZLIB", "OTHER_MACRO", "FALLBACK_X"] {
            assert!(names.contains(&expected), "应报出 {expected}: {v}");
        }
        let with_test = branches
            .iter()
            .find(|b| b["macro"] == "WITH_TEST")
            .unwrap();
        assert_eq!(with_test["defined_in_source"], true, "{v}");
        let fallback = branches
            .iter()
            .find(|b| b["macro"] == "FALLBACK_X")
            .unwrap();
        assert_eq!(fallback["defined_in_source"], false, "{v}");
    }
