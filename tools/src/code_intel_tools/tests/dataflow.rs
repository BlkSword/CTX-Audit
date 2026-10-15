// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0
//! 工具面与通用辅助类测试（envelope、增量状态、语言/花括号体、别名与标识符边界）。

use super::super::*;

    /// `path` 是**行区间**而不是数据流链：必须显式标注 `path_kind`/`dataflow_verified`/
    /// `span_statistics`，否则消费者会把区间里的原型声明当证据（实测真实 C 文件里这类行占多数）。
    #[tokio::test]
    async fn test_dataflow_path_is_labelled_as_line_span_not_chain() {
        let root = std::env::temp_dir().join("ctx-audit-df-span-label");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        // source 在第 1 行、sink 在第 4 行 ⇒ 区间覆盖中间两条原型声明
        std::fs::write(
            root.join("src/a.c"),
            "int src = 0;\nstatic int helper(int a, char *b);\nstatic int other(void);\nint sink = 0;\n",
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::DataflowPath);
        let out = tool
            .execute(json!({"source": "src", "sink": "sink"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["path_kind"], "source_sink_line_span", "{d}");
        assert_eq!(d["data"]["dataflow_verified"], false, "{d}");
        // C 不受分析管线支持：必须显式标注，并明确"不推荐用于可达性判定"
        assert_eq!(d["data"]["language_analysis_backed"], false, "{d}");
        assert_eq!(d["data"]["recommended_for_reachability"], false, "{d}");
        assert!(d["data"]["recommendation"].as_str().unwrap().contains("get_call_hierarchy"), "{d}");
        assert!(
            d["data"]["path_note"].as_str().unwrap().contains("行区间"),
            "必须明说这是行区间: {d}"
        );
        assert!(
            d["data"]["span_statistics"]["declaration_like_lines"]
                .as_u64()
                .unwrap()
                >= 2,
            "区间里的原型行必须被计数（噪声可见）: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// source 模型去噪（只作用于 MCP 只读证据面）：来源看起来是本地配置/命令行时，
    /// 必须在 uncertainty 里追加 `source_may_be_local_configuration` 并给出 `source_origin`；
    /// 普通来源不得被误标（标注是噪声，不是结论）。
    #[tokio::test]
    async fn test_dataflow_annotates_local_configuration_source() {
        // 分类器口径（纯函数）
        let cli_sig = local_configuration_signals("argv", Some("  char *cfg_path = argv[1];"));
        assert!(cli_sig.contains(&"argv"), "命令行来源应被识别: {cli_sig:?}");
        let env_sig = local_configuration_signals("getenv", Some("  char *p = getenv(\"APP_CFG\");"));
        assert!(env_sig.contains(&"getenv"), "环境变量来源应被识别: {env_sig:?}");
        let plain_sig =
            local_configuration_signals("recv_buf", Some("  n = recv(fd, recv_buf, len, 0);"));
        assert!(
            plain_sig.is_empty(),
            "普通网络来源不得被误标为本地配置: {plain_sig:?}"
        );

        let root = std::env::temp_dir().join("ctx-audit-df-source-origin");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/a.c"),
            "int load (void)\n{\n    char *cfg_path = argv[1];\n    read_cfg (cfg_path);\n    return 0;\n}\n",
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::DataflowPath);
        let out = tool
            .execute(json!({"source": "argv", "sink": "read_cfg"}))
            .await
            .unwrap();
        let env = out.data.clone().expect("应有 envelope data");
        let reasons = env["uncertainty"]["reasons"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            reasons
                .iter()
                .any(|r| r.as_str() == Some("source_may_be_local_configuration")),
            "本地配置/命令行来源必须带噪声标注: {env}"
        );
        assert_eq!(
            env["data"]["source_origin"]["classification"],
            "local_configuration_like",
            "{env}"
        );
        assert!(
            !env["data"]["source_origin"]["signals"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .is_empty(),
            "应给出命中的信号: {env}"
        );

        // 对照：普通来源（网络读入）不得追加该理由
        std::fs::write(
            root.join("src/plain.c"),
            "int copy_in (char *dst, int len)\n{\n    int n = recv (fd, dst, len, 0);\n    return n;\n}\n",
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let out2 = tool
            .execute(json!({"source": "dst", "sink": "recv", "file": "src/plain.c"}))
            .await
            .unwrap();
        let env2 = out2.data.clone().expect("应有 envelope data");
        let reasons2 = env2["uncertainty"]["reasons"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            !reasons2
                .iter()
                .any(|r| r.as_str() == Some("source_may_be_local_configuration")),
            "普通来源不得被标注: {env2}"
        );
        assert_eq!(
            env2["data"]["source_origin"]["classification"], "not_observed",
            "{env2}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 标识符驱动的前向扩展：目标行上的标识符在标称窗口之外还有使用时，窗口应扩到那处
    /// （真实 CVE：`ssize_t len = -1;` 的决定性使用在 +19 行，旧的 40 行上限内够不着）。
    /// `forward: 0` 仍必须是纯后向。
    #[tokio::test]
    async fn test_slice_forward_extends_for_identifier_use() {
        let root = std::env::temp_dir().join("ctx-audit-slice-ident-forward");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let mut src = String::from("int\nwidget_copy (char *dst, int n)\n{\n    int len = -1;\n");
        src.push_str(&"    /* filler */\n".repeat(20));
        src.push_str("    len += 1 + n;\n    return len;\n}\n");
        std::fs::write(root.join("src/f.c"), &src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        // 目标行 = 第 4 行（`int len = -1;`）；`len` 的下一处使用在第 25/26 行
        let out = tool
            .execute(json!({"file": "src/f.c", "line": 4, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let end = d["data"]["window"]["end_line"].as_u64().unwrap();
        assert!(end >= 26, "窗口应扩到 `len` 的使用处: {d}");
        assert_eq!(d["data"]["forward_bounded_by"], "identifier_use", "{d}");
        let drivers = d["data"]["forward_extended_for"].as_array().unwrap();
        assert!(drivers.iter().any(|x| x == "len"), "扩展驱动者应含 len: {d}");
        let reasons = d["uncertainty"]["reasons"].as_array().unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| r == "forward_window_extended_for_identifier_use"),
            "应如实上报窗口被扩展: {d}"
        );

        // `forward: 0` = 纯后向，不得扩展
        let out0 = tool
            .execute(json!({"file": "src/f.c", "line": 4, "depth": 40, "forward": 0}))
            .await
            .unwrap();
        let d0 = out0.data.clone().expect("应有 envelope data");
        assert_eq!(d0["data"]["window"]["end_line"], 4, "{d0}");
        assert_eq!(d0["data"]["forward_extended_for"].as_array().unwrap().len(), 0);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 窗口内标识符的**声明行**必须被交付（真实 CVE：`uint16_t n_columns;` 在目标行上方
    /// 约 170 行，固定窗口够不着；判定缺少"它是 16 位"这一步就推不出回绕）。
    #[tokio::test]
    async fn test_slice_delivers_window_identifier_declaration() {
        let root = std::env::temp_dir().join("ctx-audit-slice-decl-delivery");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let mut src = String::from("struct table_row {\n    unsigned short n_columns;\n};\n");
        src.push_str(&"\n".repeat(45)); // 把声明推到窗口之外（depth=40）
        src.push_str("int\nbuild (struct table_row *row, int n)\n{\n    row->n_columns = 0;\n    while (n > 0) {\n        row->n_columns += 1;\n        n--;\n    }\n    if (row->n_columns == 0) {\n        return -1;\n    }\n    return 0;\n}\n");
        std::fs::write(root.join("src/g.c"), &src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/g.c", "line": 57, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let decls: Vec<&serde_json::Value> = d["data"]["snippets"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s["declaration_for"] == "n_columns")
            .collect();
        assert!(!decls.is_empty(), "应交付 n_columns 的声明行: {d}");
        assert!(
            decls
                .iter()
                .any(|s| s["text"].as_str().unwrap_or("").contains("n_columns")),
            "声明行原文必须可读: {d}"
        );
        let reasons = d["uncertainty"]["reasons"].as_array().unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| r == "window_identifier_declarations_included"),
            "应如实上报附加了声明行: {d}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 守卫的作用域必须限定在**目标行所在函数**内：跨函数的守卫不得交付
    /// （此前用"目标行 ±60 行"窗口，会把上一个函数的 `if` 当成此处的净化证据 ⇒ 假阴性）
    #[tokio::test]
    async fn test_sanitizer_guards_are_scoped_to_enclosing_function() {
        let root = std::env::temp_dir().join("ctx-audit-guards-scope");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "int\nfirst (int n)\n{\n    if (n > 10) {\n        return 1;\n    }\n    return 0;\n}\n\nint\nsecond (int n)\n{\n    return n + 1;\n}\n";
        std::fs::write(root.join("src/g.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SanitizerGuards);
        // 目标行在 `second` 内（第 12 行）；第 4 行的 `if` 属于**上一个函数** `first`
        let out = tool
            .execute(json!({"file": "src/g.c", "line": 12}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let lines: Vec<u64> = d["data"]["guards"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g["line"].as_u64().unwrap())
            .collect();
        assert!(
            !lines.contains(&4),
            "跨函数的守卫不得交付给判定者: {d}"
        );
        assert_eq!(
            d["data"]["guard_scope"], "enclosing_function",
            "应如实标注守卫作用域: {d}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 上限纪律：`get_sanitizer_guards` 超限时必须**显式上报**
    /// `total_hits`/`limit`/`truncated_at_limit`，不得静默截断
    ///（README 契约；修复前 data 里只有 `{file, guards}`，第 40 条处静默 break）。
    #[tokio::test]
    async fn test_sanitizer_guards_reports_truncation() {
        let root = std::env::temp_dir().join("ctx-audit-guards-trunc");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let mut src = String::new();
        for i in 0..50 {
            src.push_str(&format!("if (guard_{}()) {{}}\n", i));
        }
        std::fs::write(root.join("src/g.js"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SanitizerGuards);

        let out = tool.execute(json!({"file": "src/g.js"})).await.unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["limit"], MAX_HITS, "{d}");
        assert_eq!(d["data"]["total_hits"], 50, "{d}");
        assert_eq!(d["data"]["truncated_at_limit"], true, "{d}");
        assert_eq!(
            d["data"]["guards"].as_array().map(|a| a.len()),
            Some(MAX_HITS),
            "{d}"
        );

        // 未超限：不得误报截断，且 total_hits == 返回条数
        std::fs::write(root.join("src/small.js"), "if (a) {}\nif (b) {}\n").unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let out2 = tool.execute(json!({"file": "src/small.js"})).await.unwrap();
        let d2 = out2.data.clone().expect("应有 envelope data");
        assert_eq!(d2["data"]["total_hits"], 2, "{d2}");
        assert_eq!(d2["data"]["truncated_at_limit"], false, "{d2}");
        assert_eq!(
            d2["data"]["guards"].as_array().map(|a| a.len()),
            Some(2),
            "{d2}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

