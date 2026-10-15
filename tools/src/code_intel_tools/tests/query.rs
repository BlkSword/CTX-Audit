// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0
//! 符号与索引查询类测试（语言判定、定义/调用点、加载与上限、按需读取）。

use super::super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(language_of("src/main.rs"), "rust");
        assert_eq!(language_of("app/models.py"), "python");
        assert_eq!(language_of("internal/x.go"), "go");
        assert_eq!(language_of("web/index.tsx"), "typescript");
        assert_eq!(language_of("a/b.cpp"), "cpp");
    }

    #[test]
    fn test_find_definitions() {
        let src = "class Foo:\n    pass\n\ndef bar():\n    pass\n";
        let defs = find_definitions(src, "bar");
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].0, 4);
    }

    #[test]
    fn test_find_call_sites_excludes_definition() {
        let src = "fn main() {\n    helper(1);\n}\nfn helper(x: i32) {}\n";
        let sites = find_call_sites(src, "helper");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].0, 2);
    }

    /// C：调用点必须在**函数体内**——原型行与函数**定义行本身**都不是调用点。
    /// 实测依据：把它们算进 callers，20 函数抽样下真值 172 / 引擎 205（精确率 0.839）。
    #[tokio::test]
    async fn test_c_callers_only_inside_function_bodies() {
        let root = std::env::temp_dir().join("ctx-audit-callers-body");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/a.c"),
            "static ret_t helper_fn(str_t *s);\n\nret_t\ncaller_fn(str_t *s)\n{\n    return helper_fn(s);\n}\n",
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::CallHierarchy);
        let hit = tool.execute(json!({"function": "helper_fn"})).await.unwrap();
        let d = hit.data.expect("应有 envelope data");
        let callers = d["data"]["callers"].as_array().cloned().unwrap_or_default();
        let lines: Vec<u64> = callers.iter().filter_map(|c| c["line"].as_u64()).collect();
        assert_eq!(lines, vec![6], "只应命中函数体内的第 6 行调用: {d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// C 的运算符/内建形式不是被调用者（`sizeof`/`_Alignof`/`offsetof`）。
    #[test]
    fn test_callee_names_skips_c_operators() {
        for line in ["n = sizeof(str_t);", "x = _Alignof(int) + offsetof(S, f);"] {
            let names = callee_names(line);
            assert!(names.is_empty(), "{line} 不应产出 callee: {names:?}");
        }
        assert_eq!(callee_names("helper_fn(a);"), vec!["helper_fn".to_string()]);
    }

    #[test]
    fn test_callee_names() {
        let names = callee_names("let x = foo.bar(1) + baz(2);");
        assert!(names.contains(&"bar".to_string()));
        assert!(names.contains(&"baz".to_string()));
    }

    #[test]
    fn test_load_files_reports_limits() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-load-limits");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
        // 超过单文件上限的文件应计入 skipped_large
        std::fs::write(root.join("big.bin"), "x".repeat(MAX_FILE_BYTES + 1)).unwrap();
        // 跳过目录不应被索引
        std::fs::create_dir_all(root.join("node_modules")).unwrap();
        std::fs::write(root.join("node_modules/skip.js"), "var x = 1;").unwrap();

        let loaded = load_files(&root);
        assert_eq!(loaded.files.len(), 1, "只应索引 src/main.rs");
        assert_eq!(loaded.files[0].0, "src/main.rs");
        assert_eq!(loaded.skipped_large, 1, "超大文件应被计数");
        assert!(!loaded.truncated_at_limit, "未达文件数上限不应标记截断");
        assert_eq!(loaded.file_stamps.len(), 1, "每个已索引文件都应有指纹");
        assert_eq!(loaded.file_stamps[0].path, "src/main.rs");
        assert!(
            loaded.dir_stamps.iter().any(|d| d.path.is_empty()),
            "应记录项目根目录指纹"
        );
        assert!(
            loaded
                .dir_stamps
                .iter()
                .any(|d| d.path == "src" || d.path.ends_with("/src")),
            "应记录子目录指纹: {:?}",
            loaded.dir_stamps.iter().map(|d| &d.path).collect::<Vec<_>>()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 点名文件解析必须与**批量索引**上限解耦：索引受文件数/单文件大小上限约束，
    /// 但调用方点名一个文件时只该回答"能不能读"。此前两者共用同一上限，于是被索引跳过的
    /// 文件被回答成"文件不存在"（实测 542KB 生成产物与超出 2000 文件上限的源码即此）。
    #[tokio::test]
    async fn test_file_skipped_by_index_is_read_on_demand() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-ondemand");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut src = String::new();
        while src.len() < MAX_FILE_BYTES + 64 * 1024 {
            src.push_str("// filler line to exceed the bulk index limit\n");
        }
        src.push_str("function target(a) {\n  var x = a + 1;\n  return x;\n}\n");
        let total = src.lines().count();
        std::fs::write(root.join("big.js"), &src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let loaded = load_files(&root);
        assert!(loaded.files.is_empty(), "超上限文件不应进批量索引");
        assert_eq!(loaded.skipped_large, 1);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let hit = tool
            .execute(json!({"file": "big.js", "line": total - 1}))
            .await
            .unwrap();
        let d = hit.data.expect("应有 envelope data");
        assert_eq!(d["data"]["content_source"], "on-demand-read", "{d}");
        assert_eq!(d["data"]["function"], "target", "{d}");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 读取失败必须给出**真实原因**：磁盘与索引都没有 / 不是常规文件 / 超过读取上限。
    #[tokio::test]
    async fn test_missing_and_non_file_requests_report_true_reason() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-missing");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn f() {}\n").unwrap();

        let missing = format!("{:?}", read_requested_file(&root, "src/nope.rs").unwrap_err());
        assert!(missing.contains("文件不存在"), "{missing}");
        assert!(missing.contains("磁盘与索引"), "{missing}");

        let dir = format!("{:?}", read_requested_file(&root, "src").unwrap_err());
        assert!(dir.contains("不是常规文件"), "{dir}");

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let err = format!(
            "{:?}",
            tool.execute(json!({"file": "src/nope.rs", "line": 1}))
                .await
                .unwrap_err()
        );
        assert!(err.contains("磁盘与索引"), "{err}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 索引遍历顺序必须确定性：`read_dir` 返回顺序随文件系统而异，而"达到文件数上限就停"
    /// 会让取舍结果在机器之间不同（实测同一仓库在两台机器上命中不同的文件子集）。
    #[test]
    fn test_load_files_order_is_deterministic() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-order");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("z/deep")).unwrap();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("z/deep/x.js"), "var x = 1;").unwrap();
        std::fs::write(root.join("a/y.js"), "var y = 1;").unwrap();
        std::fs::write(root.join("top.js"), "var t = 1;").unwrap();

        let loaded = load_files(&root);
        let paths: Vec<&str> = loaded.files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            vec!["a/y.js", "top.js", "z/deep/x.js"],
            "已索引文件应按路径排序（确定性）"
        );
        let stamps: Vec<&str> = loaded.file_stamps.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(stamps, paths, "指纹顺序应与文件顺序一致");

        let _ = std::fs::remove_dir_all(&root);
    }

