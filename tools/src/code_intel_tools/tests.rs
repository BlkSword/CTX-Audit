// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! code_intel_tools 的单元测试（按原样搬出，便于模块化维护）。

    use super::*;

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

    /// 多行签名：C/C++ 签名跨 3 行以上时也必须能取出函数名（实测
    /// `static node_t *open_header(` + 2 行参数 + `… int len) {`）。
    #[test]
    fn test_function_header_name_multi_line_signature() {
        assert_eq!(
            function_header_name_multi("http_handler(req_t *r)", &["{"], true).as_deref(),
            Some("http_handler")
        );
        let sig = [
            "parser_t *parser,",
            "node_t *parent_container,",
            "unsigned char *input, int len) {",
        ];
        assert_eq!(
            function_header_name_multi(
                "static node_t *open_header(syntax_ext_t *self,",
                &sig,
                true
            )
            .as_deref(),
            Some("open_header")
        );
        // K&R：签名已闭合，参数类型行在其后、`{` 更后 —— **只在 C 类文件**才允许
        let kr = ["opt_state *esp;", "u_char *inp;", "int id;", "{"];
        assert_eq!(
            function_header_name_multi("opt_request(esp, inp, id, len)", &kr, true).as_deref(),
            Some("opt_request")
        );
        assert_eq!(
            function_header_name_multi("opt_request(esp, inp, id, len)", &kr, false).as_deref(),
            None,
            "非 C 语言不得走 K&R 容忍（跨语言误召回的入口）"
        );
        // 拼接不得制造误判：跨行的普通调用仍不是函数头；
        // 且**圆括号已闭合**的行（`var x = require('y')`）绝不允许被后面的函数声明拼成函数头
        assert_eq!(function_header_name_multi("foo(bar);", &["baz();"], true).as_deref(), None);
        assert_eq!(
            function_header_name_multi("var isBuffer = require('is-buffer')", &["function keyIdentity (key) {"], true)
                .as_deref(),
            None
        );
        // 圆括号未闭合 ≠ 可以一路拼到后面的函数声明：模块级的 `x = re.compile(` 不得与
        // 后面的 `def f(s):` 拼成函数头（实测假阳性，关键字分支只许匹配**本行**）
        assert_eq!(
            function_header_name_multi(
                "_is_image_dataurl = re.compile(",
                &["    r'^data:image/.+;base64', re.I).search",
                  "_is_possibly_malicious_scheme = re.compile(",
                  "def _is_javascript_scheme(s):",
                  "    if _is_image_dataurl(s):"],
                true
            )
            .as_deref(),
            None
        );
    }

    /// 目标行**自身**就是函数头（ES6 类方法）时也必须解析出作用域——上溯循环从目标行上方
    /// 开始，结构上找不到目标行自己。
    #[tokio::test]
    async fn test_slice_resolves_when_target_line_is_the_header() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-selfheader");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("m.js"),
            "var handlers = {};\nhandlers.getPublicInterface = function () {\n  var self = this;\n  return self.x;\n};\n",
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        // 第 2 行就是函数头**本身**（符号索引里没有它的声明）
        let hit = tool.execute(json!({"file": "m.js", "line": 2})).await.unwrap();
        let d = hit.data.expect("应有 envelope data");
        assert_eq!(d["data"]["function"], "getPublicInterface", "{d}");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        assert_eq!(d["data"]["scope_anchor"], "within_depth", "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 长函数：函数头在目标行**上方数百行**（远超切片窗口）时，仍需给出函数名与签名，
    /// 并如实标注 `scope_anchor=outside_window`（窗口里没有头就不许说 `includes_function_header`）。
    /// 用对象属性函数表达式构造，确保**符号索引里没有该声明**，只能靠上溯找到。
    #[tokio::test]
    async fn test_slice_resolves_enclosing_function_far_above_the_window() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-farabove");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut src = String::from("var obj = {\n  farAbove: function (a) {\n    var x = a;\n");
        for i in 0..300 {
            src.push_str(&format!("    x = x + {i};\n"));
        }
        src.push_str("    return x;\n  }\n};\n");
        std::fs::write(root.join("far.js"), &src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let hit = tool.execute(json!({"file": "far.js", "line": 304})).await.unwrap();
        let d = hit.data.expect("应有 envelope data");
        assert_eq!(d["data"]["function"], "farAbove", "{d}");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        // 函数太长 ⇒ 窗口被向前扩展才装下函数头，如实标注（消费者据此知道窗口比 depth 更宽）
        assert_eq!(d["data"]["scope_anchor"], "extended_for_long_function", "{d}");
        assert_eq!(d["data"]["window"]["start_line"], 2, "{d}");
        assert_eq!(d["data"]["includes_function_header"], true, "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 端到端回归：代码段里的**落单引号**（Rust 生命周期 `&'static str`、JS 正则 `/'/g`）
    /// 不得吞掉后续声明——否则定义进不了索引（表现为 `empty_kind=index_miss`）。
    /// 同时验证空结果分类：索引里完全没有的符号报 `no_match`。
    #[tokio::test]
    async fn test_definition_after_lifetime_is_indexed_and_empty_kind_is_reported() {
        let root = std::env::temp_dir().join("ctx-audit-code-intel-lifetime");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/lib.rs"),
            "fn f() -> Option<&'static str> {\n    None\n}\n\npub fn classify_file_role(p: &str) -> &'static str {\n    \"x\"\n}\n",
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let project = root.to_string_lossy().to_string();
        let tool = CodeIntelTool::new(project, IntelKind::SymbolDefinition);

        let hit = tool
            .execute(json!({"symbol": "classify_file_role"}))
            .await
            .unwrap();
        let d = hit.data.clone().expect("应有 envelope data");
        assert!(
            d["data"]["total_hits"].as_u64().unwrap() >= 1,
            "生命周期之后的声明必须进索引: {d}"
        );
        assert_eq!(d["data"]["empty_kind"], Value::Null, "{d}");

        let miss = tool
            .execute(json!({"symbol": "definitely_absent_symbol_xyz"}))
            .await
            .unwrap();
        let m = miss.data.expect("应有 envelope data");
        assert_eq!(m["data"]["total_hits"], 0);
        assert_eq!(m["data"]["empty_kind"], "no_match", "{m}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 函数头识别：关键字形态 + **匿名函数表达式/箭头函数** + **C/C++ 无关键字定义**。
    #[test]
    fn test_function_header_name_forms() {
        assert_eq!(function_header_name("function foo(a) {").as_deref(), Some("foo"));
        assert_eq!(function_header_name("async function h(req) {").as_deref(), Some("h"));
        assert_eq!(function_header_name("def foo(x):").as_deref(), Some("foo"));
        // 匿名函数表达式：名字由属性/变量名回填
        assert_eq!(
            function_header_name("replacement: function (content) {").as_deref(),
            Some("replacement")
        );
        assert_eq!(function_header_name("const f = function (a) {").as_deref(), Some("f"));
        assert_eq!(function_header_name("handler: (req, res) => {").as_deref(), Some("handler"));
        assert_eq!(function_header_name("const g = (a) => a + 1").as_deref(), Some("g"));
        // 关键字与 `(` 之间**无空格**（JS 匿名函数常见）→ 名字回填自左侧属性/变量
        //（实测漏此形态会把 `function` 当成函数名）
        assert_eq!(
            function_header_name("Repo.prototype.refreshCache = function(then) {").as_deref(),
            Some("refreshCache")
        );
        assert_eq!(function_header_name("function(a) {").as_deref(), Some(""));
        // 关键字边界：`define(` 的 `def`、`myfn(` 的 `fn` 都不得被当成关键字
        assert_eq!(function_header_name("myfn(x) {").as_deref(), Some("myfn"));
        assert_eq!(function_header_name("define(FOO, x)").as_deref(), None);
        // C/C++：无关键字定义（单词一行 + 多行签名两种）
        assert_eq!(function_header_name("static int foo(int a) {").as_deref(), Some("foo"));
        assert_eq!(function_header_name("void bar(void) {").as_deref(), Some("bar"));
        assert_eq!(
            function_header_name_ctx("http_handler(req_t *r)", "{").as_deref(),
            Some("http_handler")
        );
        // C/C++ 负例：控制语句、调用、结构体、else
        assert_eq!(function_header_name("if (a) {"), None);
        assert_eq!(function_header_name("for (i = 0; i < n; i++) {"), None);
        assert_eq!(function_header_name("while (x) {"), None);
        assert_eq!(function_header_name("synchronized (lock) {"), None);
        assert_eq!(function_header_name("foo(bar);"), None);
        assert_eq!(function_header_name("struct foo {"), None);
        assert_eq!(function_header_name("} else {"), None);
        // 非函数头
        assert_eq!(function_header_name("const x = 1;"), None);
        assert_eq!(function_header_name("// function notAHeader() {"), None);
    }

    /// `slice_backward` 必须锚定**函数头**，包括 `replacement: function (…) {` 这类
    /// 对象属性函数表达式——它在符号索引里没有声明，旧实现因此返回
    /// `function_scope="unresolved"`、窗口不含函数头（实测"函数头入镜 40.4%"的机制性原因）。
    #[tokio::test]
    async fn test_slice_anchors_object_property_function_expression() {
        let root = std::env::temp_dir().join("ctx-audit-slice-prop-fn");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "const rules = {}\n\nrules.blockquote = {\n  filter: 'blockquote',\n  replacement: function (content, node, options) {\n    content = content.replace(/^\\n+|\\n+$/g, '')\n    return content\n  }\n}\n";
        std::fs::write(root.join("src/rules.js"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/rules.js", "line": 6, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        assert_eq!(d["data"]["function"], "replacement", "{d}");
        assert_eq!(d["data"]["function_def_line"], 5, "{d}");
        assert_eq!(d["data"]["includes_function_header"], true, "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 反向反例：目标行**不在任何函数体内**（文件级字符串数组），
    /// 即使上方 120 行内有已闭合的函数，也不得报 `resolved`——那是假作用域。
    #[tokio::test]
    async fn test_slice_does_not_falsely_anchor_closed_function() {
        let root = std::env::temp_dir().join("ctx-audit-slice-no-false-anchor");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "export function trim (s) {\n  return s\n}\n\nexport var list = [\n  'A', 'B',\n  'C', 'D'\n]\n";
        std::fs::write(root.join("src/u.js"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/u.js", "line": 7, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["function_scope"], "unresolved", "{d}");
        assert_eq!(d["data"]["includes_function_header"], false, "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// C 风格定义（**无关键字**、多行签名）也要锚定函数头：
    /// `static int` / `foo_bar(...)` / `{` 三行式——真实 C 代码库的常见形态。
    #[tokio::test]
    async fn test_slice_anchors_c_style_function_header() {
        let root = std::env::temp_dir().join("ctx-audit-slice-c-header");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "static ret_t\nhttp_handler(req_t *r)\n{\n    int n = r->n;\n    if (n == 0) {\n        return 1;\n    }\n    return 0;\n}\n";
        std::fs::write(root.join("src/a.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/a.c", "line": 5, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        assert_eq!(d["data"]["function"], "http_handler", "{d}");
        assert_eq!(d["data"]["function_def_line"], 2, "{d}");
        assert_eq!(d["data"]["includes_function_header"], true, "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// **声明行不得被当成函数头**：`struct <Type> *<name>;` 形态的变量声明在函数体内，
    /// 旧实现（符号索引把关键字后的类型名记成"该类型的定义"）让上溯/已知定义判定选中它，
    /// `function` 因此变成类型名——实测真实 C 文件里得到的是变量名而非函数名。
    /// 夹具形状与真实一致：多行签名（参数续行也带 `struct`）+ 函数体内 `struct X *p = NULL;`
    /// + 之后是真正的函数定义体（`switch` 块，使声明行的"体覆盖"成立）。
    #[tokio::test]
    async fn test_slice_ignores_declaration_lines_as_function_headers() {
        let root = std::env::temp_dir().join("ctx-audit-slice-c-decl");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lib")).unwrap();
        let src = concat!(
            "static ProxyCode open_proxy(struct Filter *cf,\n",
            "                              struct ConnState *sx,\n",
            "                              struct EasyConn *data)\n",
            "{\n",
            "  struct Connection *conn = cf->conn;\n",
            "  const size_t hostname_len = strlen(sx->hostname);\n",
            "  struct DnsEntry *dns = NULL;\n",
            "  switch(sx->state) {\n",
            "  case STATE_INIT:\n",
            "    log_info(data, \"connecting to proxy\", hostname_len, dns);\n",
            "    break;\n",
            "  default:\n",
            "    break;\n",
            "  }\n",
            "  return PROXY_OK;\n",
            "}\n",
        );
        std::fs::write(root.join("lib/proxy.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "lib/proxy.c", "line": 10, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["function"], "open_proxy", "{d}");
        assert_eq!(d["data"]["function_def_line"], 1, "{d}");
        assert_eq!(d["data"]["function_scope"], "resolved", "{d}");
        assert_eq!(d["data"]["includes_function_header"], true, "{d}");
        assert_eq!(d["data"]["scope_anchor"], "within_depth", "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 前向窗口：决定性证据常在目标行**之后**（实测形态：locus 停在注释行，
    /// 真正的谓词与拷贝在下一行，旧实现里它们完全不在窗口内）。
    #[tokio::test]
    async fn test_slice_forward_window_delivers_lines_after_target() {
        let root = std::env::temp_dir().join("ctx-audit-slice-forward");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "static char buf[16];\n\nint\ncopy_len (char *dst, const char *src, int len)\n{\n    /* length comes from the peer */\n    if (len > 0)\n        memcpy (dst, src, len);\n    return 0;\n}\n";
        std::fs::write(root.join("src/a.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        // 目标行取**注释行**（真实 CVE 形态），决定性行在其后
        let out = tool
            .execute(json!({"file": "src/a.c", "line": 6, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["function"], "copy_len", "{d}");
        // 窗口如实扩到函数体末行，且不越界
        assert_eq!(d["data"]["window"]["end_line"], 10, "{d}");
        assert_eq!(d["data"]["forward_bounded_by"], "function_body", "{d}");
        let snips = d["data"]["snippets"].as_array().unwrap();
        let after: Vec<&serde_json::Value> =
            snips.iter().filter(|s| s["is_after_target"] == true).collect();
        assert!(after.len() >= 2, "目标行之后应有谓词与拷贝: {d}");
        assert!(
            after.iter().any(|s| s["text"].as_str().unwrap_or("").contains("memcpy")),
            "决定性拷贝行必须交付: {d}"
        );
        assert_eq!(d["uncertainty"]["reasons"].as_array().unwrap().len() >= 3, true, "{d}");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `forward: 0` 必须退回**纯后向**窗口——旧行为可复现，A/B 对照才有意义。
    #[tokio::test]
    async fn test_slice_forward_zero_keeps_backward_only_window() {
        let root = std::env::temp_dir().join("ctx-audit-slice-forward-zero");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "static char buf[16];\n\nint\ncopy_len (char *dst, const char *src, int len)\n{\n    /* length comes from the peer */\n    if (len > 0)\n        memcpy (dst, src, len);\n    return 0;\n}\n";
        std::fs::write(root.join("src/a.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/a.c", "line": 8, "depth": 40, "forward": 0}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["window"]["end_line"], 8, "{d}");
        assert_eq!(d["data"]["forward_lines_returned"], 0, "{d}");
        assert!(
            d["data"]["snippets"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s["is_after_target"] == false),
            "forward=0 不得返回目标行之后的片段: {d}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// `unresolved_edges` 的 C 口径：函数指针 / 成员指针 / 表下标派发必须**逐调用点如实计数**，
    /// 而且必须与查询方向无关；没有派发的函数不得被整文件一刀切记成"有未解析边"。
    #[tokio::test]
    async fn test_call_hierarchy_counts_c_indirect_call_sites() {
        let root = std::env::temp_dir().join("ctx-audit-indirect-edges");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "typedef int (*handler_fn) (const char *);\n\nstruct ops {\n    handler_fn run;\n};\n\nstatic handler_fn table[4];\n\nint\nrun_dispatch (struct ops *o, int idx, const char *arg)\n{\n    table[idx] (arg);\n    o->run (arg);\n    (*fp) (arg);\n    return 0;\n}\n\nint\nplain_call (void)\n{\n    return helper (1);\n}\n";
        std::fs::write(root.join("src/d.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::CallHierarchy);
        let out = tool
            .execute(json!({"function": "run_dispatch", "direction": "callees"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let u = d["uncertainty"]["unresolved_edges"].as_u64().unwrap_or(0);
        assert!(u >= 3, "三类派发点都应被计数（表下标/成员指针/函数指针）: {d}");
        assert_eq!(d["uncertainty"]["level"], "high", "{d}");

        // 对照：无派发的函数必须是 0（旧实现会因文件里出现 `(*…)` 之类整文件 +1）
        let out2 = tool
            .execute(json!({"function": "plain_call", "direction": "callees"}))
            .await
            .unwrap();
        let d2 = out2.data.clone().expect("应有 envelope data");
        assert_eq!(
            d2["uncertainty"]["unresolved_edges"].as_u64().unwrap_or(0),
            0,
            "{d2}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// C3：调用点解析不出目标（表下标 / 成员指针 / 函数指针派发）时，必须交付**按签名匹配的
    /// 候选目标集合**——候选来自已索引的 C 定义、每条带 `reason`/`score`、字段级标注为启发式，
    /// 且**不得**影响 `unresolved_edges` 的数值语义。
    #[tokio::test]
    async fn test_dispatch_candidates_signature_heuristic() {
        let root = std::env::temp_dir().join("ctx-audit-dispatch-candidates");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = concat!(
            "struct conn { int fd; };\n",
            "\n",
            "static int\n",
            "handle_conn (struct conn *c, const char *buf)\n",
            "{\n",
            "    return c->fd;\n",
            "}\n",
            "\n",
            "static int\n",
            "three_args (int a, int b, int c)\n",
            "{\n",
            "    return a + b + c;\n",
            "}\n",
            "\n",
            "typedef int (*handler_fn) (struct conn *, const char *);\n",
            "\n",
            "static handler_fn table[4];\n",
            "\n",
            "int\n",
            "run_dispatch (struct conn *c, const char *buf, int idx)\n",
            "{\n",
            "    return table[idx] (c, buf);\n",
            "}\n",
        );
        std::fs::write(root.join("src/d.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::CallHierarchy);
        let out = tool
            .execute(json!({"function": "run_dispatch", "direction": "callees"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let dc = &d["data"]["dispatch_candidates"];
        assert_eq!(dc["heuristic"], true, "字段级必须标注启发式: {d}");
        assert_eq!(dc["basis"], "signature_match_over_indexed_c_definitions", "{d}");
        let sites = dc["call_sites"].as_array().unwrap();
        assert!(
            !sites.is_empty(),
            "表下标派发必须作为调用点交付: {d}"
        );
        let cands = dc["candidates"].as_array().unwrap();
        assert!(!cands.is_empty(), "签名匹配应产出候选: {d}");
        for c in cands {
            assert!(
                c["reason"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
                "每条候选必须带非空 reason: {c}"
            );
            assert!(c["score"].as_f64().is_some(), "每条候选必须带 score: {c}");
            assert!(c["line"].as_u64().is_some(), "候选必须给出定义行: {c}");
        }
        let names: Vec<&str> = cands.iter().filter_map(|c| c["name"].as_str()).collect();
        assert!(
            names.contains(&"handle_conn"),
            "同参数个数 + 实参名一致的 C 定义必须进候选: {d}"
        );
        assert!(
            !names.contains(&"three_args"),
            "参数个数不匹配（3≠2）的定义不得进候选: {d}"
        );
        // 只加证据：未解析边口径不变
        assert!(
            d["uncertainty"]["unresolved_edges"].as_u64().unwrap_or(0) >= 1,
            "unresolved_edges 必须仍然计数: {d}"
        );
        let reasons = d["uncertainty"]["reasons"].as_array().unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| r == "dispatch_candidates_are_signature_heuristic"),
            "必须如实标注候选是签名启发式: {d}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// C3：**跨行签名**的定义必须进候选空间（C 的 80 列风格：形参表折行）。
    /// 只用"定义行"原文时括号不闭合 ⇒ 真目标整批缺席，候选退化成"巧合同参数个数的无关函数"。
    #[tokio::test]
    async fn test_dispatch_candidates_multiline_signature_target_found() {
        let root = std::env::temp_dir().join("ctx-audit-dispatch-multiline");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = concat!(
            "struct conn { int fd; };\n",
            "\n",
            // 真目标：形参表折行 ⇒ 索引里的"定义行"原文括号不闭合
            "static int\n",
            "handle_conn (struct conn *c,\n",
            "             const char *buf)\n",
            "{\n",
            "    return c->fd;\n",
            "}\n",
            "\n",
            // 噪声：单行签名且参数个数不同
            "static int one_arg (int a) { return a; }\n",
            "\n",
            "typedef int (*handler_fn) (struct conn *, const char *);\n",
            "\n",
            "static handler_fn table[4];\n",
            "\n",
            "int\n",
            "run_dispatch (struct conn *c, const char *buf, int idx)\n",
            "{\n",
            "    return table[idx] (c, buf);\n",
            "}\n",
        );
        std::fs::write(root.join("src/m.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::CallHierarchy);
        let out = tool
            .execute(json!({"function": "run_dispatch", "direction": "callees"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let dc = &d["data"]["dispatch_candidates"];
        let cands = dc["candidates"].as_array().unwrap();
        let target = cands
            .iter()
            .find(|c| c["name"] == "handle_conn")
            .unwrap_or_else(|| panic!("跨行签名的真目标必须在候选里: {d}"));
        assert!(
            target["signature"]
                .as_str()
                .unwrap_or("")
                .contains("const char *buf"),
            "续行后的签名文本必须完整: {target}"
        );
        assert!(
            dc["signature_space"]["signatures_joined_from_continuation_lines"]
                .as_u64()
                .unwrap_or(0)
                >= 1,
            "必须如实上报发生过续行: {d}"
        );
        assert!(
            !cands.iter().any(|c| c["name"] == "one_arg"),
            "参数个数不匹配的定义不得进候选: {d}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// C3 对照：签名**不匹配**（实参个数没有任何已索引 C 定义与之相等）⇒ 候选为空、
    /// 并如实给出原因，不得为了"有字段"而硬凑候选。
    #[tokio::test]
    async fn test_dispatch_candidates_empty_when_no_signature_match() {
        let root = std::env::temp_dir().join("ctx-audit-dispatch-nomatch");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = concat!(
            "static int\n",
            "two_args (int a, char *b)\n",
            "{\n",
            "    return a;\n",
            "}\n",
            "\n",
            "typedef int (*handler_fn) (int, char *, char *);\n",
            "\n",
            "static handler_fn table[4];\n",
            "\n",
            "int\n",
            "run_dispatch (int idx, char *a, char *b, char *c)\n",
            "{\n",
            "    table[idx] (a, b, c);\n",
            "    return 0;\n",
            "}\n",
        );
        std::fs::write(root.join("src/n.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::CallHierarchy);
        let out = tool
            .execute(json!({"function": "run_dispatch", "direction": "callees"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let dc = &d["data"]["dispatch_candidates"];
        assert!(
            dc["call_sites"].as_array().unwrap().len() == 1,
            "派发调用点必须被交付: {d}"
        );
        assert_eq!(
            dc["candidates"].as_array().unwrap().len(),
            0,
            "实参个数与任何已索引定义都不相等 ⇒ 候选必须为空: {d}"
        );
        assert_eq!(dc["total_hits"], 0, "{d}");
        assert_eq!(dc["truncated_at_limit"], false, "{d}");
        let reasons = d["uncertainty"]["reasons"].as_array().unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| r == "dispatch_targets_unresolved_no_signature_match"),
            "无候选时也必须如实说明: {d}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// C3：`slice_backward` 的 envelope 同样必须交付 `dispatch_candidates`
    /// （所在函数体由作用域解析确定；非 C 语言不做签名匹配）。
    #[tokio::test]
    async fn test_slice_backward_exposes_dispatch_candidates() {
        let root = std::env::temp_dir().join("ctx-audit-slice-dispatch");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = concat!(
            "struct conn { int fd; };\n",
            "\n",
            "static int\n",
            "handle_conn (struct conn *c, const char *buf)\n",
            "{\n",
            "    return c->fd;\n",
            "}\n",
            "\n",
            "typedef int (*handler_fn) (struct conn *, const char *);\n",
            "\n",
            "static handler_fn table[4];\n",
            "\n",
            "int\n",
            "run_dispatch (struct conn *c, const char *buf, int idx)\n",
            "{\n",
            "    return table[idx] (c, buf);\n",
            "}\n",
        );
        std::fs::write(root.join("src/s.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/s.c", "line": 16, "depth": 20}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let dc = &d["data"]["dispatch_candidates"];
        assert_eq!(dc["heuristic"], true, "切片响应也必须带启发式标注: {d}");
        let names: Vec<&str> = dc["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["name"].as_str())
            .collect();
        assert!(
            names.contains(&"handle_conn"),
            "切片所在函数体内的派发点应产出候选: {d}"
        );
        let reasons = d["uncertainty"]["reasons"].as_array().unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| r == "dispatch_candidates_are_signature_heuristic"),
            "切片响应也必须标注签名启发式: {d}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// C2：`get_call_hierarchy` 必须交付**有界**的轻量过程间摘要。
    /// 断言：字段存在、每个条目要么带摘要要么带不可用原因、上限（8）被尊重、
    /// 超限时 `truncated_at_limit = true`、并且摘要是复用 `compute_summary_from_cpg` 产出的。
    #[tokio::test]
    async fn test_function_summaries_bounded_and_truncated() {
        let root = std::env::temp_dir().join("ctx-audit-func-summaries");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let mut src = String::from("#include <string.h>\n\n");
        for i in 0..10 {
            src.push_str(&format!(
                "static int callee_{:02} (int a) {{ return a + {}; }}\n",
                i, i
            ));
        }
        src.push_str("\nint hub (char *buf, int n)\n{\n");
        src.push_str("    callee_00(n);\n");
        src.push_str("    strlen(buf);\n"); // 库里没有已索引定义 ⇒ 该项必须如实降级
        for i in 1..10 {
            src.push_str(&format!("    callee_{:02}(n);\n", i));
        }
        src.push_str("    memcpy(buf, \"y\", 1);\n    return n;\n}\n");
        std::fs::write(root.join("src/h.c"), &src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::CallHierarchy);
        let out = tool
            .execute(json!({"function": "hub", "direction": "callees"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let fs = &d["data"]["function_summaries"];
        assert_eq!(fs["method"], "compute_summary_from_cpg", "{d}");
        assert_eq!(fs["limit"], MAX_FUNCTION_SUMMARIES, "必须上报上限: {d}");
        assert!(
            fs["total_hits"].as_u64().unwrap_or(0) > MAX_FUNCTION_SUMMARIES as u64,
            "本次响应里的函数数应超过上限（目标 + callee 名）: {d}"
        );
        assert_eq!(
            fs["truncated_at_limit"], true,
            "超限时必须如实标注截断: {d}"
        );
        let sums = fs["summaries"].as_array().unwrap();
        assert_eq!(
            sums.len(),
            MAX_FUNCTION_SUMMARIES,
            "交付的摘要条目数必须被上限钉住: {d}"
        );
        // 目标函数自己的摘要必须是真摘要（复用 compute_summary_from_cpg）
        assert_eq!(sums[0]["func"], "hub", "{d}");
        assert_eq!(sums[0]["available"], true, "{d}");
        assert!(sums[0]["param_to_return"].as_array().is_some(), "{d}");
        assert!(sums[0]["param_to_sink"].as_array().is_some(), "{d}");
        // 字段级可用性标注，以及"参数→返回"的可读参数名（不能只有下标）
        assert_eq!(fs["available"], true, "有摘要时字段级必须标注可用: {d}");
        assert!(fs["reason"].is_null(), "可用时字段级不得给降级原因: {d}");
        assert_eq!(fs["considered"], fs["total_hits"], "{d}");
        let p2r = sums[0]["param_to_return"].as_array().unwrap();
        assert!(
            p2r.iter()
                .any(|e| e["param_name"].as_str() == Some("buf") && e["param"].as_u64() == Some(0)),
            "参数→返回必须把下标还原成参数名: {d}"
        );
        // 每条要么可用（带摘要），要么带**原因**（绝不静默缺席）
        for s in sums {
            if s["available"] == true {
                assert!(s["basis"].as_str().unwrap_or("").contains("compute_summary_from_cpg"), "{s}");
            } else {
                assert!(
                    s["reason"].as_str().map(|r| !r.is_empty()).unwrap_or(false),
                    "不可用的条目必须给出原因: {s}"
                );
            }
        }
        // 索引里没有定义的 callee（`strlen`/`memcpy`）必须被计为"未解析到定义"
        assert!(
            fs["resolved_in_index"].as_u64().unwrap_or(0) < fs["total_hits"].as_u64().unwrap_or(0),
            "未索引的 callee 不应被算作已解析: {d}"
        );
        let reasons = d["uncertainty"]["reasons"].as_array().unwrap();
        assert!(
            reasons
                .iter()
                .any(|r| r == "function_summaries_single_function_scope"),
            "摘要的作用域限制必须进 uncertainty: {d}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// C2 的已知边界（**只记录，不改检测**）：既有调用名判据要求 `name(` 紧邻，
    /// GNU 风格 `name (args)`（`(` 前有空格）不被识别。于这类文件里 `function_summaries`
    /// 只会有目标函数自己，`total_hits` 会如实反映"没识别到 callee"。
    /// 该判据同时服务调用图（检测线冻结），本任务不动它。
    #[test]
    fn test_callee_names_requires_adjacent_paren() {
        assert_eq!(callee_names("    ok(a, b);"), vec!["ok".to_string()]);
        assert!(
            callee_names("    gnu_style (a, b);").is_empty(),
            "带空格的 GNU 风格调用不被既有判据识别（只记录边界，不改检测）"
        );
    }

    /// P7 活代码视图：`#if 0` 里的函数**不进索引**、切片里也不出现；`#ifdef` 一类无法判定
    /// ⇒ 如实标 `in_conditional_region` 并给 uncertainty 原因（不假装这段一定参与编译）。
    #[tokio::test]
    async fn test_dead_branch_excluded_and_conditional_labeled() {
        let root = std::env::temp_dir().join("ctx-audit-preproc-view");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "#include <string.h>\n\n#if 0\nint dead_only (void)\n{\n    return 1;\n}\n#endif\n\nint live_only (void)\n{\n    return 2;\n}\n";
        std::fs::write(root.join("src/d.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let def = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SymbolDefinition);
        let out = def.execute(json!({"symbol": "dead_only"})).await.unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["total_hits"], 0, "`#if 0` 里的函数不得进索引: {d}");

        let out2 = def.execute(json!({"symbol": "live_only"})).await.unwrap();
        let d2 = out2.data.clone().expect("应有 envelope data");
        assert!(
            d2["data"]["total_hits"].as_u64().unwrap_or(0) >= 1,
            "活代码里的函数必须可查: {d2}"
        );

        // 无法判定的条件编译区：切片必须标注，而不是静默当成活代码
        let src2 = "int live_only (void)\n{\n#ifdef FEATURE_X\n    return 1;\n#else\n    return 2;\n#endif\n}\n";
        std::fs::write(root.join("src/c.c"), src2).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let sl = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out3 = sl.execute(json!({"file": "src/c.c", "line": 4})).await.unwrap();
        let d3 = out3.data.clone().expect("应有 envelope data");
        let snips = d3["data"]["snippets"].as_array().unwrap();
        assert!(
            snips.iter().any(|s| s["in_conditional_region"] == true),
            "条件编译行必须带 in_conditional_region: {d3}"
        );
        let reasons = d3["uncertainty"]["reasons"].as_array().unwrap();
        assert!(
            reasons.iter().any(|r| r == "conditional_compilation_region_present"),
            "必须如实上报条件编译区: {d3}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 非 C 的 callers 不得把**目标函数自己的定义行**算成调用点。
    /// 实测形态：Java 的 `public int handle(String s) {`（Go/Rust/Python 的定义行带
    /// `func`/`fn`/`def` 关键字，已被调用点判据排除；Java 没有，故由定义行判据统一挡）。
    #[tokio::test]
    async fn test_callers_exclude_own_definition_line_java() {
        let root = std::env::temp_dir().join("ctx-audit-callers-java-def");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "interface Handler {\n    int handle(String s);\n}\n\nclass Impl implements Handler {\n    public int handle(String s) {\n        return s.length();\n    }\n    int use(Handler h) {\n        return h.handle(\"x\");\n    }\n}\n";
        std::fs::write(root.join("src/A.java"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::CallHierarchy);
        let out = tool
            .execute(json!({"function": "handle", "direction": "callers"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let lines: Vec<u64> = d["data"]["callers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["line"].as_u64())
            .collect();
        assert_eq!(
            lines,
            vec![10],
            "只应有真调用点 L10（接口声明 L2 与定义行 L6 都不算）: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// P7 补完：未激活分支（`#if 0`）里的内容不得作为**证据**交付。
    /// 覆盖三条路径：守卫、调用图的 callers、数据流路径。
    #[tokio::test]
    async fn test_dead_branch_not_delivered_as_evidence() {
        let root = std::env::temp_dir().join("ctx-audit-dead-evidence");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        let src = "int target (void) {\n    int n = 0;\n#if 0\n    if (n > 0) { return 1; }\n#endif\n    if (n > 2) { return 3; }\n    return n;\n}\n\nint caller_live (void) {\n    return target();\n}\n\n#if 0\nint caller_dead (void) {\n    return target();\n}\n#endif\n\n#if 0\nvoid dead_flow (void) {\n    char *dead_src = getenv(\"X\");\n    sink_call(dead_src);\n}\n#endif\n";
        std::fs::write(root.join("src/z.c"), src).unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);

        // ① 守卫：`#if 0` 里的 if（L4）与指令行本身（L3）都不算，活分支的 L6 必须保留
        let g = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SanitizerGuards);
        let out = g.execute(json!({"file": "src/z.c", "line": 7})).await.unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let lines: Vec<u64> = d["data"]["guards"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x["line"].as_u64())
            .collect();
        assert!(!lines.contains(&3), "`#if 0` 指令行不是守卫: {d}");
        assert!(!lines.contains(&4), "`#if 0` 里的 if 不是守卫: {d}");
        assert!(lines.contains(&6), "活分支的 if 必须是守卫: {d}");

        // ② callers：未激活分支里的调用点不是边（只应剩活分支 L11）
        let c = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::CallHierarchy);
        let out2 = c
            .execute(json!({"function": "target", "direction": "callers"}))
            .await
            .unwrap();
        let d2 = out2.data.clone().expect("应有 envelope data");
        let cl: Vec<u64> = d2["data"]["callers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x["line"].as_u64())
            .collect();
        assert_eq!(cl, vec![11], "只应返回活分支里的调用点 L11: {d2}");

        // ③ 数据流：源点只出现在未激活分支里 ⇒ 不产生路径
        let f = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::DataflowPath);
        let out3 = f
            .execute(json!({"source": "dead_src", "sink": "sink_call"}))
            .await
            .unwrap();
        let d3 = out3.data.clone().expect("应有 envelope data");
        assert_eq!(
            d3["data"]["path"].as_array().unwrap().len(),
            0,
            "未激活分支里的源点不得产出路径: {d3}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// 判定要素 + 可达性视图：给定 locus **一次调用**就要能回答"有没有检查、锚点在哪、
    /// 谁调用它、最小窗口多少"，且**缺席要显式**（`no_check_found`）。
    #[tokio::test]
    async fn test_slice_returns_decision_facts_and_reachability() {
        let root = std::env::temp_dir().join("ctx-audit-locus-facts");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/a.c"),
            concat!(
                "int copy_in(char *user, unsigned int n);\n",
                "\n",
                "void handle(char *user, unsigned int n)\n",
                "{\n",
                "    char dst[32];\n",
                "    memcpy(dst, user, n);\n",
                "}\n",
                "\n",
                "int caller(void)\n",
                "{\n",
                "    handle(\"x\", 4);\n",
                "    return 0;\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/a.c", "line": 6, "depth": 40}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        // 检查缺席必须显式，锚点必须给出行号，语义边界必须如实
        assert_eq!(
            d["data"]["decision_facts"]["guards"]["no_check_found"], true,
            "该夹具无 n<=32 检查，必须报 no_check_found: {d}"
        );
        // 目标行自身的检查状态必须显式给出（之前被静默丢弃 ⇒ 当决定性行就是目标行时凭空消失）
        assert_eq!(
            d["data"]["decision_facts"]["guards"]["target_line_check"]["is_check"], false,
            "`memcpy(dst, user, n);` 不是检查行: {d}"
        );
        assert_eq!(
            d["data"]["decision_facts"]["guards"]["target_line_check"]["line"], 6,
            "目标行自身检查状态必须带行号: {d}"
        );
        let anchors = d["data"]["decision_facts"]["capacity_anchors"]
            .as_array()
            .unwrap();
        assert!(
            anchors.iter().any(|a| a["line"] == 5),
            "char dst[32] 必须作为容量锚点: {d}"
        );
        assert!(
            d["data"]["decision_facts"]["minimal_window"]["lines"]
                .as_u64()
                .unwrap()
                >= 1,
            "{d}"
        );
        assert_eq!(
            d["data"]["decision_facts"]["semantics"]["pointer_or_bounds_reasoning"], false,
            "不得声称做了指针/边界推理: {d}"
        );
        // 来源候选 = 签名参数；入口候选 = 调用者
        let origins = d["data"]["reachability"]["origin_candidates"]
            .as_array()
            .unwrap();
        // 参数名必须按**源码顺序**取（`unsigned int n` → `n`）；用排序列表会把名字挤掉
        assert!(
            origins.iter().any(|o| o["name"] == "n"),
            "参数 n 必须在来源候选里: {d}"
        );
        let entries = d["data"]["reachability"]["entry_candidates"]
            .as_array()
            .unwrap();
        assert!(
            entries.iter().any(|e| e["line"] == 11),
            "调用者 caller() 必须在入口候选里: {d}"
        );
        // 最小窗口必须显著小于交付窗口，且检查行缺席要显式
        assert!(d["data"]["decision_facts"]["minimal_window"]["lines"].as_u64().unwrap() <= 8, "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 路径匹配：精确、`/**` 前缀、`/*` 单段。
    #[test]
    fn test_route_matches_pattern() {
        assert!(route_matches_pattern("/admin/users", "/admin/users"));
        assert!(!route_matches_pattern("/admin/users/1", "/admin/users"));
        assert!(route_matches_pattern("/admin/users", "/admin/**"));
        assert!(route_matches_pattern("/admin/users/1", "/admin/**"));
        assert!(route_matches_pattern("/admin/users", "/admin/*"));
        assert!(!route_matches_pattern("/admin/users/1", "/admin/*"));
        assert!(!route_matches_pattern("/public/x", "/admin/**"));
    }

    /// 跨文件安全配置：匹配器与授权子句被正确取出（输入显式，直接喂内存文件对）。
    #[test]
    fn test_security_config_matchers_and_annotation() {
        let files = vec![
            (
                "src/SecurityConfig.java".to_string(),
                concat!(
                    "package app;\n",
                    "@Configuration\n",
                    "@EnableWebSecurity\n",
                    "public class SecurityConfig {\n",
                    "    @Bean\n",
                    "    public SecurityFilterChain chain(HttpSecurity http) {\n",
                    "        http.authorizeHttpRequests(auth -> auth\n",
                    "            .requestMatchers(\"/admin/**\").hasRole(\"ADMIN\")\n",
                    "            .requestMatchers(\"/public/**\").permitAll()\n",
                    "            .anyRequest().authenticated());\n",
                    "        return null;\n",
                    "    }\n",
                    "}\n",
                )
                .to_string(),
            ),
        ];
        let chains = security_config_chains(&files);
        let matchers: Vec<(String, String, String, u32)> = chains
            .iter()
            .flat_map(|c| {
                c.rules
                    .iter()
                    .map(|r| (r.pattern.clone(), r.clause.clone(), r.file.clone(), r.line))
            })
            .collect();
        assert!(
            matchers.iter().any(|(p, c, f, _)| p == "/admin/**" && c == "hasRole" && f.ends_with("SecurityConfig.java")),
            "应取到 /admin/** 的 hasRole 子句: {matchers:?}"
        );
        assert!(
            matchers.iter().any(|(p, c, _, _)| p == "/public/**" && c == "permitAll"),
            "应取到 /public/** 的 permitAll 子句: {matchers:?}"
        );
        let decls = security_config_declarations(&files);
        assert_eq!(decls.len(), 1, "应识别出安全配置类: {decls:?}");

        let mut routes = vec![
            json!({"line": 1, "route": "/admin/users", "http_method": "GET"}),
            json!({"line": 2, "route": "/public/info", "http_method": "GET"}),
            json!({"line": 3, "route": "/other/thing", "http_method": "GET"}),
        ];
        annotate_route_coverage(&mut routes, &chains);
        assert_eq!(routes[0]["global_coverage"], "covered_by_global_config", "{routes:?}");
        assert_eq!(routes[1]["global_coverage"], "permitted_by_global_config", "{routes:?}");
        // `anyRequest().authenticated()` 是 Catch-all：未命中具体规则的路径同样受保护
        assert_eq!(routes[2]["global_coverage"], "covered_by_global_config", "{routes:?}");

        // 没有 `anyRequest()` 的链：未命中即如实报"无匹配"（不等于未受保护）
        let noany = vec![(
            "src/NoAny.java".to_string(),
            concat!(
                "public class NoAny {\n",
                "    @Bean\n",
                "    public SecurityFilterChain c(HttpSecurity http) {\n",
                "        http.authorizeHttpRequests(x -> x.requestMatchers(\"/admin/**\").hasRole(\"ADMIN\"));\n",
                "        return null;\n",
                "    }\n",
                "}\n",
            )
            .to_string(),
        )];
        let chains3 = security_config_chains(&noany);
        let mut r3 = vec![json!({"line": 1, "route": "/other", "http_method": "GET"})];
        annotate_route_coverage(&mut r3, &chains3);
        assert_eq!(r3[0]["global_coverage"], "no_global_match_found", "{r3:?}");

        // 无任何安全配置时：如实报"未找到配置"，不推断"未受保护"
        let mut solo = vec![json!({"line": 1, "route": "/x", "http_method": "GET"})];
        annotate_route_coverage(&mut solo, &[]);
        assert_eq!(solo[0]["global_coverage"], "no_global_config_found", "{solo:?}");
    }

    /// 顺序语义：`@Order` 小者先求值、链内首个匹配生效；无序链结论矛盾时报 ambiguous。
    #[test]
    fn test_security_chain_ordering_and_ambiguity() {
        let files = vec![(
            "src/SecurityConfig.java".to_string(),
            concat!(
                "package app;\n",
                "public class SecurityConfig {\n",
                "    @Bean\n",
                "    @Order(1)\n",
                "    public SecurityFilterChain apiChain(HttpSecurity http) {\n",
                "        http.securityMatcher(\"/api/**\");\n",
                "        http.authorizeHttpRequests(auth -> auth\n",
                "            .requestMatchers(\"/api/admin/**\").hasRole(\"ADMIN\")\n",
                "            .anyRequest().authenticated());\n",
                "        return null;\n",
                "    }\n",
                "    @Bean\n",
                "    public SecurityFilterChain webChain(HttpSecurity http) {\n",
                "        http.authorizeHttpRequests(auth -> auth\n",
                "            .requestMatchers(\"/**\").permitAll());\n",
                "        return null;\n",
                "    }\n",
                "}\n",
            )
            .to_string(),
        )];
        let chains = security_config_chains(&files);
        assert_eq!(chains.len(), 2, "应切出两条链: {chains:?}");
        assert_eq!(chains[0].order, Some(1), "链 1 应带 @Order(1): {chains:?}");
        assert_eq!(chains[0].matcher.as_deref(), Some("/api/**"), "{chains:?}");
        let mut routes = vec![
            json!({"line": 1, "route": "/api/admin/x", "http_method": "GET"}),
            json!({"line": 2, "route": "/api/open/x", "http_method": "GET"}),
            json!({"line": 3, "route": "/web/page", "http_method": "GET"}),
        ];
        annotate_route_coverage(&mut routes, &chains);
        assert_eq!(routes[0]["global_coverage"], "covered_by_global_config", "{routes:?}");
        assert_eq!(routes[0]["global_match"]["chain_order"], 1, "{routes:?}");
        assert_eq!(routes[1]["global_coverage"], "covered_by_global_config", "{routes:?}");
        assert_eq!(routes[2]["global_coverage"], "permitted_by_global_config", "{routes:?}");

        let ambiguous = vec![(
            "src/Two.java".to_string(),
            concat!(
                "public class Two {\n",
                "    @Bean\n",
                "    public SecurityFilterChain a(HttpSecurity http) {\n",
                "        http.authorizeHttpRequests(x -> x.requestMatchers(\"/x/**\").permitAll());\n",
                "        return null;\n",
                "    }\n",
                "    @Bean\n",
                "    public SecurityFilterChain b(HttpSecurity http) {\n",
                "        http.authorizeHttpRequests(x -> x.requestMatchers(\"/x/**\").hasRole(\"ADMIN\"));\n",
                "        return null;\n",
                "    }\n",
                "}\n",
            )
            .to_string(),
        )];
        let chains2 = security_config_chains(&ambiguous);
        let mut r2 = vec![json!({"line": 1, "route": "/x/y", "http_method": "GET"})];
        annotate_route_coverage(&mut r2, &chains2);
        assert_eq!(r2[0]["global_coverage"], "ambiguous_across_chains", "{r2:?}");
    }
    /// 容器级过滤器：`@WebFilter` / `FilterRegistrationBean` / `web.xml` 三类注册都能被取到，
    /// 且按 Servlet 风格模式与路由匹配（`/*` 全匹配、`/x/*` 前缀、`*.ext` 后缀）。
    #[test]
    fn test_container_filter_registrations() {
        assert!(servlet_pattern_matches("/a/b", "/*"));
        assert!(servlet_pattern_matches("/api/x", "/api/*"));
        assert!(!servlet_pattern_matches("/other/x", "/api/*"));
        assert!(servlet_pattern_matches("/page.jsp", "*.jsp"));
        assert!(servlet_pattern_matches("/exact", "/exact"));

        let files = vec![
            (
                "src/AuthFilter.java".to_string(),
                concat!(
                    "package app;\n",
                    "import javax.servlet.annotation.WebFilter;\n",
                    "@WebFilter(urlPatterns = \"/api/*\")\n",
                    "public class AuthFilter implements Filter {\n",
                    "}\n",
                )
                .to_string(),
            ),
            (
                "src/FilterConfig.java".to_string(),
                concat!(
                    "package app;\n",
                    "public class FilterConfig {\n",
                    "    @Bean\n",
                    "    public FilterRegistrationBean<RateLimitFilter> limit() {\n",
                    "        FilterRegistrationBean<RateLimitFilter> reg = new FilterRegistrationBean<>();\n",
                    "        reg.addUrlPatterns(\"/admin/*\");\n",
                    "        return reg;\n",
                    "    }\n",
                    "}\n",
                )
                .to_string(),
            ),
            (
                "web/WEB-INF/web.xml".to_string(),
                concat!(
                    "<web-app>\n",
                    "  <filter>\n",
                    "    <filter-name>csrfFilter</filter-name>\n",
                    "    <filter-class>app.CsrfFilter</filter-class>\n",
                    "  </filter>\n",
                    "  <filter-mapping>\n",
                    "    <filter-name>csrfFilter</filter-name>\n",
                    "    <url-pattern>/secure/*</url-pattern>\n",
                    "  </filter-mapping>\n",
                    "</web-app>\n",
                )
                .to_string(),
            ),
        ];
        let filters = container_filter_registrations(&files);
        assert!(
            filters.iter().any(|f| f.kind == "web_filter" && f.pattern == "/api/*"),
            "@WebFilter 的 urlPatterns 应被取到: {filters:?}"
        );
        assert!(
            filters.iter().any(|f| f.kind == "filter_registration" && f.pattern == "/admin/*"),
            "FilterRegistrationBean 的 addUrlPatterns 应被取到: {filters:?}"
        );
        assert!(
            filters.iter().any(|f| f.kind == "web_xml_filter_mapping" && f.pattern == "/secure/*" && f.name.as_deref() == Some("csrfFilter")),
            "web.xml 的 url-pattern 与 filter-name 应被取到: {filters:?}"
        );

        let mut routes = vec![
            json!({"line": 1, "route": "/api/users", "http_method": "GET"}),
            json!({"line": 2, "route": "/admin/users", "http_method": "GET"}),
            json!({"line": 3, "route": "/other/page", "http_method": "GET"}),
        ];
        annotate_container_filters(&mut routes, &filters);
        assert_eq!(routes[0]["container_filter_count"], 1, "{routes:?}");
        assert_eq!(routes[1]["container_filter_count"], 1, "{routes:?}");
        assert_eq!(routes[2]["container_filter_count"], 0, "{routes:?}");
        assert_eq!(
            routes[0]["container_filters"][0]["kind"], "web_filter",
            "{routes:?}"
        );
    }

    /// 类级授权注解：打在类声明正上方的 `@PreAuthorize` 等应作为类级证据取到；
    /// 只有方法级注解时不得算作类级；无类级注解时如实报"本文件不可见"。
    #[test]
    fn test_class_level_auth_annotations() {
        let with_class_auth = concat!(
            "package app;\n",
            "import org.springframework.security.access.prepost.PreAuthorize;\n",
            "@RestController\n",
            "@RequestMapping(\"/api\")\n",
            "@PreAuthorize(\"hasRole('ADMIN')\")\n",
            "public class AdminApi {\n",
            "    @GetMapping(\"/users\")\n",
            "    public String users() { return \"ok\"; }\n",
            "}\n",
        );
        let hits = class_level_auth_annotations(with_class_auth);
        assert_eq!(hits.len(), 1, "应取到 1 条类级授权注解: {hits:?}");
        assert!(
            hits[0].1.contains("hasRole('ADMIN')"),
            "应取到类级 @PreAuthorize 文本: {hits:?}"
        );
        assert_eq!(hits[0].0, 5, "应报类级注解所在行: {hits:?}");

        // 只有方法级注解：向上收集应当在类声明处停止，不得把方法注解算作类级
        let method_only = concat!(
            "package app;\n",
            "@RestController\n",
            "public class OpenApi {\n",
            "    @GetMapping(\"/users\")\n",
            "    @PreAuthorize(\"isAuthenticated()\")\n",
            "    public String users() { return \"ok\"; }\n",
            "}\n",
        );
        let none = class_level_auth_annotations(method_only);
        assert!(none.is_empty(), "方法级注解不得算作类级: {none:?}");

        let mut routes = vec![json!({"line": 1, "route": "/api/users", "http_method": "GET"})];
        annotate_class_level_auth(&mut routes, &hits);
        assert_eq!(routes[0]["class_level_auth_count"], 1, "{routes:?}");
        assert_eq!(routes[0]["auth_scope"], "class_level_visible", "{routes:?}");

        let mut empty = vec![json!({"line": 1, "route": "/x", "http_method": "GET"})];
        annotate_class_level_auth(&mut empty, &[]);
        assert_eq!(empty[0]["auth_scope"], "none_visible_in_file", "{empty:?}");
        assert_eq!(empty[0]["class_level_auth_count"], 0, "{empty:?}");
    }

    /// 方法级授权覆盖类级：有方法级注解的端点报 `method_level`，只有类级时报 `class_level`，
    /// 两者都不可见时报 `none_visible`。用真实调用链（AST 定位方法 + 向上取注解）验证。
    #[tokio::test]
    async fn test_auth_effect_method_overrides_class() {
        let root = std::env::temp_dir().join("ctx-audit-auth-effect");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/AdminApi.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "import org.springframework.security.access.prepost.PreAuthorize;\n",
                "@RestController\n",
                "@PreAuthorize(\"hasRole('ADMIN')\")\n",
                "public class AdminApi {\n",
                "    @GetMapping(\"/admin/users\")\n",
                "    public String users() { return \"ok\"; }\n",
                "\n",
                "    @GetMapping(\"/admin/me\")\n",
                "    @PreAuthorize(\"isAuthenticated()\")\n",
                "    public String me() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/AdminApi.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let users = routes
            .iter()
            .find(|r| r["route"] == "/admin/users")
            .expect("应有 /admin/users");
        let me = routes
            .iter()
            .find(|r| r["route"] == "/admin/me")
            .expect("应有 /admin/me");
        assert_eq!(users["auth_effect"], "class_level", "{d}");
        assert_eq!(users["class_level_auth_count"], 1, "{d}");
        assert_eq!(me["auth_effect"], "method_level", "{d}");
        assert_eq!(me["method_level_auth_count"], 1, "{d}");
        assert!(me["method_level_auth"][0]["text"]
            .as_str()
            .unwrap_or("")
            .contains("isAuthenticated"), "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Shiro 链：`filterChainDefinitionMap.put` 保持声明顺序、首个匹配生效；
    /// `anon` 映射为放行、`roles[...]`/`perms[...]`/`authc` 映射为受限；
    /// Shiro 特有通配（`/x**`、`/x/*`）按各自语义匹配。
    #[test]
    fn test_shiro_filter_chains() {
        assert!(shiro_pattern_matches("/favicon.ico", "/favicon.ico**"));
        assert!(shiro_pattern_matches("/captcha/captchaImage", "/captcha/captchaImage**"));
        assert!(shiro_pattern_matches("/css/a.css", "/css/**"));
        assert!(shiro_pattern_matches("/css/a.css", "/css/*"));
        assert!(!shiro_pattern_matches("/css/a/b.css", "/css/*"));
        assert!(!shiro_pattern_matches("/admin/x", "/css/**"));
        assert_eq!(shiro_clause("anon"), "permitAll");
        assert_eq!(shiro_clause("authc,roles[admin]"), "hasRole");
        assert_eq!(shiro_clause("authc,perms[user:add]"), "hasAuthority");
        assert_eq!(shiro_clause("user"), "authenticated");

        let files = vec![(
            "src/main/java/app/ShiroConfig.java".to_string(),
            concat!(
                "package app;\n",
                "public class ShiroConfig {\n",
                "    public ShiroFilterFactoryBean shiroFilterFactoryBean() {\n",
                "        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();\n",
                "        filterChainDefinitionMap.put(\"/login\", \"anon\");\n",
                "        filterChainDefinitionMap.put(\"/css/**\", \"anon\");\n",
                "        filterChainDefinitionMap.put(\"/admin/**\", \"authc,roles[admin]\");\n",
                "        filterChainDefinitionMap.put(\"/**\", \"authc\");\n",
                "        return null;\n",
                "    }\n",
                "}\n",
            )
            .to_string(),
        )];
        let chains = shiro_filter_chains(&files);
        assert_eq!(chains.len(), 1, "应切出一条 Shiro 链: {chains:?}");
        assert_eq!(chains[0].rules.len(), 4, "应取到 4 条链定义: {chains:?}");
        assert_eq!(chains[0].rules[0].pattern, "/login", "{chains:?}");
        assert_eq!(chains[0].rules[0].clause, "permitAll", "{chains:?}");

        let mut routes = vec![
            json!({"line": 1, "route": "/login", "http_method": "GET"}),
            json!({"line": 2, "route": "/css/main.css", "http_method": "GET"}),
            json!({"line": 3, "route": "/admin/users", "http_method": "GET"}),
            json!({"line": 4, "route": "/system/other", "http_method": "GET"}),
        ];
        annotate_route_coverage(&mut routes, &chains);
        assert_eq!(routes[0]["global_coverage"], "permitted_by_global_config", "{routes:?}");
        assert_eq!(routes[1]["global_coverage"], "permitted_by_global_config", "{routes:?}");
        assert_eq!(routes[2]["global_coverage"], "covered_by_global_config", "{routes:?}");
        assert_eq!(routes[2]["global_match"]["clause"], "hasRole", "{routes:?}");
        // 声明序在末位的 `/**` 兜底：前面的具体规则先命中
        assert_eq!(routes[3]["global_coverage"], "covered_by_global_config", "{routes:?}");
        assert_eq!(routes[3]["ordering_basis"], "declaration_order", "{routes:?}");
    }

    /// Shiro 注解式授权：`@RequiresPermissions` / `@RequiresRoles` 等应与 Spring 注解一样
    /// 成为类级/方法级证据，并参与"方法级覆盖类级"的判定。
    #[test]
    fn test_shiro_authorization_annotations_are_evidence() {
        let content = concat!(
            "package app;\n",
            "import org.apache.shiro.authz.annotation.RequiresPermissions;\n",
            "import org.apache.shiro.authz.annotation.RequiresRoles;\n",
            "@RestController\n",
            "@RequiresRoles(\"admin\")\n",
            "public class SysUserController {\n",
            "    @RequiresPermissions(\"system:user:list\")\n",
            "    @PostMapping(\"/list\")\n",
            "    public String list() { return \"ok\"; }\n",
            "    @PostMapping(\"/view\")\n",
            "    public String view() { return \"ok\"; }\n",
            "}\n",
        );
        let class_hits = class_level_auth_annotations(content);
        assert_eq!(class_hits.len(), 1, "类级应取到 @RequiresRoles: {class_hits:?}");
        assert!(class_hits[0].1.contains("RequiresRoles"), "{class_hits:?}");

        let method_hits = method_level_auth_annotations(content, 7, 9, 6);
        assert_eq!(
            method_hits.len(),
            1,
            "方法级应取到 @RequiresPermissions: {method_hits:?}"
        );
        assert!(
            method_hits[0].1.contains("system:user:list"),
            "{method_hits:?}"
        );
        assert_eq!(
            auth_effect(class_hits.len(), method_hits.len()),
            "method_level",
            "方法级注解存在时落点应为方法级"
        );
        assert_eq!(auth_effect(class_hits.len(), 0), "class_level");
        assert_eq!(auth_effect(0, 0), "none_visible");
    }




    /// 类级映射注解只提供前缀，不得被当成端点：`scope=class` 且不参与覆盖/授权判定。
    #[tokio::test]
    async fn test_class_scope_mapping_is_not_an_endpoint() {
        let root = std::env::temp_dir().join("ctx-audit-route-scope");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/Api.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "@RequestMapping(\"/api\")\n",
                "public class Api {\n",
                "    @GetMapping(\"/ping\")\n",
                "    public String ping() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool.execute(json!({"file": "src/Api.java"})).await.unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let class_entry = routes
            .iter()
            .find(|r| r["scope"] == "class")
            .expect("类级映射应被标注 scope=class");
        assert_eq!(class_entry["route"], "/api", "{d}");
        assert!(
            class_entry.get("global_coverage").is_none(),
            "类级映射不应参与覆盖判定: {d}"
        );
        assert!(
            class_entry.get("auth_effect").is_none(),
            "类级映射不应参与授权落点判定: {d}"
        );
        let method_entry = routes
            .iter()
            .find(|r| r["scope"] == "method")
            .expect("方法级映射应为 scope=method");
        assert_eq!(method_entry["route"], "/api/ping", "{d}");
        assert!(method_entry.get("global_coverage").is_some(), "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }
    /// 嵌套匿名回调内的行，应归属到最近的**实名**外层函数（而不是因最内层是占位名就整个放弃）；
    /// 同时保留"只有匿名体时不接管、交由启发式命名"的行为。
    #[tokio::test]
    async fn test_js_nested_callback_attributes_to_named_outer_function() {
        let root = std::env::temp_dir().join("ctx-audit-js-nested");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/index.js"),
            concat!(
                "module.exports = function (args, opts) {\n",
                "    var aliases = {};\n",
                "    Object.keys(opts.alias || {}).forEach(function (key) {\n",
                "        aliases[key] = [].concat(opts.alias[key]);\n",
                "    });\n",
                "    return aliases;\n",
                "};\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::SliceBackward);
        let out = tool
            .execute(json!({"file": "src/index.js", "line": 4, "depth": 40, "forward": 0}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        assert_eq!(d["data"]["scope_source"], "ast", "{d}");
        assert_eq!(d["data"]["function"], "exports", "{d}");
        assert_eq!(d["data"]["function_def_line"], 1, "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }


    /// 拦截器注册：`addInterceptor(x).addPathPatterns("/**")` 应作为证据交付；
    /// 无显式路径时按"全部路径"处理并如实标注依据；不参与鉴权判定字段。
    #[test]
    fn test_interceptor_registrations() {
        let files = vec![(
            "src/ApiConfig.java".to_string(),
            concat!(
                "package app;\n",
                "public class ApiConfig implements WebMvcConfigurer {\n",
                "    public void addInterceptors(InterceptorRegistry registry) {\n",
                "        registry.addInterceptor(new RateLimitInterceptor()).addPathPatterns(\"/api/**\");\n",
                "        registry.addInterceptor(localeChangeInterceptor());\n",
                "    }\n",
                "}\n",
            )
            .to_string(),
        )];
        let regs = interceptor_registrations(&files);
        assert!(
            regs.iter()
                .any(|r| r.pattern == "/api/**" && r.name.as_deref() == Some("RateLimitInterceptor")),
            "应取到带路径的拦截器注册: {regs:?}"
        );
        assert!(
            regs.iter().any(|r| r.basis == "default_all_paths"),
            "无显式路径的注册应按全部路径并标注依据: {regs:?}"
        );

        let mut routes = vec![
            json!({"line": 1, "route": "/api/users", "http_method": "GET", "scope": "method"}),
            json!({"line": 2, "route": "/other", "http_method": "GET", "scope": "method"}),
            json!({"line": 3, "route": "/api", "http_method": "ANY", "scope": "class"}),
        ];
        annotate_interceptors(&mut routes, &regs);
        assert_eq!(routes[0]["interceptor_count"], 2, "{routes:?}");
        assert_eq!(routes[1]["interceptor_count"], 1, "{routes:?}");
        assert!(
            routes[2].get("interceptor_count").is_none(),
            "类级映射不应参与: {routes:?}"
        );
        // 证据面不得冒充鉴权判定
        assert!(routes[0].get("auth_effect").is_none(), "{routes:?}");
    }

    /// 导入语句不得作为证据：`import ...FilterRegistrationBean;` 不能产出"容器过滤器注册"；
    /// 同一文件里的真实注册必须能取出**过滤器名**。
    #[test]
    fn test_imports_are_not_evidence_and_filter_name_is_read() {
        assert!(is_import_or_package_line("import org.springframework.boot.web.servlet.FilterRegistrationBean;"));
        assert!(!is_import_or_package_line("registration.setFilter(new XssFilter());"));

        let files = vec![
            (
                "src/FilterConfig.java".to_string(),
                concat!(
                    "package app;\n",
                    "import org.springframework.boot.web.servlet.FilterRegistrationBean;\n",
                    "import com.ruoyi.common.xss.XssFilter;\n",
                    "public class FilterConfig {\n",
                    "    @Bean\n",
                    "    public FilterRegistrationBean<XssFilter> xssFilterRegistration() {\n",
                    "        FilterRegistrationBean<XssFilter> registration = new FilterRegistrationBean<>();\n",
                    "        registration.setDispatcherTypes(DispatcherType.REQUEST);\n",
                    "        registration.setFilter(new XssFilter());\n",
                    "        registration.addUrlPatterns(\"/*\");\n",
                    "        registration.setName(\"xssFilter\");\n",
                    "        return registration;\n",
                    "    }\n",
                    "}\n",
                )
                .to_string(),
            ),
            (
                "src/OnlyImport.java".to_string(),
                concat!(
                    "package app;\n",
                    "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n",
                    "public class OnlyImport {\n",
                    "}\n",
                )
                .to_string(),
            ),
        ];
        let regs = container_filter_registrations(&files);
        assert_eq!(regs.len(), 1, "只有真实注册才应产出条目（import 行不算）: {regs:?}");
        assert_eq!(regs[0].name.as_deref(), Some("xssFilter"), "{regs:?}");
        assert_eq!(regs[0].pattern, "/*", "{regs:?}");
        assert!(
            regs[0].line > 3,
            "行号应指向真实注册而非 import 行: {regs:?}"
        );

        // 只有 import 的文件不得"看起来像安全配置"
        assert!(
            !looks_like_security_config(&files[1].1),
            "仅导入 HttpSecurity 的文件不得被判为安全配置"
        );
        assert!(
            !looks_like_shiro_config("import org.apache.shiro.spring.web.ShiroFilterFactoryBean;\n"),
            "仅导入 ShiroFilterFactoryBean 的文件不得被判为 Shiro 配置"
        );
    }

    /// 模块根：多模块仓库里应取**最深**的含构建文件的祖先；无构建文件时返回 None（保持全项目范围）。
    #[test]
    fn test_module_root_scoping() {
        let files = vec![
            ("pom.xml".to_string(), String::new()),
            ("appA/pom.xml".to_string(), String::new()),
            ("appA/src/main/java/A.java".to_string(), String::new()),
            ("appB/build.gradle".to_string(), String::new()),
            ("appB/src/main/java/B.java".to_string(), String::new()),
        ];
        assert_eq!(
            module_root_of(&files, "appA/src/main/java/A.java").as_deref(),
            Some("appA/"),
            "应取最深模块根"
        );
        assert_eq!(
            module_root_of(&files, "appB/src/main/java/B.java").as_deref(),
            Some("appB/")
        );
        assert_eq!(module_root_of(&files, "loose/C.java"), None);
        // 聚合者显式列出子模块 ⇒ 应用根上移到聚合者（多模块单应用必须跨模块取证据）
        let agg = vec![
            ("pom.xml".to_string(), "<project><modules><module>appA</module></modules></project>".to_string()),
            ("appA/pom.xml".to_string(), "<project/>".to_string()),
            ("appA/src/main/java/A.java".to_string(), String::new()),
            ("appB/pom.xml".to_string(), "<project/>".to_string()),
            ("appB/src/main/java/B.java".to_string(), String::new()),
        ];
        assert_eq!(module_root_of(&agg, "appA/src/main/java/A.java").as_deref(), Some(""), "被聚合的模块应上移到根");
        assert_eq!(module_root_of(&agg, "appB/src/main/java/B.java").as_deref(), Some("appB/"), "未被聚合者保持自身模块");
        assert_eq!(evidence_scope_label(&Some("appA/".to_string())), "module");
        assert_eq!(evidence_scope_label(&None), "project");
    }

    /// 端到端：同仓库两个模块各有安全配置，端点的覆盖判定**只能**来自本模块的配置。
    #[tokio::test]
    async fn test_cross_file_evidence_is_scoped_to_the_module() {
        let root = std::env::temp_dir().join("ctx-audit-module-scope");
        let _ = std::fs::remove_dir_all(&root);
        for d in ["appA/src/main/java", "appB/src/main/java"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("appA/pom.xml"), "<project/>").unwrap();
        std::fs::write(root.join("appB/pom.xml"), "<project/>").unwrap();
        std::fs::write(
            root.join("appA/src/main/java/Api.java"),
            concat!(
                "package a;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "@RequestMapping(\"/a\")\n",
                "public class Api {\n",
                "    @GetMapping(\"/ping\")\n",
                "    public String ping() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("appA/src/main/java/SecurityConfig.java"),
            concat!(
                "package a;\n",
                "public class SecurityConfig {\n",
                "    public SecurityFilterChain chain(HttpSecurity http) {\n",
                "        http.authorizeHttpRequests(a -> a.requestMatchers(\"/a/**\").hasRole(\"A\"));\n",
                "        return null;\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        // 另一个模块的配置：绝不能影响 A 端点的判定
        std::fs::write(
            root.join("appB/src/main/java/OtherConfig.java"),
            concat!(
                "package b;\n",
                "public class OtherConfig {\n",
                "    public SecurityFilterChain chain(HttpSecurity http) {\n",
                "        http.authorizeHttpRequests(x -> x.requestMatchers(\"/**\").permitAll());\n",
                "        return null;\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "appA/src/main/java/Api.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let ping = routes
            .iter()
            .find(|r| r["route"] == "/a/ping")
            .expect("应有 /a/ping");
        assert_eq!(ping["evidence_scope"], "module", "{d}");
        assert_eq!(ping["chains_considered"], 1, "只应考虑本模块的链: {d}");
        assert_eq!(ping["global_coverage"], "covered_by_global_config", "{d}");
        assert!(
            ping["global_match"]["chain_file"]
                .as_str()
                .unwrap_or("")
                .contains("appA/"),
            "覆盖判定必须来自本模块配置: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
    /// web.xml 按区段归类：`<filter-mapping>` 是过滤器证据（带本映射的 filter-name 与 dispatcher）；
    /// `<security-constraint>` 是声明式约束证据；`<servlet-mapping>` 与无上下文的 `<url-pattern>` 不作保护证据。
    #[test]
    fn test_web_xml_sections_are_classified() {
        let files = vec![(
            "web/WEB-INF/web.xml".to_string(),
            concat!(
                "<web-app>\n",
                "  <servlet-mapping>\n",
                "    <servlet-name>app</servlet-name>\n",
                "    <url-pattern>*.htm</url-pattern>\n",
                "  </servlet-mapping>\n",
                "  <filter-mapping>\n",
                "    <filter-name>springSecurityFilterChain</filter-name>\n",
                "    <url-pattern>/*</url-pattern>\n",
                "    <dispatcher>REQUEST</dispatcher>\n",
                "  </filter-mapping>\n",
                "  <security-constraint>\n",
                "    <web-resource-collection>\n",
                "      <url-pattern>/admin/*</url-pattern>\n",
                "    </web-resource-collection>\n",
                "  </security-constraint>\n",
                "  <welcome-file-list>\n",
                "    <url-pattern>/bare</url-pattern>\n",
                "  </welcome-file-list>\n",
                "</web-app>\n",
            )
            .to_string(),
        )];
        let regs = container_filter_registrations(&files);
        assert!(
            regs.iter().any(|r| r.kind == "web_xml_filter_mapping"
                && r.pattern == "/*"
                && r.name.as_deref() == Some("springSecurityFilterChain")
                && r.dispatcher.as_deref() == Some("REQUEST")),
            "filter-mapping 应带出名字与 dispatcher: {regs:?}"
        );
        assert!(
            regs.iter().any(|r| r.kind == "web_xml_security_constraint" && r.pattern == "/admin/*"),
            "security-constraint 应作为声明式约束证据: {regs:?}"
        );
        assert!(
            !regs.iter().any(|r| r.pattern == "*.htm"),
            "servlet-mapping 是路由，不得当作保护证据: {regs:?}"
        );
        assert!(
            !regs.iter().any(|r| r.pattern == "/bare"),
            "无区段上下文的 url-pattern 不得当作保护证据: {regs:?}"
        );
    }
    /// 非字面量匹配器（如 `requestMatchers(ignoreUrls)`）不得被静默丢弃：
    /// 应作为 `<dynamic>` 规则登记，并在覆盖判定上带出 `coverage_caveat`。
    #[test]
    fn test_dynamic_matcher_is_visible_not_silently_dropped() {
        let files = vec![(
            "src/SecurityConfig.java".to_string(),
            concat!(
                "package app;\n",
                "public class SecurityConfig {\n",
                "    public SecurityFilterChain chain(HttpSecurity http) {\n",
                "        http.authorizeHttpRequests(a -> {\n",
                "            String[] ignoreUrls = props.getIgnoreUrls();\n",
                "            a.requestMatchers(ignoreUrls).permitAll();\n",
                "            a.anyRequest().authenticated();\n",
                "        });\n",
                "        return null;\n",
                "    }\n",
                "}\n",
            )
            .to_string(),
        )];
        let chains = security_config_chains(&files);
        assert_eq!(chains.len(), 1, "{chains:?}");
        assert!(
            chains[0].rules.iter().any(|r| r.pattern == "<dynamic>"),
            "动态匹配器必须被登记而不是丢弃: {chains:?}"
        );
        let mut routes = vec![json!({"line": 1, "route": "/api/v1/auth/captcha", "http_method": "GET", "scope": "method"})];
        annotate_route_coverage(&mut routes, &chains);
        assert_eq!(
            routes[0]["coverage_caveat"], "dynamic_matcher_unresolved",
            "必须带出动态匹配器未解析的提示: {routes:?}"
        );
    }

    /// `@WebFilter` 的类名在手写注解下方（常隔着 `@Order`/`@Component`）也要取到。
    #[test]
    fn test_web_filter_class_name_is_read_from_below() {
        let files = vec![(
            "src/CorsFilter.java".to_string(),
            concat!(
                "package app;\n",
                "@WebFilter(urlPatterns = \"/*\")\n",
                "@Order(Integer.MIN_VALUE)\n",
                "@Component\n",
                "public class CorsFilter implements Filter {\n",
                "}\n",
            )
            .to_string(),
        )];
        let regs = container_filter_registrations(&files);
        assert_eq!(regs.len(), 1, "{regs:?}");
        assert_eq!(regs[0].kind, "web_filter", "{regs:?}");
        assert_eq!(regs[0].name.as_deref(), Some("CorsFilter"), "{regs:?}");
        assert_eq!(regs[0].pattern, "/*", "{regs:?}");
    }
    /// 反应式安全配置应被**建模**：`pathMatchers("/x").permitAll()` 与 `anyExchange().authenticated()`
    /// 与 servlet 侧同语义（链内首个匹配生效、`anyExchange()` 等价 `/**` 兜底），并可给出出处。
    #[tokio::test]
    async fn test_reactive_security_rules_are_modelled() {
        let root = std::env::temp_dir().join("ctx-audit-reactive-modelled");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/WebfluxSecurityConfiguration.java"),
            concat!(
                "package app;\n",
                "import org.springframework.security.config.web.server.ServerHttpSecurity;\n",
                "import org.springframework.security.web.server.SecurityWebFilterChain;\n",
                "@EnableWebFluxSecurity\n",
                "public class WebfluxSecurityConfiguration {\n",
                "    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {\n",
                "        http.authorizeExchange(e -> e\n",
                "                .pathMatchers(\"/login\").permitAll()\n",
                "                .anyExchange().authenticated());\n",
                "        return http.build();\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/IndexController.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "public class IndexController {\n",
                "    @GetMapping(\"/\")\n",
                "    public String index() { return \"ok\"; }\n",
                "    @GetMapping(\"/login\")\n",
                "    public String login() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/IndexController.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let idx = routes.iter().find(|r| r["route"] == "/").expect("应有 /");
        assert_eq!(idx["global_coverage"], "covered_by_global_config", "{d}");
        assert_eq!(idx["chains_considered"], 1, "{d}");
        assert!(
            idx["global_match"]["file"]
                .as_str()
                .unwrap_or("")
                .contains("WebfluxSecurityConfiguration.java"),
            "应给出来自反应式配置的出处: {d}"
        );
        assert!(idx["coverage_caveat"].is_null(), "已建模就不该带未建模提示: {d}");
        let login = routes
            .iter()
            .find(|r| r["route"] == "/login")
            .expect("应有 /login");
        assert_eq!(
            login["global_coverage"], "permitted_by_global_config",
            "`pathMatchers(\"/login\").permitAll()` 应判为公开: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 反应式配置存在、但**没有可用的规则**时，仍要如实说"未建模"，不得说成"没有保护"。
    #[tokio::test]
    async fn test_reactive_config_without_rules_is_reported_as_not_modelled() {
        let root = std::env::temp_dir().join("ctx-audit-reactive-norules");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/WebfluxSecurityConfiguration.java"),
            concat!(
                "package app;\n",
                "import org.springframework.security.config.web.server.ServerHttpSecurity;\n",
                "import org.springframework.security.web.server.SecurityWebFilterChain;\n",
                "@EnableWebFluxSecurity\n",
                "public class WebfluxSecurityConfiguration {\n",
                "    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {\n",
                "        http.csrf(csrf -> csrf.disable());\n",
                "        return http.build();\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/IndexController.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "public class IndexController {\n",
                "    @GetMapping(\"/\")\n",
                "    public String index() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/IndexController.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let idx = routes.iter().find(|r| r["route"] == "/").expect("应有 /");
        assert_eq!(idx["global_coverage"], "framework_not_modeled", "{d}");
        assert_eq!(
            idx["coverage_caveat"], "reactive_security_not_modeled",
            "{d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Spring Security 的 XML 配置应与注解/Java DSL 侧同语义地参与覆盖判定：
    /// `permitAll` → 公开、`hasRole(...)` → 已覆盖、`/x*` 按前缀命中、并给出来处。
    #[tokio::test]
    async fn test_spring_xml_security_rules_are_modelled() {
        let root = std::env::temp_dir().join("ctx-audit-spring-xml");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/applicationContext-security.xml"),
            concat!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
                "<b:beans xmlns=\"http://www.springframework.org/schema/security\"\n",
                "         xmlns:b=\"http://www.springframework.org/schema/beans\">\n",
                "  <http>\n",
                "    <intercept-url pattern=\"/\" access=\"permitAll\"/>\n",
                "    <intercept-url pattern=\"/login.jsp*\" access=\"permitAll\"/>\n",
                "    <intercept-url pattern=\"/admin/**\" access=\"hasRole('ADMIN')\"/>\n",
                "    <intercept-url pattern=\"/**\" access=\"authenticated\"/>\n",
                "  </http>\n",
                "</b:beans>\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/PublicController.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "public class PublicController {\n",
                "    @GetMapping(\"/\")\n",
                "    public String root() { return \"ok\"; }\n",
                "    @GetMapping(\"/login.jsp\")\n",
                "    public String login() { return \"ok\"; }\n",
                "    @GetMapping(\"/admin/list\")\n",
                "    public String admin() { return \"ok\"; }\n",
                "    @GetMapping(\"/profile\")\n",
                "    public String profile() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/PublicController.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let find = |p: &str| routes.iter().find(|r| r["route"] == p).cloned();
        let root_ep = find("/").expect("应有 /");
        assert_eq!(
            root_ep["global_coverage"], "permitted_by_global_config",
            "`access=\"permitAll\"` 应判为公开: {d}"
        );
        let login = find("/login.jsp").expect("应有 /login.jsp");
        assert_eq!(
            login["global_coverage"], "permitted_by_global_config",
            "Ant 的 `/login.jsp*` 应按前缀命中: {d}"
        );
        let admin = find("/admin/list").expect("应有 /admin/list");
        assert_eq!(admin["global_coverage"], "covered_by_global_config", "{d}");
        assert_eq!(admin["global_match"]["clause"], "hasRole", "{d}");
        assert_eq!(admin["global_match"]["pattern"], "/admin/**", "{d}");
        assert!(
            admin["global_match"]["file"]
                .as_str()
                .unwrap_or("")
                .ends_with("applicationContext-security.xml"),
            "应给出来自 XML 的出处: {d}"
        );
        let profile = find("/profile").expect("应有 /profile");
        assert_eq!(
            profile["global_coverage"], "covered_by_global_config",
            "`/**` 兜底应生效: {d}"
        );
        assert_eq!(profile["global_match"]["clause"], "authenticated", "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 未建模的保护栈（示例：Sa-Token）必须显式标注，绝不能静默给"没有保护"。
    #[tokio::test]
    async fn test_unmodeled_protection_stack_is_reported() {
        let root = std::env::temp_dir().join("ctx-audit-unmodeled-stack");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/SaTokenConfigure.java"),
            concat!(
                "package app;\n",
                "public class SaTokenConfigure implements WebMvcConfigurer {\n",
                "    public void addInterceptors(InterceptorRegistry registry) {\n",
                "        registry.addInterceptor(new SaInterceptor(handle -> StpUtil.checkLogin()))\n",
                "                .addPathPatterns(\"/**\");\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/AdminController.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "@RequestMapping(\"/admin\")\n",
                "public class AdminController {\n",
                "    @GetMapping(\"/list\")\n",
                "    public String list() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/AdminController.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let r = routes
            .iter()
            .find(|x| x["route"] == "/admin/list")
            .expect("应有 /admin/list");
        assert_eq!(r["global_coverage"], "framework_not_modeled", "{d}");
        assert_eq!(r["coverage_caveat"], "unmodeled_protection_signal", "{d}");
        assert_eq!(r["unmodeled_framework"], "sa-token", "{d}");
        assert!(
            r["unmodeled_source"]["file"]
                .as_str()
                .unwrap_or("")
                .contains("SaTokenConfigure.java"),
            "要带出信号出处: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 反向守卫：通用过滤器基类（可能只是日志过滤器）不得把"确实没有配置"误升级成"未建模"。
    #[tokio::test]
    async fn test_generic_filter_base_class_does_not_trigger_unmodeled() {
        let root = std::env::temp_dir().join("ctx-audit-generic-filter");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/MDCFilter.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.filter.OncePerRequestFilter;\n",
                "public class MDCFilter extends OncePerRequestFilter {\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/PlainController.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "public class PlainController {\n",
                "    @GetMapping(\"/ping\")\n",
                "    public String ping() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/PlainController.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let r = routes.iter().find(|x| x["route"] == "/ping").expect("应有 /ping");
        assert_eq!(
            r["global_coverage"], "no_global_config_found",
            "通用过滤器基类不得触发未建模: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
    /// Allman 排版（`{` 独占下一行）下，类级前缀与类级授权注解仍须可判定。
    #[test]
    fn test_type_declaration_allman_style() {
        let content = concat!(
            "package app;\n",
            "@RestController\n",
            "@RequestMapping(\"/system/user\")\n",
            "@RequiresRoles(\"admin\")\n",
            "public class SysUserController extends BaseController\n",
            "{\n",
            "    @GetMapping()\n",
            "    public String list() { return \"ok\"; }\n",
            "}\n",
        );
        assert_eq!(
            class_route_prefix(content).as_deref(),
            Some("/system/user"),
            "Allman 排版下类级前缀必须可判定"
        );
        let class_hits = class_level_auth_annotations(content);
        assert_eq!(
            class_hits.len(),
            1,
            "Allman 排版下类级授权注解必须可判定: {class_hits:?}"
        );
        assert!(class_hits[0].1.contains("RequiresRoles"), "{class_hits:?}");
        assert_ne!(
            type_declaration_line(content),
            0,
            "Allman 排版下类型声明行必须可定位"
        );
    }
    /// 类级路由前缀继承：`@RequestMapping` 提供前缀，方法级映射拼接；空实参的方法级映射
    /// 应继承为类级路径，而不是留空。
    #[test]
    fn test_class_route_prefix_inheritance() {
        assert_eq!(
            join_route_paths(Some("/system/user"), Some("/list")).as_deref(),
            Some("/system/user/list")
        );
        assert_eq!(
            join_route_paths(Some("/system/user"), None).as_deref(),
            Some("/system/user")
        );
        assert_eq!(join_route_paths(None, Some("/list")).as_deref(), Some("/list"));
        assert_eq!(join_route_paths(None, None), None);
        assert_eq!(
            join_route_paths(Some("system/user/"), Some("list")).as_deref(),
            Some("/system/user/list")
        );

        let content = concat!(
            "package app;\n",
            "import org.springframework.web.bind.annotation.*;\n",
            "@RestController\n",
            "@RequestMapping(\"/system/user\")\n",
            "public class SysUserController {\n",
            "    @GetMapping()\n",
            "    public String list() { return \"ok\"; }\n",
            "}\n",
        );
        assert_eq!(class_route_prefix(content).as_deref(), Some("/system/user"));
        // 类声明所在的映射行不重复拼接前缀；方法级空实参映射继承前缀
        assert_eq!(
            annotate_route_with_prefix(content, 4, Some("/system/user")).as_deref(),
            Some("/system/user")
        );
        assert_eq!(
            annotate_route_with_prefix(content, 6, None).as_deref(),
            Some("/system/user")
        );
        assert_eq!(
            annotate_route_with_prefix(content, 7, Some("list")).as_deref(),
            Some("/system/user/list")
        );

        let no_prefix = concat!(
            "package app;\n",
            "@RestController\n",
            "public class OpenController {\n",
            "    @GetMapping(\"/ping\")\n",
            "    public String ping() { return \"ok\"; }\n",
            "}\n",
        );
        assert_eq!(class_route_prefix(no_prefix), None);
    }
    /// Java 框架证据：注解式映射必须能被识别，并带出可复核的**路由值**与 **HTTP 方法**；
    /// 方法级授权注解必须进入鉴权链判定（`auth_present`）。夹具不依赖任何外部项目。
    #[tokio::test]
    async fn test_framework_context_reads_java_spring_annotations() {
        let root = std::env::temp_dir().join("ctx-audit-framework-java");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/Api.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "import org.springframework.security.access.prepost.PreAuthorize;\n",
                "@RestController\n",
                "public class Api {\n",
                "    @GetMapping(\"/admin/users\")\n",
                "    @PreAuthorize(\"hasRole('ADMIN')\")\n",
                "    public String listUsers() {\n",
                "        return \"ok\";\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/Api.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let hit = routes
            .iter()
            .find(|r| r["http_method"] == "GET")
            .expect("应识别出 @GetMapping 路由");
        assert_eq!(hit["route"], "/admin/users", "{d}");
        let mw = d["data"]["middleware"].as_array().expect("middleware 应为数组");
        assert!(
            mw.iter().any(|m| String::from(m["text"].as_str().unwrap_or("")).contains("@PreAuthorize")),
            "方法级授权注解应进入中间件/鉴权链: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
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
    fn test_tool_surface_is_ten() {
        assert_eq!(CODE_INTEL_TOOL_SURFACE.len(), 10);
        assert_eq!(IntelKind::all().len(), 9);
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

