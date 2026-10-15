// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0
//! 单点切片与归属类测试（函数头识别、窗口边界、dispatch 候选、函数摘要、死分支）。

use super::super::*;

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


