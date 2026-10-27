// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! R250：加速器改造的单元测试 —— 索引截断诚实性、brief 输出、单条路由证伪、敏感返回面、基线卡。

use super::super::*;

fn write_file(root: &std::path::Path, rel: &str, body: &str) {
    let path = root.join(rel);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(path, body).unwrap();
}

/// 只有 `/admin/**` 规则的 Spring Security 配置（用来制造"既定范围内/外"两条路由）。
fn security_config() -> &'static str {
    concat!(
        "package app;\n",
        "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\n",
        "@Configuration\n",
        "@EnableWebSecurity\n",
        "public class SecurityConfig {\n",
        "    @Bean\n",
        "    public SecurityFilterChain chain(HttpSecurity http) throws Exception {\n",
        "        http.authorizeHttpRequests(auth -> auth\n",
        "            .requestMatchers(\"/admin/**\").hasRole(\"ADMIN\"));\n",
        "        return http.build();\n",
        "    }\n",
        "}\n",
    )
}

fn protected_controller() -> &'static str {
    concat!(
        "package app;\n",
        "import org.springframework.web.bind.annotation.*;\n",
        "@RestController\n",
        "@RequestMapping(\"/admin\")\n",
        "public class AdminController {\n",
        "    @GetMapping(\"/export\")\n",
        "    public String export() { return \"ok\"; }\n",
        "}\n",
    )
}

fn exposed_controller() -> &'static str {
    concat!(
        "package app;\n",
        "import org.springframework.web.bind.annotation.*;\n",
        "@RestController\n",
        "@RequestMapping(\"/data\")\n",
        "public class DataController {\n",
        "    @GetMapping(\"/export\")\n",
        "    public String export() {\n",
        "        String aesKey = systemConfigService.getAesHexKeyOrGenerate();\n",
        "        return aesKey;\n",
        "    }\n",
        "}\n",
    )
}

fn build_project(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(name);
    let _ = std::fs::remove_dir_all(&root);
    write_file(&root, "src/SecurityConfig.java", security_config());
    write_file(&root, "src/AdminController.java", protected_controller());
    write_file(&root, "src/DataController.java", exposed_controller());
    root
}

fn loaded(paths: &[(&str, &str)]) -> Vec<(String, String)> {
    paths
        .iter()
        .map(|(p, c)| (p.to_string(), c.to_string()))
        .collect()
}

/// 内容索引被截断时，任何"没有保护"的结论都必须降级为 `coverage_unknown`，
/// 并且不得再给出"未覆盖清单"（R249 实测：halo 上会给出 3 vs 221 的高置信错答案）。
#[test]
fn test_index_truncation_downgrades_uncovered_verdicts() {
    let root = build_project("ctx-audit-r250-truncation");
    let files = loaded(&[
        ("src/SecurityConfig.java", security_config()),
        ("src/AdminController.java", protected_controller()),
        ("src/DataController.java", exposed_controller()),
    ]);
    let id = "statv1:test";
    let filter = RouteFilter::default();

    let clean = compute_routes(&root, &files, id, false, &filter, false);
    assert_eq!(clean.data["index_truncated_at_limit"], false);
    assert!(
        !clean.data["uncovered_endpoints"]
            .as_array()
            .unwrap()
            .is_empty(),
        "未截断时应给出未覆盖清单: {}",
        clean.data["uncovered_endpoints"]
    );

    let truncated = compute_routes(&root, &files, id, false, &filter, true);
    assert_eq!(truncated.data["index_truncated_at_limit"], true);
    assert!(
        truncated.reasons.contains(&"index_truncated_at_limit"),
        "uncertainty 理由必须包含截断: {:?}",
        truncated.reasons
    );
    assert_eq!(
        truncated.data["uncovered_suppressed_by_truncation"], true,
        "截断时不得输出残缺的未覆盖清单"
    );
    assert!(
        truncated.data["uncovered_endpoints"]
            .as_array()
            .unwrap()
            .is_empty(),
        "截断时未覆盖清单必须被抑制"
    );
    let verdicts = truncated.data["verdict_counts"].as_object().unwrap();
    assert!(
        verdicts.contains_key("coverage_unknown"),
        "未覆盖判定必须降级为 coverage_unknown: {verdicts:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// brief 视图：保留判定所需字段（工单消费方依赖），去掉逐路由重证据。
#[test]
fn test_brief_view_keeps_verdict_fields_and_drops_heavy_evidence() {
    let root = build_project("ctx-audit-r250-brief");
    let files = loaded(&[
        ("src/SecurityConfig.java", security_config()),
        ("src/AdminController.java", protected_controller()),
        ("src/DataController.java", exposed_controller()),
    ]);
    let table = compute_routes(
        &root,
        &files,
        "statv1:test",
        false,
        &RouteFilter::default(),
        false,
    );
    let brief = brief_data(&table.data, 0, 0);
    assert_eq!(brief["detail"], "brief");
    assert_eq!(brief["provenance_omitted"], true);
    let routes = brief["routes"].as_array().unwrap();
    let admin = routes
        .iter()
        .find(|r| r["route"] == "/admin/export")
        .expect("应保留 /admin/export");
    assert_eq!(admin["global_coverage"], "covered_by_global_config");
    assert!(admin["file"]
        .as_str()
        .unwrap()
        .ends_with("AdminController.java"));
    assert!(admin["line"].as_u64().unwrap() > 0);
    assert!(
        admin.get("interceptors").is_none() && admin.get("container_filters").is_none(),
        "brief 不应带拦截器/过滤器重证据: {admin}"
    );
    let full_bytes = serde_json::to_string(&table.data).unwrap().len();
    let brief_bytes = serde_json::to_string(&brief).unwrap().len();
    // 小 fixture 上倍数关系不稳定（真实项目 154 路由：451KB -> ~30KB）；
    // 这里只断言"不更大"，体量收益在集成验证里按真实项目量。
    assert!(
        brief_bytes < full_bytes.max(1),
        "brief 不应大于 full: {brief_bytes} vs {full_bytes}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `explain_route`：受保护路由给出 covered + 证伪命令；未覆盖路由给出 uncovered + 敏感返回面。
#[tokio::test]
async fn test_explain_route_covered_and_uncovered() {
    let root = build_project("ctx-audit-r250-explain");
    let project = root.to_string_lossy().to_string();

    let covered = CodeIntelTool::new(project.clone(), IntelKind::ExplainRoute)
        .execute(json!({"route": "/admin/export"}))
        .await
        .unwrap();
    let c = covered.data.clone().expect("envelope");
    assert_eq!(c["data"]["matched"], true, "{c}");
    assert_eq!(c["data"]["verdict"], "covered_by_global_config", "{c}");
    assert_eq!(c["data"]["asserted_verdict"], "covered");
    assert!(
        c["data"]["falsify"]
            .as_str()
            .unwrap()
            .contains("--assert covered"),
        "证伪命令必须带 --assert: {c}"
    );
    let checks = c["data"]["decided_by"].as_array().unwrap();
    assert!(
        checks
            .iter()
            .any(|x| x["check"] == "path matched a declared rule"),
        "必须给出匹配到规则这一检查: {checks:?}"
    );

    let uncovered = CodeIntelTool::new(project.clone(), IntelKind::ExplainRoute)
        .execute(json!({"route": "/data/export"}))
        .await
        .unwrap();
    let u = uncovered.data.clone().expect("envelope");
    assert_eq!(u["data"]["verdict"], "no_global_match_found", "{u}");
    assert_eq!(u["data"]["asserted_verdict"], "uncovered");
    assert_eq!(
        u["data"]["sensitive_return"]["risky_return"], true,
        "handler 里读到 aesKey 相关调用时必须报敏感返回面: {}",
        u["data"]["sensitive_return"]
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 敏感返回面只报"窗口里读到的"敏感字段（启发式，不推断泄漏）。
#[test]
fn test_sensitive_surface_reports_read_fields() {
    let content = concat!(
        "public class C {\n",
        "    public Map<String, Object> exportSiteData() {\n",
        "        Map<String, Object> result = new HashMap<>();\n",
        "        result.put(\"adminUsername\", config.getUsername());\n",
        "        result.put(\"aesKey\", service.getAesHexKeyOrGenerate());\n",
        "        return result;\n",
        "    }\n",
        "}\n",
    );
    let files = loaded(&[("src/C.java", content)]);
    let v = sensitive_surface(&files, "src/C.java", 2);
    assert_eq!(v["available"], true, "{v}");
    assert_eq!(v["risky_return"], true, "{v}");
    let fields: Vec<String> = v["sensitive_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["field"].as_str().map(|s| s.to_lowercase()))
        .collect();
    assert!(
        fields.iter().any(|f| f.contains("aes")),
        "应读到 aes 相关字段: {fields:?}"
    );
}

/// 基线卡：链路 + 规则出处 + "注解存在但没有消费者"必须被如实报出。
#[test]
fn test_baseline_reports_chain_and_unconsumed_annotation() {
    let controller = concat!(
        "package app;\n",
        "@RestController\n",
        "public class U {\n",
        "    @PreAuthorize(\"hasRole('ADMIN')\")\n",
        "    @GetMapping(\"/u\")\n",
        "    public String u() { return \"ok\"; }\n",
        "}\n",
    );
    let files = loaded(&[
        ("src/SecurityConfig.java", security_config()),
        ("src/U.java", controller),
    ]);
    let (data, level, _reasons) = security_baseline(&files, false);
    assert!(data["summary"]["chains"].as_u64().unwrap() >= 1, "{data}");
    assert!(data["summary"]["rules"].as_u64().unwrap() >= 1, "{data}");
    let unconsumed = data["summary"]["annotations_without_consumer"]
        .as_array()
        .unwrap();
    assert!(
        unconsumed.iter().any(|v| v == "PreAuthorize"),
        "没有 @EnableMethodSecurity 时 @PreAuthorize 必须报为无消费者: {unconsumed:?}"
    );
    assert_eq!(level, "low", "有链有规则时不确定性应为 low");

    // 加了 @EnableMethodSecurity 之后，同一个注解应变成"有消费者"
    let secured = concat!(
        "package app;\n",
        "@Configuration\n",
        "@EnableMethodSecurity\n",
        "public class MethodSecurityConfig {}\n",
    );
    let files2 = loaded(&[
        ("src/SecurityConfig.java", security_config()),
        ("src/U.java", controller),
        ("src/MethodSecurityConfig.java", secured),
    ]);
    let (data2, _l2, _r2) = security_baseline(&files2, false);
    let consumers = data2["annotation_consumers"].as_array().unwrap();
    let pa = consumers
        .iter()
        .find(|c| c["annotation"] == "PreAuthorize")
        .expect("应报出 @PreAuthorize");
    assert_eq!(
        pa["consumed"], true,
        "@EnableMethodSecurity 存在时应识别消费者: {pa}"
    );
}

/// 非 Spring Bean 的类上的映射注解**不是端点**（R249 的 D2 诱饵）：
/// `explain_route` 必须给出 `not_an_endpoint`，而不是让它进"未覆盖"结论。
#[tokio::test]
async fn test_explain_route_flags_non_bean_class() {
    let root = std::env::temp_dir().join("ctx-audit-r250-notbean");
    let _ = std::fs::remove_dir_all(&root);
    write_file(&root, "src/SecurityConfig.java", security_config());
    write_file(
        &root,
        "src/LegacyHandler.java",
        concat!(
            "package app;\n",
            "import org.springframework.web.bind.annotation.GetMapping;\n",
            "public class LegacyHandler {\n",
            "    @GetMapping(\"/legacy/export\")\n",
            "    public String export() { return \"x\"; }\n",
            "}\n",
        ),
    );
    let project = root.to_string_lossy().to_string();
    let out = CodeIntelTool::new(project, IntelKind::ExplainRoute)
        .execute(json!({"route": "/legacy/export"}))
        .await
        .unwrap();
    let d = out.data.clone().expect("envelope");
    assert_eq!(d["data"]["matched"], true, "{d}");
    assert_eq!(d["data"]["not_an_endpoint"], true, "{d}");
    assert_eq!(d["data"]["asserted_verdict"], "not_an_endpoint", "{d}");
    let checks = d["data"]["decided_by"].as_array().unwrap();
    let bean = checks
        .iter()
        .find(|c| c["check"] == "declaring class is a Spring bean")
        .expect("必须有 bean 检查");
    assert_eq!(bean["result"], "absent", "{bean}");
    let _ = std::fs::remove_dir_all(&root);
}

/// 端点表与单条判定必须口径一致：非 Bean 类上的映射**不得**进入"未覆盖清单"。
#[test]
fn test_routes_table_marks_non_bean_route_and_keeps_verdicts_consistent() {
    let root = std::env::temp_dir().join("ctx-audit-r250-table-notbean");
    let _ = std::fs::remove_dir_all(&root);
    let handler = concat!(
        "package app;\n",
        "import org.springframework.web.bind.annotation.GetMapping;\n",
        "/**\n",
        " * <p>注意: 该类不是 Spring Bean, 只有在 {@code ExportAutoConfiguration} 中\n",
        " * 显式注册为 {@code @Bean} 后才会生效.</p>\n",
        " */\n",
        "@Slf4j\n",
        "public class LegacyHandler {\n",
        "    @GetMapping(\"/legacy/export\")\n",
        "    public String export() { return \"x\"; }\n",
        "}\n",
    );
    write_file(&root, "src/SecurityConfig.java", security_config());
    write_file(&root, "src/LegacyHandler.java", handler);
    let files = loaded(&[
        ("src/SecurityConfig.java", security_config()),
        ("src/LegacyHandler.java", handler),
    ]);
    let table = compute_routes(
        &root,
        &files,
        "statv1:test",
        false,
        &RouteFilter::default(),
        false,
    );
    assert_eq!(
        table.data["not_an_endpoint_routes"], 1,
        "非 Bean 类上的映射必须被标记: {}",
        table.data["routes"]
    );
    let uncovered = table.data["uncovered_endpoints"].as_array().unwrap();
    assert!(
        uncovered.iter().all(|r| r["route"] != "/legacy/export"),
        "非端点不得进入未覆盖清单: {uncovered:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 单元级：非 Bean 判定（含 Javadoc 里出现 @Bean 的干扰）。
#[test]
fn test_file_route_is_bean_unit() {
    let content = concat!(
        "package app;\n",
        "import org.springframework.web.bind.annotation.GetMapping;\n",
        "/**\n",
        " * 显式注册为 {@code @Bean} 后才会生效.\n",
        " */\n",
        "@Slf4j\n",
        "public class LegacyHandler {\n",
        "    @GetMapping(\"/legacy/export\")\n",
        "    public String export() { return \"x\"; }\n",
        "}\n",
    );
    assert_eq!(
        file_route_is_bean(content, 8, "src/LegacyHandler.java"),
        Some(false)
    );
    let ctrl = concat!(
        "package app;\n",
        "@RestController\n",
        "public class C {\n",
        "    @GetMapping(\"/x\")\n",
        "    public String x() { return \"\"; }\n",
        "}\n",
    );
    assert_eq!(file_route_is_bean(ctrl, 4, "src/C.java"), Some(true));
}

/// xcludePathPatterns 命中 ⇒ 该路径不进拦截器，链内规则不生效（实测缺口，R252 修复）。
#[tokio::test]
async fn test_interceptor_exclude_downgrades_coverage() {
    let root = std::env::temp_dir().join("ctx-audit-r252-exclude");
    let _ = std::fs::remove_dir_all(&root);
    let satoken = concat!(
        "package app;\n",
        "import cn.dev33.satoken.interceptor.SaInterceptor;\n",
        "import cn.dev33.satoken.router.SaRouter;\n",
        "import cn.dev33.satoken.stp.StpUtil;\n",
        "@Configuration\n",
        "public class SaTokenConfigure implements WebMvcConfigurer {\n",
        "    @Override\n",
        "    public void addInterceptors(InterceptorRegistry registry) {\n",
        "        registry.addInterceptor(new SaInterceptor(handle -> {\n",
        "            SaRouter.match(\"/admin/**\", () -> {\n",
        "                StpUtil.checkLogin();\n",
        "            });\n",
        "        })).addPathPatterns(\"/**\").excludePathPatterns(\"/admin\", \"/admin/export\");\n",
        "    }\n",
        "}\n",
    );
    write_file(&root, "src/SaTokenConfigure.java", satoken);
    write_file(&root, "src/AdminController.java", protected_controller());
    let project = root.to_string_lossy().to_string();
    let out = CodeIntelTool::new(project, IntelKind::ExplainRoute)
        .execute(json!({"route": "/admin/export"}))
        .await
        .unwrap();
    let d = out.data.clone().expect("envelope");
    assert_eq!(d["data"]["verdict"], "excluded_from_interceptor", "{d}");
    assert_eq!(d["data"]["asserted_verdict"], "uncovered", "{d}");
    let _ = std::fs::remove_dir_all(&root);
}

/// 全限定注解（@pkg.SaCheckLogin）必须被识别为"有注解 + 有消费者"。
#[tokio::test]
async fn test_fully_qualified_annotation_is_detected() {
    let root = std::env::temp_dir().join("ctx-audit-r252-fq-annotation");
    let _ = std::fs::remove_dir_all(&root);
    let satoken = concat!(
        "package app;\n",
        "@Configuration\n",
        "public class SaTokenConfigure {\n",
        "    public void addInterceptors(InterceptorRegistry registry) {\n",
        "        registry.addInterceptor(new SaInterceptor(handle -> {\n",
        "            SaRouter.match(\"/admin/**\", () -> StpUtil.checkLogin());\n",
        "        })).addPathPatterns(\"/**\");\n",
        "    }\n",
        "}\n",
    );
    write_file(&root, "src/SaTokenConfigure.java", satoken);
    let controller = concat!(
        "package app;\n",
        "@RestController\n",
        "@RequestMapping(\"/user\")\n",
        "public class UserController {\n",
        "    @cn.dev33.satoken.annotation.SaCheckLogin\n",
        "    @PostMapping(\"/updatePwd\")\n",
        "    public String updatePwd() { return \"ok\"; }\n",
        "}\n",
    );
    write_file(&root, "src/UserController.java", controller);
    let project = root.to_string_lossy().to_string();
    let out = CodeIntelTool::new(project, IntelKind::ExplainRoute)
        .execute(json!({"route": "/user/updatePwd"}))
        .await
        .unwrap();
    let d = out.data.clone().expect("envelope");
    assert_eq!(d["data"]["asserted_verdict"], "covered", "{d}");
    let checks = d["data"]["decided_by"].as_array().unwrap();
    let ann = checks
        .iter()
        .find(|c| c["check"] == "method/class auth annotation")
        .expect("应有注解检查");
    assert_eq!(ann["result"], "present_and_consumed", "{ann}");
    let _ = std::fs::remove_dir_all(&root);
}

/// 跨文件 Express mount：`app.use('/api', posts)` + `require('./routes/posts')`
/// ⇒ 子路由文件里的 `router.get('/x')` 合成 `/api/x`（R252 T3 的漏项）。
#[test]
fn test_express_cross_file_mount_prefix() {
    let root = std::env::temp_dir().join("ctx-audit-r253-mount");
    let _ = std::fs::remove_dir_all(&root);
    let app = concat!(
        "const express = require('express');\n",
        "const app = express();\n",
        "const posts = require('./routes/posts');\n",
        "app.use('/api', posts);\n",
        "app.listen(3000);\n",
    );
    let posts = concat!(
        "const express = require('express');\n",
        "const router = express.Router();\n",
        "router.get('/posts', (req, res) => res.send([]));\n",
        "router.delete('/posts/:id', (req, res) => res.send('ok'));\n",
        "module.exports = router;\n",
    );
    write_file(&root, "src/app.js", app);
    write_file(&root, "src/routes/posts.js", posts);
    let files = loaded(&[("src/app.js", app), ("src/routes/posts.js", posts)]);
    let table = compute_routes(&root, &files, "statv1:test", false, &RouteFilter::default(), false);
    let routes: Vec<String> = table.data["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["route"].as_str().map(|s| s.to_string()))
        .collect();
    assert!(
        routes.iter().any(|r| r == "/api/posts"),
        "跨文件 mount 前缀应被合成: {routes:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// 非建模栈必须有信号：PHP/Rust/C# 的路由声明要出现在 `unmodelled_route_stacks` 里，
/// 而不是沉默（R252 T3 的洞：`unmodelled_route_files=0` 会让人读成"没有端点"）。
#[test]
fn test_unmodelled_stack_signal() {
    let root = std::env::temp_dir().join("ctx-audit-r253-unmodelled");
    let _ = std::fs::remove_dir_all(&root);
    let php = "<?php\nRoute::get('/php/ping', function () { return 'pong'; });\n";
    let rust = "#[get(\"/rust/ping\")]\nasync fn ping() -> impl Responder { \"pong\" }\n";
    let cs = "var app = builder.Build();\napp.MapGet(\"/cs/ping\", () => \"pong\");\n";
    write_file(&root, "php/routes/web.php", php);
    write_file(&root, "rust/src/main.rs", rust);
    write_file(&root, "cs/Program.cs", cs);
    let files = loaded(&[
        ("php/routes/web.php", php),
        ("rust/src/main.rs", rust),
        ("cs/Program.cs", cs),
    ]);
    let table = compute_routes(&root, &files, "statv1:test", false, &RouteFilter::default(), false);
    assert_eq!(
        table.data["unmodelled_route_files"], 3,
        "{}", table.data["unmodelled_route_files"]
    );
    let stacks = table.data["unmodelled_route_stacks"].as_object().unwrap();
    assert!(stacks.contains_key("php-laravel"), "{stacks:?}");
    assert!(stacks.contains_key("rust-web"), "{stacks:?}");
    assert!(stacks.contains_key("csharp-aspnet"), "{stacks:?}");
    // 这些栈里"顺带"报出的路由必须打上栈名，消费者才知道它未被建模
    for r in table.data["routes"].as_array().unwrap() {
        assert!(
            r.get("unmodelled_stack").is_some(),
            "非建模栈的路由必须带 unmodelled_stack: {r}"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// 自定义 Servlet `Filter` 承载鉴权时，基线卡必须指出它在哪（R255 实测缺口：
/// 某项目鉴权全在 AuthFilter.doFilter 里，基线卡却报 `unmodeled_protection_frameworks: []`）。
#[test]
fn test_custom_filter_reported_as_unmodelled_protection() {
    let filter = concat!(
        "package app;\n",
        "import javax.servlet.*;\n",
        "public class AuthFilter implements Filter {\n",
        "    private AuthConfigs authConfigs;\n",
        "    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {\n",
        "        if (!authConfigs.isAuthEnabled()) { chain.doFilter(request, response); return; }\n",
        "        throw new AccessException(\"unauthorized\");\n",
        "    }\n",
        "}\n",
    );
    let files = loaded(&[("src/main/java/app/AuthFilter.java", filter)]);
    let (data, _, _) = security_baseline(&files, false);
    let unmodelled = data["summary"]["unmodeled_protection_frameworks"]
        .as_array()
        .expect("unmodeled_protection_frameworks should be an array");
    let hit = unmodelled.iter().any(|u| {
        u["framework"] == "servlet-filter"
            && u["file"]
                .as_str()
                .map(|f| f.ends_with("AuthFilter.java"))
                .unwrap_or(false)
    });
    assert!(hit, "custom auth filter must be reported: {unmodelled:?}");
}
