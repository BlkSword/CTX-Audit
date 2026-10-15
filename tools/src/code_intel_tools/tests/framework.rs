// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 框架证据相关的单元测试（路由、安全链、容器与拦截器、授权落点、未建模保护栈）。

use super::super::*;
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


    /// Sa-Token 应被**建模**：`SaRouter.match("/admin/**")` 内的 `checkLogin/checkRole` 成为规则，
    /// 并给出来源；`@SaCheckLogin` 作为方法级授权证据。
    #[tokio::test]
    async fn test_sa_token_rules_are_modelled() {
        let root = std::env::temp_dir().join("ctx-audit-satoken");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/SaTokenConfigure.java"),
            concat!(
                "package app;\n",
                "import cn.dev33.satoken.interceptor.SaInterceptor;\n",
                "public class SaTokenConfigure implements WebMvcConfigurer {\n",
                "    public void addInterceptors(InterceptorRegistry registry) {\n",
                "        registry.addInterceptor(new SaInterceptor(handle -> {\n",
                "            SaRouter.match(\"/admin/**\", () -> {\n",
                "                StpUtil.checkLogin();\n",
                "                StpUtil.checkRole(\"admin\");\n",
                "            });\n",
                "        })).addPathPatterns(\"/**\");\n",
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
                "public class AdminController {\n",
                "    @GetMapping(\"/admin/list\")\n",
                "    public String list() { return \"ok\"; }\n",
                "    @SaCheckLogin\n",
                "    @GetMapping(\"/share/info\")\n",
                "    public String share() { return \"ok\"; }\n",
                "    @GetMapping(\"/public/hello\")\n",
                "    public String hello() { return \"ok\"; }\n",
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
        let admin = routes.iter().find(|r| r["route"] == "/admin/list").expect("/admin/list");
        assert_eq!(admin["global_coverage"], "covered_by_global_config", "{d}");
        assert_eq!(admin["global_match"]["clause"], "authenticated", "{d}");
        assert!(
            admin["global_match"]["file"].as_str().unwrap_or("").contains("SaTokenConfigure.java"),
            "应给出来自 Sa-Token 配置的出处: {d}"
        );
        let share = routes.iter().find(|r| r["route"] == "/share/info").expect("/share/info");
        assert_eq!(share["auth_effect"], "method_level", "`@SaCheckLogin` 应计入方法级授权: {d}");
        let public = routes.iter().find(|r| r["route"] == "/public/hello").expect("/public/hello");
        assert_eq!(
            public["global_coverage"], "no_global_match_found",
            "有配置但无匹配规则时应如实说'未匹配': {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }


    /// 函数式路由应被识别为端点，并与其所在应用的安全配置一起判定覆盖。
    #[tokio::test]
    async fn test_functional_routes_are_endpoints() {
        let root = std::env::temp_dir().join("ctx-audit-functional-routes");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/HelloApplication.java"),
            concat!(
                "package example;\n",
                "import org.springframework.web.reactive.function.server.RouterFunction;\n",
                "import org.springframework.web.reactive.function.server.ServerResponse;\n",
                "import static org.springframework.web.reactive.function.server.RequestPredicates.GET;\n",
                "import static org.springframework.web.reactive.function.server.RouterFunctions.route;\n",
                "@SpringBootApplication\n",
                "public class HelloApplication {\n",
                "    @Bean\n",
                "    public RouterFunction<ServerResponse> routes(HelloController helloController) {\n",
                "        return route(GET(\"/\"), helloController::hello);\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/SecurityConfig.java"),
            concat!(
                "package example;\n",
                "import org.springframework.security.config.web.server.ServerHttpSecurity;\n",
                "import org.springframework.security.web.server.SecurityWebFilterChain;\n",
                "@EnableWebFluxSecurity\n",
                "public class SecurityConfig {\n",
                "    public SecurityWebFilterChain chain(ServerHttpSecurity http) {\n",
                "        http.authorizeExchange(e -> e.anyExchange().authenticated());\n",
                "        return http.build();\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/HelloApplication.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let r = routes
            .iter()
            .find(|x| x["route"] == "/")
            .expect("函数式路由 GET / 应被识别: {d}");
        assert_eq!(r["http_method"], "GET", "{d}");
        assert_eq!(r["route_source"], "functional", "{d}");
        assert_eq!(r["scope"], "method", "{d}");
        assert_eq!(r["global_coverage"], "covered_by_global_config", "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 反向守卫：没有 WebFlux 函数式类型的文件里，`GET("...")` 不得被当成端点。
    #[tokio::test]
    async fn test_plain_get_call_is_not_a_functional_route() {
        let root = std::env::temp_dir().join("ctx-audit-plain-get");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/PlainService.java"),
            concat!(
                "package app;\n",
                "public class PlainService {\n",
                "    void run() {\n",
                "        client.send(GET(\"/not-an-endpoint\"));\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/PlainService.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let bad = routes.iter().find(|x| x["route"] == "/not-an-endpoint");
        assert!(bad.is_none(), "普通 GET(...) 不得被当成端点: {d}");
        let _ = std::fs::remove_dir_all(&root);
    }


    /// 已建模的栈不应再被当成"未建模信号"（否则已建模项目的每个端点都会被贴上未建模提示）。
    #[tokio::test]
    async fn test_modelled_stack_is_not_reported_as_unmodelled_signal() {
        let root = std::env::temp_dir().join("ctx-audit-modelled-not-signal");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/SaTokenConfigure.java"),
            concat!(
                "package app;\n",
                "public class SaTokenConfigure implements WebMvcConfigurer {\n",
                "    public void addInterceptors(InterceptorRegistry registry) {\n",
                "        registry.addInterceptor(new SaInterceptor(handle -> {\n",
                "            SaRouter.match(\"/admin/**\", () -> StpUtil.checkLogin());\n",
                "        }));\n",
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
                "public class AdminController {\n",
                "    @GetMapping(\"/admin/list\")\n",
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
        let r = routes.iter().find(|x| x["route"] == "/admin/list").expect("/admin/list");
        assert_eq!(r["global_coverage"], "covered_by_global_config", "{d}");
        assert!(r["coverage_caveat"].is_null(), "已建模不应带未建模提示: {d}");
        assert!(r["unmodeled_signals"].is_null(), "已建模不应带未建模信号: {d}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 并存：结论来自已建模栈，同时存在**另一个未建模**保护面时，保留结论但显式带出信号。
    #[tokio::test]
    async fn test_coexisting_unmodelled_signal_is_visible() {
        let root = std::env::temp_dir().join("ctx-audit-coexist-signal");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("src/SecurityConfig.java"),
            concat!(
                "package app;\n",
                "public class SecurityConfig {\n",
                "    public SecurityFilterChain chain(HttpSecurity http) {\n",
                "        http.authorizeHttpRequests(a -> a.requestMatchers(\"/api/**\").authenticated());\n",
                "        return null;\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        // 另一个未建模栈只有一个无法读出规则的信号（没有 SaRouter.match）
        std::fs::write(
            root.join("src/OtherStack.java"),
            concat!(
                "package app;\n",
                "public class OtherStack {\n",
                "    void guard() {\n",
                "        StpUtil.checkLogin();\n",
                "    }\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/ApiController.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "public class ApiController {\n",
                "    @GetMapping(\"/api/list\")\n",
                "    public String list() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/ApiController.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let r = routes.iter().find(|x| x["route"] == "/api/list").expect("/api/list");
        assert_eq!(
            r["global_coverage"], "covered_by_global_config",
            "已建模栈的结论应保留: {d}"
        );
        assert_eq!(
            r["coverage_caveat"], "unmodeled_protection_present",
            "并存时应带出提示: {d}"
        );
        assert!(
            r["unmodeled_signals"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
            "并存时应列出信号: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 自动配置：声明了安全 starter、但范围内无可读配置 ⇒ 如实提示（结论不改写）。
    #[tokio::test]
    async fn test_security_starter_without_config_is_flagged() {
        let root = std::env::temp_dir().join("ctx-audit-starter-no-config");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("build.gradle"),
            concat!(
                "dependencies {\n",
                "    implementation 'org.springframework.boot:spring-boot-starter-webflux'\n",
                "    implementation 'org.springframework.boot:spring-boot-starter-security'\n",
                "}\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("src/HelloController.java"),
            concat!(
                "package app;\n",
                "import org.springframework.web.bind.annotation.*;\n",
                "@RestController\n",
                "public class HelloController {\n",
                "    @GetMapping(\"/hello\")\n",
                "    public String hello() { return \"ok\"; }\n",
                "}\n",
            ),
        )
        .unwrap();
        crate::index_cache::invalidate(&root);
        crate::symbol_index::invalidate(&root);
        let tool = CodeIntelTool::new(root.to_string_lossy().to_string(), IntelKind::FrameworkContext);
        let out = tool
            .execute(json!({"file": "src/HelloController.java"}))
            .await
            .unwrap();
        let d = out.data.clone().expect("应有 envelope data");
        let routes = d["data"]["routes"].as_array().expect("routes 应为数组");
        let r = routes.iter().find(|x| x["route"] == "/hello").expect("/hello");
        assert_eq!(r["global_coverage"], "no_global_config_found", "{d}");
        assert_eq!(
            r["coverage_caveat"], "security_starter_without_explicit_config",
            "应提示存在自动配置保护: {d}"
        );
        assert!(
            r["starter_source"]["file"].as_str().unwrap_or("").contains("build.gradle"),
            "应带出 starter 出处: {d}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
