use serde::{Deserialize, Serialize};

/// 语言特定模式 — 允许一条规则对不同语言使用不同正则
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LanguagePattern {
    pub language: String,
    pub pattern: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// 多语言模式列表（优先于 pattern）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<LanguagePattern>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe: Option<String>,
    /// OWASP Top 10 映射（如 "A03:2021-Injection"）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    /// 修复建议
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    /// 参考链接
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
    /// 可选的净化函数/模式列表。
    /// 当规则命中后，如果匹配位置之前出现任一 sanitizer 模式，引擎会跳过该发现。
    /// 这是通用的规则级去误报机制，任何 regex/AST 规则均可声明。
    #[serde(default)]
    pub sanitizers: Vec<String>,
    /// sanitizer 作用域：false（默认）仅看命中点之前的文本；
    /// true 则全文件任一处出现即豁免——适用于"缺失检查"类规则
    /// （校验调用在文件任意位置都算该项目已接入防护，分支级缺失交给判定层）
    #[serde(default)]
    pub sanitizer_file_scope: bool,
    /// sanitizer 匹配语义：`any`（默认）任一 sanitizer 出现即豁免；
    /// `all` 要求全部 sanitizer 都出现才豁免——用于"防护完整性"检查：
    /// 危险集合必须被完整覆盖（如 CWE-88 要求 LD_/DYLD_/LDR_/_RLD/=() 全集），
    /// 只覆盖子集视为防护不完整，仍报告。
    #[serde(default)]
    pub sanitizer_match: SanitizerMatch,
    /// 命中点之后 N 行内出现 sanitizer 即豁免（默认 0 = 关闭）。
    /// 用于"先取路径后校验"形态：校验调用在 sink 之后（如
    /// `path = root.resolve(name); checkDirectoryTraversal(root, path);`），
    /// 前缀语义看不到、文件级语义又会被同文件其他守卫/ import 误豁免。
    /// 设置后替代前缀语义（仅看后向窗口，不看命中点之前）。
    #[serde(default)]
    pub sanitizer_after_lines: usize,
    /// 命中点之前 N 行内出现 sanitizer 即豁免（默认 0 = 关闭）。
    /// 用于"先净化后使用"形态（如 `const safe = sanitize(name); path.join(dir, safe)`），
    /// 与无界前缀语义的区别是窗口有界：同文件远处的 import/无关守卫不会误豁免。
    /// 与 sanitizer_after_lines 可并存（两个窗口任一命中即豁免）。
    #[serde(default)]
    pub sanitizer_before_lines: usize,
    /// true 时每个文件最多保留一个命中（缺失检查类规则：检查有无是文件级语义，
    /// 多个命中只是同一问题的重复报告）
    #[serde(default)]
    pub once_per_file: bool,
    /// true 时丢弃命中点位于字符串字面量内的 finding——sink 调用形态的规则
    /// 匹配的是代码而非数据，字符串里的 "system()" 只是文本（如错误消息）。
    /// 凭证类规则不要开：字符串字面量正是它们的目标。
    #[serde(default)]
    pub exclude_string_literals: bool,
    /// true 时 sanitizer 检查扩展到 PHP include/require 链解析出的守卫文件
    /// （backlog 10.13）：校验常放在 bootstrap include 的全局安全文件中
    /// （如 csrf.php 对所有 POST 统一校验），单文件检查会把全局防护误判为缺失。
    /// 仅对 .php 文件生效；链解析有界（深度≤3、文件≤16）。
    #[serde(default)]
    pub sanitizer_include_chain: bool,
    /// true 时丢弃命中点位于 PHP 非裸调用形态内的 finding——方法调用（->）、
    /// 静态调用（::）、构造调用（new）与函数/方法定义点的同名文本不是内建函数
    /// 调用（如 `$pdo->exec(`、`Foo::exec(`、`new System()`、`function exec(`）。
    /// regex 层无前视/后视能力无法表达该消歧，用 tree-sitter 节点范围实现。
    /// 仅对 .php 文件生效。
    #[serde(default)]
    pub php_bare_call_only: bool,
    /// true 时对 Go 的 `io.Copy(` 命中要求"同一函数内存在文件打开调用"
    /// （os.Create / os.OpenFile 及其 `*Os*Create/OpenFile` 包装）才保留
    /// （backlog 10.19）。io.Copy 的参数是 io.Reader/io.Writer 接口——
    /// HTTP 响应、管道、zip writer、临时文件等流拷贝目标均非文件路径写入，
    /// 直接把 io.Copy 当文件写入 sink 误标率近 100%（transfer.sh/miniflux/
    /// filestash 三连）。真正的危险形态是"用户可控路径创建文件后 Copy"，
    /// 共现式近似即此语义；os.CreateTemp 属良性临时文件，不计入。
    /// 仅对 .go 文件生效。
    #[serde(default)]
    pub go_io_copy_requires_open_file: bool,
    /// 授权检查语义（missing-authorization 家族，backlog 10.27）：
    /// 命中点所在函数/方法体内必须出现任一授权关键字才豁免。
    /// 资源操作（按 id/name 的 get/delete/update/remove 等）的函数体内
    /// 没有身份/属主校验（currentUser/owner/isAdmin/hasRole 等）即为
    /// "缺失授权"候选（CWE-862）。区别于 sanitizer_file_scope 的文件级
    /// 语义：同文件远处 import 的 auth 模块不应豁免本函数——授权是
    /// 函数级语义，文件级匹配会系统性误豁免。
    /// 授权关键字从规则声明的 sanitizers 列表读取（复用现有机制）。
    #[serde(default)]
    pub auth_check_in_func: bool,
    /// true 时跳过 const-args/字面量参数的 likely_fp 降权（默认 false）。
    /// 用于"API 存在即风险"类规则（如 Prisma $queryRawUnsafe）——其参数
    /// 形态多样（模板字面量含嵌套括号时 extract_call_args 按 rfind('(')
    /// 取参数会错位，误判"参数全部为字面量"降 info，埋没真问题）；
    /// 且该 API 语义上即反模式，常量参数也不构成安全保证。
    #[serde(default)]
    pub skip_likely_fp: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SanitizerMatch {
    /// 任一 sanitizer 出现即豁免（默认，兼容旧规则）
    #[default]
    Any,
    /// 全部 sanitizer 都出现才豁免（防护完整性检查）
    All,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RuleSet {
    pub name: String,
    pub version: String,
    pub rules: Vec<Rule>,
}
