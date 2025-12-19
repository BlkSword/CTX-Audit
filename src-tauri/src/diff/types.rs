use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 差异类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffType {
    /// 相等的内容
    Equal,
    /// 插入的内容
    Insert,
    /// 删除的内容
    Delete,
    /// 修改的内容
    Replace,
}

/// 文件差异中的一行
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffLine {
    /// 行号（左侧文件）
    pub left_line_number: Option<u32>,
    /// 行号（右侧文件）
    pub right_line_number: Option<u32>,
    /// 差异类型
    pub diff_type: DiffType,
    /// 行内容
    pub content: String,
    /// 是否为空白行（用于对齐）
    pub is_placeholder: bool,
}

/// 单个文件的差异信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiff {
    /// 文件路径（相对于项目根目录）
    pub path: String,
    /// 文件状态（新增、删除、修改、重命名）
    pub status: FileStatus,
    /// 差异行列表
    pub lines: Vec<DiffLine>,
    /// 左侧文件的统计信息
    pub left_stats: FileStats,
    /// 右侧文件的统计信息
    pub right_stats: FileStats,
}

/// 文件状态
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileStatus {
    /// 新增文件
    Added,
    /// 删除文件
    Deleted,
    /// 修改文件
    Modified,
    /// 重命名文件
    Renamed { old_path: String },
    /// 未修改
    Unchanged,
}

/// 文件统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStats {
    /// 文件大小（字节）
    pub size: u64,
    /// 行数
    pub line_count: u32,
    /// 最后修改时间（Unix时间戳）
    pub modified_time: Option<i64>,
}

/// 两个版本之间的整体差异比较结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    /// 比较的源标识（可以是文件路径、Git commit hash等）
    pub source_a: String,
    /// 比较的目标标识
    pub source_b: String,
    /// 比较时间
    pub comparison_time: i64,
    /// 文件差异列表
    pub file_diffs: Vec<FileDiff>,
    /// 总体统计信息
    pub summary: ComparisonSummary,
}

/// 比较结果的总体统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonSummary {
    /// 新增文件数
    pub files_added: u32,
    /// 删除文件数
    pub files_deleted: u32,
    /// 修改文件数
    pub files_modified: u32,
    /// 重命名文件数
    pub files_renamed: u32,
    /// 新增行数
    pub lines_added: u32,
    /// 删除行数
    pub lines_deleted: u32,
}

/// 差异显示模式
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffViewMode {
    /// 并排视图
    SideBySide,
    /// 统一视图
    Unified,
    /// 仅显示差异
    Compact,
}

/// 比较配置选项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonConfig {
    /// 是否忽略空白字符差异
    pub ignore_whitespace: bool,
    /// 是否忽略大小写
    pub ignore_case: bool,
    /// 显示模式
    pub view_mode: DiffViewMode,
    /// 上下文行数（对于统一视图）
    pub context_lines: u32,
    /// 是否进行语法高亮
    pub enable_syntax_highlight: bool,
    /// 是否检测文件移动和重命名
    pub detect_renames: bool,
    /// 文件相似度阈值（用于重命名检测）
    pub rename_similarity_threshold: f32,
}

impl Default for ComparisonConfig {
    fn default() -> Self {
        Self {
            ignore_whitespace: false,
            ignore_case: false,
            view_mode: DiffViewMode::SideBySide,
            context_lines: 3,
            enable_syntax_highlight: true,
            detect_renames: true,
            rename_similarity_threshold: 0.8,
        }
    }
}

/// 比较请求
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonRequest {
    /// 源路径（文件或目录）
    pub source_a: String,
    /// 目标路径（文件或目录）
    pub source_b: String,
    /// 比较配置
    pub config: ComparisonConfig,
    /// 是否为Git比较（特殊处理）
    pub is_git_comparison: bool,
    /// Git特定的参数
    pub git_params: Option<GitComparisonParams>,
}

/// Git比较参数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitComparisonParams {
    /// 仓库路径
    pub repository_path: String,
    /// 左侧的commit hash、分支名或标签
    pub left_ref: String,
    /// 右侧的commit hash、分支名或标签
    pub right_ref: String,
    /// 指定要比较的文件路径（可选，为空则比较所有变更）
    pub file_paths: Vec<String>,
}