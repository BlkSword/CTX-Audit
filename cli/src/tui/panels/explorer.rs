// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 文件浏览器面板

use ratatui::{Frame, layout::Rect, style::{Color, Style}, widgets::{Block, Borders, List, ListItem, Wrap}};
use std::path::{Path, PathBuf};
use std::collections::HashMap;

/// 文件浏览器面板
pub struct ExplorerPanel {
    /// 当前路径
    current_path: PathBuf,
    /// 文件树
    file_tree: Vec<FileNode>,
    /// 展开的目录
    expanded_dirs: std::collections::HashSet<PathBuf>,
    /// 选中索引
    selected: usize,
    /// 项目根路径
    project_root: Option<PathBuf>,
}

/// 文件节点
#[derive(Debug, Clone)]
pub struct FileNode {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub language: Option<String>,
    pub depth: usize,
    pub is_expanded: bool,
}

impl ExplorerPanel {
    /// 创建新的文件浏览器
    pub fn new() -> Self {
        Self {
            current_path: PathBuf::from("."),
            file_tree: Vec::new(),
            expanded_dirs: std::collections::HashSet::new(),
            selected: 0,
            project_root: None,
        }
    }

    /// 渲染面板
    pub fn render(&self, f: &mut Frame, rect: Rect, active: bool) {
        let items: Vec<ListItem> = self.file_tree
            .iter()
            .enumerate()
            .map(|(i, file)| {
                let is_selected = i == self.selected;
                let prefix = "  ".repeat(file.depth);

                let icon = if file.is_dir {
                    if file.is_expanded {
                        "📂"
                    } else {
                        "📁"
                    }
                } else {
                    self.get_file_icon(&file.name)
                };

                let style = if is_selected {
                    Style::default().bg(Color::DarkGray).add_modifier(ratatui::style::Modifier::REVERSED)
                } else if file.is_dir {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::White)
                };

                let text = format!("{}{} {}", prefix, icon, file.name);
                ListItem::new(text).style(style)
            })
            .collect();

        let border_style = if active {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let list = List::new(items)
            .block(Block::default()
                .title(format!(" 文件浏览器 - {} ",
                    self.current_path.display()))
                .borders(Borders::ALL)
                .border_style(border_style)
            )
            .highlight_style(Style::default().bg(Color::DarkGray));

        f.render_widget(list, rect);
    }

    /// 设置项目根路径并加载文件
    pub fn set_project_root(&mut self, path: PathBuf) -> Result<(), std::io::Error> {
        self.project_root = Some(path.clone());
        self.current_path = path.clone();
        self.load_directory(&path)?;
        Ok(())
    }

    /// 加载目录内容
    pub fn load_directory(&mut self, path: &Path) -> Result<(), std::io::Error> {
        self.file_tree.clear();
        self.expanded_dirs.clear();
        self.selected = 0;

        // 如果有项目根，从根开始
        let root = self.project_root.clone().map(|p| p.as_path().to_path_buf()).unwrap_or_else(|| path.to_path_buf());
        self.build_file_tree(&root, 0)?;
        self.current_path = path.to_path_buf();

        Ok(())
    }

    /// 构建文件树
    fn build_file_tree(&mut self, path: &Path, depth: usize) -> Result<(), std::io::Error> {
        let entries = std::fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .filter(|e| {
                // 过滤隐藏文件和特定目录
                let file_name = e.file_name();
                let name = file_name.to_string_lossy();
                !name.starts_with('.')
                    && name != "node_modules"
                    && name != "target"
                    && name != "dist"
                    && name != ".git"
            })
            .collect::<Vec<_>>();

        let mut dirs = Vec::new();
        let mut files = Vec::new();

        for entry in entries {
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            let is_dir = path.is_dir();

            let language = if !is_dir {
                self.detect_language(&name)
            } else {
                None
            };

            let node = FileNode {
                name: name.clone(),
                path: path.clone(),
                is_dir,
                language,
                depth,
                is_expanded: self.expanded_dirs.contains(&path),
            };

            if is_dir {
                dirs.push((name, node));
            } else {
                files.push((name, node));
            }
        }

        // 排序：目录在前，文件在后，都按字母顺序
        dirs.sort_by(|a, b| a.0.cmp(&b.0));
        files.sort_by(|a, b| a.0.cmp(&b.0));

        // 先添加目录
        for (_, node) in dirs {
            let node_path = node.path.clone();
            self.file_tree.push(node);
            // 如果目录已展开，递归加载内容
            if self.expanded_dirs.contains(&node_path) {
                self.build_file_tree(&node_path, depth + 1)?;
            }
        }

        // 再添加文件
        for (_, node) in files {
            self.file_tree.push(node);
        }

        Ok(())
    }

    /// 检测编程语言
    fn detect_language(&self, filename: &str) -> Option<String> {
        let ext = Path::new(filename).extension()?.to_str()?;

        let lang = match ext {
            "rs" => "Rust",
            "go" => "Go",
            "py" => "Python",
            "js" | "jsx" | "mjs" => "JavaScript",
            "ts" | "tsx" => "TypeScript",
            "java" => "Java",
            "kt" | "kts" => "Kotlin",
            "cpp" | "cc" | "cxx" => "C++",
            "c" | "h" => "C",
            "cs" => "C#",
            "rb" => "Ruby",
            "php" => "PHP",
            "swift" => "Swift",
            "scala" => "Scala",
            "sh" | "bash" => "Shell",
            "html" | "htm" => "HTML",
            "css" | "scss" | "sass" | "less" => "CSS",
            "json" => "JSON",
            "xml" => "XML",
            "yaml" | "yml" => "YAML",
            "toml" => "TOML",
            "md" => "Markdown",
            "sql" => "SQL",
            _ => return None,
        };

        Some(lang.to_string())
    }

    /// 获取文件图标
    fn get_file_icon(&self, filename: &str) -> &'static str {
        let ext = Path::new(filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        match ext {
            "rs" => "🦀",
            "go" => "🐹",
            "py" => "🐍",
            "js" | "jsx" | "ts" | "tsx" => "📜",
            "java" => "☕",
            "cpp" | "cc" | "c" | "h" => "⚙",
            "rb" => "💎",
            "php" => "🐘",
            "swift" => "🍎",
            "kt" => "🤖",
            "html" | "htm" => "🌐",
            "css" | "scss" | "sass" => "🎨",
            "json" => "📋",
            "xml" => "📄",
            "yaml" | "yml" => "⚙",
            "md" => "📝",
            "sql" => "🗄",
            "sh" | "bash" => "🦪",
            "toml" => "⚙",
            "txt" => "📄",
            _ => "📄",
        }
    }

    /// 选择下一个
    pub fn select_next(&mut self) {
        if !self.file_tree.is_empty() {
            self.selected = (self.selected + 1).min(self.file_tree.len() - 1);
        }
    }

    /// 选择上一个
    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    /// 展开选中的目录
    pub fn toggle_expand(&mut self) {
        if let Some(node) = self.file_tree.get(self.selected) {
            if node.is_dir {
                let node_path = node.path.clone();
                if self.expanded_dirs.contains(&node.path) {
                    self.expanded_dirs.remove(&node.path);
                } else {
                    self.expanded_dirs.insert(node.path.clone());
                }
                // 重新加载文件树
                if let Some(root) = self.project_root.clone() {
                    let _ = self.build_file_tree(&root, 0);
                }
            }
        }
    }

    /// 进入选中的目录
    pub fn enter_directory(&mut self) -> Result<(), std::io::Error> {
        if let Some(node) = self.file_tree.get(self.selected) {
            if node.is_dir {
                let node_path = node.path.clone();
                self.current_path = node_path.clone();
                self.load_directory(&node_path)?;
                self.selected = 0;
            }
        }
        Ok(())
    }

    /// 返回上级目录
    pub fn go_up(&mut self) -> Result<(), std::io::Error> {
        let parent = self.current_path.parent().map(|p| p.to_path_buf());
        if let Some(parent) = parent {
            self.current_path = parent.clone();
            self.load_directory(&parent)?;
            self.selected = 0;
        }
        Ok(())
    }

    /// 获取选中项
    pub fn selected(&self) -> Option<&FileNode> {
        self.file_tree.get(self.selected)
    }

    /// 获取当前路径
    pub fn current_path(&self) -> &Path {
        &self.current_path
    }
}

impl Default for ExplorerPanel {
    fn default() -> Self {
        Self::new()
    }
}
