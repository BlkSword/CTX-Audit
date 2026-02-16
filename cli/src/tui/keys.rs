// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! 快捷键系统

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 快捷键动作
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyAction {
    /// 退出
    Quit,
    /// 切换面板
    NextPanel,
    PrevPanel,
    /// 确认
    Confirm,
    /// 取消
    Cancel,
    /// 向上导航
    NavigateUp,
    /// 向下导航
    NavigateDown,
    /// 向左导航
    NavigateLeft,
    /// 向右导航
    NavigateRight,
    /// 向上翻页
    PageUp,
    /// 向下翻页
    PageDown,
    /// 跳到开始
    Home,
    /// 跳到结束
    End,
    /// 删除
    Delete,
    /// 刷新
    Refresh,
    /// 搜索
    Search,
    /// 帮助
    Help,
    /// 自定义动作
    Custom(String),
}

/// 快捷键绑定
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBinding {
    /// 键码
    pub key: String,
    /// 修饰键
    #[serde(default)]
    pub modifiers: Vec<String>,
    /// 动作
    pub action: KeyAction,
}

impl KeyBinding {
    /// 从键事件创建绑定
    pub fn from_event(event: &KeyEvent, action: KeyAction) -> Self {
        let key = match event.code {
            KeyCode::Char(c) => c.to_string(),
            KeyCode::F(n) => format!("F{}", n),
            KeyCode::Null => "Null".to_string(),
            KeyCode::Esc => "Esc".to_string(),
            KeyCode::Enter => "Enter".to_string(),
            KeyCode::Tab => "Tab".to_string(),
            KeyCode::BackTab => "BackTab".to_string(),
            KeyCode::Backspace => "Backspace".to_string(),
            KeyCode::Delete => "Delete".to_string(),
            KeyCode::Modifier(_) => "Modifier".to_string(),
            KeyCode::Insert => "Insert".to_string(),
            KeyCode::Up => "Up".to_string(),
            KeyCode::Down => "Down".to_string(),
            KeyCode::Left => "Left".to_string(),
            KeyCode::Right => "Right".to_string(),
            KeyCode::Home => "Home".to_string(),
            KeyCode::End => "End".to_string(),
            KeyCode::PageUp => "PageUp".to_string(),
            KeyCode::PageDown => "PageDown".to_string(),
            KeyCode::Media(_media) => "Media".to_string(),
            KeyCode::PrintScreen => "PrintScreen".to_string(),
            KeyCode::Pause => "Pause".to_string(),
            KeyCode::Menu => "Menu".to_string(),
            KeyCode::KeypadBegin => "KeypadBegin".to_string(),
            KeyCode::CapsLock => "CapsLock".to_string(),
            KeyCode::ScrollLock => "ScrollLock".to_string(),
            KeyCode::NumLock => "NumLock".to_string(),
        };

        let mut modifiers = Vec::new();
        if event.modifiers.contains(KeyModifiers::SHIFT) {
            modifiers.push("shift".to_string());
        }
        if event.modifiers.contains(KeyModifiers::CONTROL) {
            modifiers.push("control".to_string());
        }
        if event.modifiers.contains(KeyModifiers::ALT) {
            modifiers.push("alt".to_string());
        }
        if event.modifiers.contains(KeyModifiers::SUPER) {
            modifiers.push("super".to_string());
        }
        if event.modifiers.contains(KeyModifiers::HYPER) {
            modifiers.push("hyper".to_string());
        }

        Self { key, modifiers, action }
    }

    /// 检查键事件是否匹配此绑定
    pub fn matches(&self, event: &KeyEvent) -> bool {
        // 检查键码
        let key_matches = match event.code {
            KeyCode::Char(c) => self.key == c.to_string(),
            KeyCode::F(n) => self.key == format!("F{}", n),
            KeyCode::Esc => self.key == "Esc",
            KeyCode::Enter => self.key == "Enter",
            KeyCode::Tab => self.key == "Tab",
            KeyCode::BackTab => self.key == "BackTab",
            KeyCode::Backspace => self.key == "Backspace",
            KeyCode::Delete => self.key == "Delete",
            KeyCode::Up => self.key == "Up",
            KeyCode::Down => self.key == "Down",
            KeyCode::Left => self.key == "Left",
            KeyCode::Right => self.key == "Right",
            KeyCode::Home => self.key == "Home",
            KeyCode::End => self.key == "End",
            KeyCode::PageUp => self.key == "PageUp",
            KeyCode::PageDown => self.key == "PageDown",
            _ => false,
        };

        if !key_matches {
            return false;
        }

        // 检查修饰键
        for modifier in &self.modifiers {
            let has_modifier = match modifier.as_str() {
                "shift" => event.modifiers.contains(KeyModifiers::SHIFT),
                "control" => event.modifiers.contains(KeyModifiers::CONTROL),
                "alt" => event.modifiers.contains(KeyModifiers::ALT),
                "super" => event.modifiers.contains(KeyModifiers::SUPER),
                "hyper" => event.modifiers.contains(KeyModifiers::HYPER),
                _ => false,
            };
            if !has_modifier {
                return false;
            }
        }

        true
    }
}

/// 默认快捷键配置
pub fn default_keybindings() -> Vec<KeyBinding> {
    vec![
        // 退出
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            KeyAction::Quit,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            KeyAction::Quit,
        ),

        // 面板切换
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            KeyAction::NextPanel,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
            KeyAction::PrevPanel,
        ),

        // 导航
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
            KeyAction::NavigateUp,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            KeyAction::NavigateDown,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            KeyAction::NavigateLeft,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Right, KeyModifiers::NONE),
            KeyAction::NavigateRight,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE),
            KeyAction::PageUp,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE),
            KeyAction::PageDown,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Home, KeyModifiers::NONE),
            KeyAction::Home,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::End, KeyModifiers::NONE),
            KeyAction::End,
        ),

        // 确认/取消
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            KeyAction::Confirm,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            KeyAction::Cancel,
        ),

        // 删除/刷新
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE),
            KeyAction::Delete,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL),
            KeyAction::Refresh,
        ),

        // 帮助
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE),
            KeyAction::Help,
        ),
        KeyBinding::from_event(
            &KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE),
            KeyAction::Help,
        ),
    ]
}

/// 快捷键管理器
pub struct KeyBindings {
    /// 绑定列表
    bindings: Vec<KeyBinding>,
    /// 快捷键到动作的映射
    key_map: HashMap<String, KeyAction>,
}

impl KeyBindings {
    /// 创建新的快捷键管理器
    pub fn new() -> Self {
        let bindings = default_keybindings();
        let key_map = Self::build_key_map(&bindings);

        Self { bindings, key_map }
    }

    /// 从配置创建
    pub fn from_config(config: Vec<KeyBinding>) -> Self {
        let key_map = Self::build_key_map(&config);

        Self {
            bindings: config,
            key_map,
        }
    }

    /// 构建快捷键映射
    fn build_key_map(bindings: &[KeyBinding]) -> HashMap<String, KeyAction> {
        let mut map = HashMap::new();

        for binding in bindings {
            let key = Self::format_key(&binding.key, &binding.modifiers);
            map.insert(key, binding.action.clone());
        }

        map
    }

    /// 格式化快捷键字符串
    fn format_key(key: &str, modifiers: &[String]) -> String {
        if modifiers.is_empty() {
            return key.to_string();
        }

        let mut parts = modifiers.to_vec();
        parts.push(key.to_string());
        parts.join("+")
    }

    /// 查找键事件对应的动作
    pub fn find_action(&self, event: &KeyEvent) -> Option<&KeyAction> {
        for binding in &self.bindings {
            if binding.matches(event) {
                return Some(&binding.action);
            }
        }
        None
    }

    /// 获取快捷键说明
    pub fn get_help_text(&self) -> Vec<(String, String)> {
        let mut help = Vec::new();

        let mut grouped: std::collections::HashMap<String, Vec<&KeyBinding>> =
            std::collections::HashMap::new();

        // 分组
        for binding in &self.bindings {
            let group = match &binding.action {
                KeyAction::Quit => "退出",
                KeyAction::NextPanel | KeyAction::PrevPanel => "面板切换",
                KeyAction::NavigateUp | KeyAction::NavigateDown
                | KeyAction::NavigateLeft | KeyAction::NavigateRight => "导航",
                KeyAction::PageUp | KeyAction::PageDown => "翻页",
                KeyAction::Home | KeyAction::End => "跳转",
                KeyAction::Confirm | KeyAction::Cancel => "操作",
                KeyAction::Delete | KeyAction::Refresh => "编辑",
                KeyAction::Search => "搜索",
                KeyAction::Help => "帮助",
                KeyAction::Custom(_) => "自定义",
            };

            grouped.entry(group.to_string())
                .or_insert_with(Vec::new)
                .push(binding);
        }

        // 格式化
        for group in ["退出", "面板切换", "导航", "翻页", "跳转", "操作", "编辑", "搜索", "帮助"] {
            if let Some(bindings) = grouped.get(group) {
                let keys: Vec<String> = bindings.iter()
                    .map(|b| Self::format_key(&b.key, &b.modifiers))
                    .collect();

                help.push((group.to_string(), keys.join(", ")));
            }
        }

        help
    }
}

impl Default for KeyBindings {
    fn default() -> Self {
        Self::new()
    }
}
